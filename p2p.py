#!/usr/bin/env python3

import asyncio
import websockets
import json
from typing import Set, Dict, Any, List, Optional
import logging
from blockchain import Blockchain
import time
import hashlib
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import socket
import struct
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PeerInfo:
    address: str
    port: int
    last_seen: float
    latency: float
    version: str
    capabilities: List[str]
    is_validator: bool
    shard_id: Optional[int]

class DHTNode:
    def __init__(self, node_id: str, address: str, port: int):
        self.node_id = node_id
        self.address = address
        self.port = port
        self.buckets: Dict[int, Set[str]] = {i: set() for i in range(160)}  # 160-bit key space
        self.data: Dict[str, Any] = {}

    def distance(self, other_id: str) -> int:
        """Calculate XOR distance between two node IDs"""
        return int(self.node_id, 16) ^ int(other_id, 16)

    def update_bucket(self, node_id: str):
        """Update the appropriate bucket with a node ID"""
        distance = self.distance(node_id)
        bucket_index = distance.bit_length() - 1
        self.buckets[bucket_index].add(node_id)

    def get_closest_nodes(self, target_id: str, k: int = 8) -> List[str]:
        """Get k closest nodes to the target ID"""
        distance = self.distance(target_id)
        bucket_index = distance.bit_length() - 1
        
        # Start with the current bucket
        closest = list(self.buckets[bucket_index])
        
        # If we need more nodes, look in adjacent buckets
        i = 1
        while len(closest) < k and (bucket_index - i >= 0 or bucket_index + i < 160):
            if bucket_index - i >= 0:
                closest.extend(self.buckets[bucket_index - i])
            if bucket_index + i < 160:
                closest.extend(self.buckets[bucket_index + i])
            i += 1
        
        # Sort by distance and return k closest
        return sorted(closest, key=lambda x: self.distance(x))[:k]

class P2PNode:
    def __init__(self, host: str = "0.0.0.0", port: int = 6000):
        self.host = host
        self.port = port
        self.node_id = hashlib.sha256(f"{host}:{port}".encode()).hexdigest()
        self.peers: Dict[str, PeerInfo] = {}
        self.blockchain = None
        self.server = None
        self.known_peers: Set[str] = set()
        self.peer_latency: Dict[str, float] = {}
        self.sync_interval = 60
        self.max_peers = 50
        self.min_peers = 10
        self.dht = DHTNode(self.node_id, host, port)
        self.encryption_key = self._generate_encryption_key()
        self.version = "1.0.0"
        self.capabilities = ["blockchain", "dht", "encryption"]

    def _generate_encryption_key(self) -> bytes:
        """Generate an encryption key for secure communication"""
        salt = b'straz_blockchain_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.node_id.encode()))
        return key

    def set_blockchain(self, blockchain: Blockchain):
        self.blockchain = blockchain

    async def start(self):
        """Start the P2P server"""
        self.server = await websockets.serve(
            self.handle_connection,
            self.host,
            self.port
        )
        logger.info(f"P2P server started on {self.host}:{self.port}")
        
        # Start background tasks
        asyncio.create_task(self.periodic_sync())
        asyncio.create_task(self.periodic_peer_discovery())
        asyncio.create_task(self.periodic_peer_health_check())
        asyncio.create_task(self.periodic_dht_maintenance())

    async def periodic_sync(self):
        """Periodically sync with peers"""
        while True:
            await asyncio.sleep(self.sync_interval)
            await self.sync_with_peers()

    async def periodic_peer_discovery(self):
        """Periodically discover new peers"""
        while True:
            await asyncio.sleep(300)  # Every 5 minutes
            await self.discover_peers()

    async def periodic_peer_health_check(self):
        """Periodically check peer health"""
        while True:
            await asyncio.sleep(60)  # Every minute
            await self.check_peer_health()

    async def periodic_dht_maintenance(self):
        """Periodically maintain DHT state"""
        while True:
            await asyncio.sleep(3600)  # Every hour
            await self.maintain_dht()

    async def maintain_dht(self):
        """Maintain DHT state by refreshing buckets and removing stale nodes"""
        current_time = time.time()
        
        # Remove stale nodes from DHT
        for bucket in self.dht.buckets.values():
            stale_nodes = set()
            for node_id in bucket:
                if node_id in self.peers:
                    peer = self.peers[node_id]
                    if current_time - peer.last_seen > 3600:  # 1 hour
                        stale_nodes.add(node_id)
            bucket -= stale_nodes
        
        # Refresh buckets by querying random nodes
        for bucket_index in range(160):
            if len(self.dht.buckets[bucket_index]) > 0:
                random_node = random.choice(list(self.dht.buckets[bucket_index]))
                await self.query_dht_node(random_node)

    async def discover_peers(self):
        """Discover new peers through DHT and existing peers"""
        # Query DHT for new peers
        closest_nodes = self.dht.get_closest_nodes(self.node_id)
        for node_id in closest_nodes:
            if node_id not in self.peers:
                await self.connect_to_peer(node_id)
        
        # Query existing peers for new peers
        for peer in list(self.peers.values()):
            try:
                async with websockets.connect(f"ws://{peer.address}:{peer.port}") as websocket:
                    await self.send_message(websocket, {
                        "type": "get_peers"
                    })
            except Exception as e:
                logger.error(f"Failed to discover peers through {peer.address}:{e}")
                del self.peers[peer.address]

    async def check_peer_health(self):
        """Check health of connected peers"""
        current_time = time.time()
        for peer_id, peer in list(self.peers.items()):
            try:
                start_time = time.time()
                async with websockets.connect(f"ws://{peer.address}:{peer.port}") as websocket:
                    await self.send_message(websocket, {
                        "type": "ping"
                    })
                    response = await websocket.recv()
                    latency = time.time() - start_time
                    
                    # Update peer info
                    peer.latency = latency
                    peer.last_seen = current_time
                    
                    # Update DHT
                    self.dht.update_bucket(peer_id)
            except Exception as e:
                logger.error(f"Peer {peer.address} is unhealthy: {e}")
                del self.peers[peer_id]
                self.known_peers.remove(peer.address)

    async def sync_with_peers(self):
        """Sync blockchain with peers"""
        if not self.blockchain:
            return

        for peer in list(self.peers.values()):
            try:
                async with websockets.connect(f"ws://{peer.address}:{peer.port}") as websocket:
                    # Get the latest block height
                    await self.send_message(websocket, {
                        "type": "get_block_height"
                    })
                    response = await websocket.recv()
                    data = json.loads(response)
                    
                    if data["type"] == "block_height":
                        peer_height = data["height"]
                        local_height = len(self.blockchain.chain)
                        
                        if peer_height > local_height:
                            # Request missing blocks
                            await self.send_message(websocket, {
                                "type": "get_blocks",
                                "data": {
                                    "start_height": local_height,
                                    "end_height": peer_height
                                }
                            })
            except Exception as e:
                logger.error(f"Failed to sync with peer {peer.address}: {e}")
                del self.peers[peer.address]

    async def handle_connection(self, websocket, path):
        """Handle incoming connections"""
        peer_address = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        peer_id = hashlib.sha256(peer_address.encode()).hexdigest()
        
        # Add peer to DHT
        self.dht.update_bucket(peer_id)
        
        try:
            await self.handle_peer_messages(websocket)
        except Exception as e:
            logger.error(f"Error handling connection from {peer_address}: {e}")
        finally:
            if peer_id in self.peers:
                del self.peers[peer_id]

    async def handle_peer_messages(self, websocket):
        """Handle messages from peers"""
        async for message in websocket:
            try:
                # Decrypt message
                decrypted_message = self._decrypt_message(message)
                data = json.loads(decrypted_message)
                await self.process_message(data)
            except json.JSONDecodeError:
                logger.error("Invalid JSON message received")
            except Exception as e:
                logger.error(f"Error processing message: {e}")

    def _encrypt_message(self, message: str) -> bytes:
        """Encrypt a message using Fernet"""
        f = Fernet(self.encryption_key)
        return f.encrypt(message.encode())

    def _decrypt_message(self, encrypted_message: bytes) -> str:
        """Decrypt a message using Fernet"""
        f = Fernet(self.encryption_key)
        return f.decrypt(encrypted_message).decode()

    async def process_message(self, message: Dict[str, Any]):
        """Process different types of messages"""
        message_type = message.get("type")
        data = message.get("data", {})

        if message_type == "handshake":
            # Handle handshake
            peer_id = data["node_id"]
            peer_info = PeerInfo(
                address=data["address"],
                port=data["port"],
                last_seen=time.time(),
                latency=0.0,
                version=data["version"],
                capabilities=data["capabilities"],
                is_validator=data.get("is_validator", False),
                shard_id=data.get("shard_id")
            )
            self.peers[peer_id] = peer_info
            self.known_peers.add(f"{peer_info.address}:{peer_info.port}")
            self.dht.update_bucket(peer_id)
        
        elif message_type == "new_block":
            # Handle new block
            if self.blockchain:
                block_data = data["block"]
                if self.verify_block(block_data):
                    self.blockchain.chain.append(Block.from_dict(block_data))
                    # Broadcast to other peers
                    await self.broadcast_except(message, data["sender"])
        
        elif message_type == "new_transaction":
            # Handle new transaction
            if self.blockchain:
                transaction = data["transaction"]
                if self.blockchain.validate_transaction(transaction):
                    self.blockchain.transaction_pool[self.blockchain.calculate_transaction_hash(transaction)] = transaction
                    # Broadcast to other peers
                    await self.broadcast_except(message, data["sender"])
        
        elif message_type == "get_blocks":
            # Handle block request
            if self.blockchain:
                start_height = data["start_height"]
                end_height = data["end_height"]
                blocks = self.blockchain.chain[start_height:end_height]
                return {
                    "type": "blocks",
                    "data": {
                        "blocks": [block.to_dict() for block in blocks]
                    }
                }
        
        elif message_type == "get_peers":
            # Return list of known peers
            return {
                "type": "peers",
                "data": {
                    "peers": [
                        {
                            "node_id": peer_id,
                            "address": peer.address,
                            "port": peer.port,
                            "version": peer.version,
                            "capabilities": peer.capabilities,
                            "is_validator": peer.is_validator,
                            "shard_id": peer.shard_id
                        }
                        for peer_id, peer in self.peers.items()
                    ]
                }
            }
        
        elif message_type == "ping":
            # Handle ping
            return {
                "type": "pong",
                "data": {
                    "timestamp": time.time()
                }
            }
        
        elif message_type == "dht_query":
            # Handle DHT query
            target_id = data["target_id"]
            closest_nodes = self.dht.get_closest_nodes(target_id)
            return {
                "type": "dht_response",
                "data": {
                    "nodes": closest_nodes
                }
            }

    async def broadcast_except(self, message: Dict[str, Any], exclude_peer: str):
        """Broadcast a message to all peers except one"""
        encrypted_message = self._encrypt_message(json.dumps(message))
        for peer in self.peers.values():
            if f"{peer.address}:{peer.port}" != exclude_peer:
                try:
                    async with websockets.connect(f"ws://{peer.address}:{peer.port}") as websocket:
                        await websocket.send(encrypted_message)
                except Exception as e:
                    logger.error(f"Failed to broadcast to {peer.address}:{e}")
                    del self.peers[peer.address]

    async def send_message(self, websocket, message: Dict[str, Any]):
        """Send a message to a peer"""
        try:
            encrypted_message = self._encrypt_message(json.dumps(message))
            await websocket.send(encrypted_message)
        except Exception as e:
            logger.error(f"Failed to send message: {e}")

    async def stop(self):
        """Stop the P2P server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("P2P server stopped")

if __name__ == "__main__":
    # Example usage
    async def main():
        node = P2PNode()
        await node.start()
        
        # Keep the server running
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await node.stop()

    asyncio.run(main()) 