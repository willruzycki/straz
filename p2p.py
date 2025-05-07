#!/usr/bin/env python3

import asyncio
import websockets
import json
from typing import Set, Dict, Any
import logging
from blockchain import Blockchain

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class P2PNode:
    def __init__(self, host: str = "0.0.0.0", port: int = 6000):
        self.host = host
        self.port = port
        self.peers: Set[str] = set()
        self.blockchain = None
        self.server = None

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

    async def connect_to_peer(self, peer_url: str):
        """Connect to a peer"""
        try:
            async with websockets.connect(peer_url) as websocket:
                self.peers.add(peer_url)
                await self.send_message(websocket, {
                    "type": "handshake",
                    "data": {
                        "host": self.host,
                        "port": self.port
                    }
                })
                await self.handle_peer_messages(websocket)
        except Exception as e:
            logger.error(f"Failed to connect to peer {peer_url}: {e}")
            self.peers.remove(peer_url)

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast a message to all peers"""
        for peer in self.peers:
            try:
                async with websockets.connect(peer) as websocket:
                    await self.send_message(websocket, message)
            except Exception as e:
                logger.error(f"Failed to broadcast to {peer}: {e}")
                self.peers.remove(peer)

    async def handle_connection(self, websocket, path):
        """Handle incoming connections"""
        peer_url = f"ws://{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        self.peers.add(peer_url)
        try:
            await self.handle_peer_messages(websocket)
        except Exception as e:
            logger.error(f"Error handling connection from {peer_url}: {e}")
        finally:
            self.peers.remove(peer_url)

    async def handle_peer_messages(self, websocket):
        """Handle messages from peers"""
        async for message in websocket:
            try:
                data = json.loads(message)
                await self.process_message(data)
            except json.JSONDecodeError:
                logger.error("Invalid JSON message received")
            except Exception as e:
                logger.error(f"Error processing message: {e}")

    async def process_message(self, message: Dict[str, Any]):
        """Process different types of messages"""
        message_type = message.get("type")
        data = message.get("data", {})

        if message_type == "handshake":
            # Handle handshake
            pass
        elif message_type == "new_block":
            # Handle new block
            if self.blockchain:
                # Verify and add block
                pass
        elif message_type == "new_transaction":
            # Handle new transaction
            if self.blockchain:
                # Add transaction to pool
                pass
        elif message_type == "get_blocks":
            # Handle block request
            if self.blockchain:
                # Send requested blocks
                pass

    async def send_message(self, websocket, message: Dict[str, Any]):
        """Send a message to a peer"""
        try:
            await websocket.send(json.dumps(message))
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