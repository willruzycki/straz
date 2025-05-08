#!/usr/bin/env python3

import socket
import threading
import json
import time
import hashlib
import requests
from typing import List, Dict, Any, Set, Optional
from blockchain import Blockchain, Block
from wallet import Wallet

class Node:
    def __init__(self, host: str = '0.0.0.0', port: int = 5000):
        self.host = host
        self.port = port
        self.blockchain = Blockchain()
        self.peers: Set[str] = set()  # Set of peer URLs
        self.wallet: Optional[Wallet] = None
        
        # Initialize the node server
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    def start(self) -> None:
        """Start the node server."""
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        
        # Start a thread to accept incoming connections
        threading.Thread(target=self.accept_connections, daemon=True).start()
        
        print(f"Node started on {self.host}:{self.port}")
        
        # Sync blockchain with peers
        if self.peers:
            self.sync_with_peers()
    
    def accept_connections(self) -> None:
        """Accept incoming connections from peers."""
        while True:
            client, address = self.socket.accept()
            threading.Thread(target=self.handle_client, args=(client, address), daemon=True).start()
    
    def handle_client(self, client: socket.socket, address: tuple) -> None:
        """Handle an incoming connection from a peer."""
        try:
            # Receive data from client
            data = client.recv(4096).decode('utf-8')
            if not data:
                return
            
            # Parse the message
            message = json.loads(data)
            
            # Handle different message types
            if message["type"] == "get_blockchain":
                # Send the blockchain to the peer
                response = {
                    "type": "blockchain",
                    "data": self.blockchain.to_dict()
                }
                client.send(json.dumps(response).encode('utf-8'))
            
            elif message["type"] == "broadcast_transaction":
                # Add the transaction to pending transactions
                transaction = message["data"]
                self.blockchain.pending_transactions.append(transaction)
                
                # Acknowledge receipt
                response = {
                    "type": "ack",
                    "message": "Transaction received"
                }
                client.send(json.dumps(response).encode('utf-8'))
            
            elif message["type"] == "broadcast_block":
                # Verify and add the block to the blockchain
                block_data = message["data"]
                block = Block(
                    block_data["index"],
                    block_data["timestamp"],
                    block_data["transactions"],
                    block_data["previous_hash"],
                    block_data["nonce"]
                )
                block.hash = block_data["hash"]
                
                # Verify the block
                if self.verify_block(block):
                    self.blockchain.chain.append(block)
                    
                    # Acknowledge receipt
                    response = {
                        "type": "ack",
                        "message": "Block accepted"
                    }
                else:
                    response = {
                        "type": "error",
                        "message": "Invalid block"
                    }
                
                client.send(json.dumps(response).encode('utf-8'))
            
            elif message["type"] == "get_peers":
                # Send the list of peers to the client
                response = {
                    "type": "peers",
                    "data": list(self.peers)
                }
                client.send(json.dumps(response).encode('utf-8'))
            
            elif message["type"] == "add_peer":
                # Add the peer to the peer list
                peer_url = message["data"]
                if peer_url not in self.peers and peer_url != f"{self.host}:{self.port}":
                    self.peers.add(peer_url)
                    
                    # Acknowledge receipt
                    response = {
                        "type": "ack",
                        "message": "Peer added"
                    }
                else:
                    response = {
                        "type": "error",
                        "message": "Peer already exists or is self"
                    }
                
                client.send(json.dumps(response).encode('utf-8'))
        
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        
        finally:
            client.close()
    
    def connect_to_peer(self, host: str, port: int) -> bool:
        """Connect to a peer and add it to the peer list."""
        peer_url = f"{host}:{port}"
        
        if peer_url in self.peers or peer_url == f"{self.host}:{self.port}":
            return False
        
        try:
            # Connect to the peer
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((host, port))
            
            # Send a message to add this node as a peer
            message = {
                "type": "add_peer",
                "data": f"{self.host}:{self.port}"
            }
            client.send(json.dumps(message).encode('utf-8'))
            
            # Receive a response
            response = json.loads(client.recv(4096).decode('utf-8'))
            
            if response["type"] == "ack":
                # Add the peer to the peer list
                self.peers.add(peer_url)
                
                # Get the peer's blockchain
                self.get_blockchain_from_peer(host, port)
                
                # Get the peer's peers
                self.get_peers_from_peer(host, port)
                
                return True
            
            return False
        
        except Exception as e:
            print(f"Error connecting to peer {host}:{port}: {e}")
            return False
        
        finally:
            client.close()
    
    def get_blockchain_from_peer(self, host: str, port: int) -> bool:
        """Get the blockchain from a peer."""
        try:
            # Connect to the peer
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((host, port))
            
            # Send a message to get the blockchain
            message = {
                "type": "get_blockchain"
            }
            client.send(json.dumps(message).encode('utf-8'))
            
            # Receive the blockchain
            response = json.loads(client.recv(4096).decode('utf-8'))
            
            if response["type"] == "blockchain":
                # Check if the peer's blockchain is longer than ours
                peer_blockchain = response["data"]
                if len(peer_blockchain["chain"]) > len(self.blockchain.chain):
                    # Verify the peer's blockchain
                    if self.verify_blockchain(peer_blockchain):
                        # Replace our blockchain with the peer's
                        self.blockchain = Blockchain.load_from_dict(peer_blockchain)
                        return True
            
            return False
        
        except Exception as e:
            print(f"Error getting blockchain from peer {host}:{port}: {e}")
            return False
        
        finally:
            client.close()
    
    def get_peers_from_peer(self, host: str, port: int) -> bool:
        """Get the peers from a peer."""
        try:
            # Connect to the peer
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((host, port))
            
            # Send a message to get the peers
            message = {
                "type": "get_peers"
            }
            client.send(json.dumps(message).encode('utf-8'))
            
            # Receive the peers
            response = json.loads(client.recv(4096).decode('utf-8'))
            
            if response["type"] == "peers":
                # Add the peer's peers to our peer list
                for peer_url in response["data"]:
                    if peer_url not in self.peers and peer_url != f"{self.host}:{self.port}":
                        peer_host, peer_port = peer_url.split(":")
                        self.connect_to_peer(peer_host, int(peer_port))
                
                return True
            
            return False
        
        except Exception as e:
            print(f"Error getting peers from peer {host}:{port}: {e}")
            return False
        
        finally:
            client.close()
    
    def sync_with_peers(self) -> None:
        """Sync the blockchain with all peers."""
        for peer_url in self.peers:
            host, port = peer_url.split(":")
            self.get_blockchain_from_peer(host, int(port))
    
    def broadcast_transaction(self, transaction: Dict) -> None:
        """Broadcast a transaction to all peers."""
        message = {
            "type": "broadcast_transaction",
            "data": transaction
        }
        
        for peer_url in self.peers:
            try:
                host, port = peer_url.split(":")
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((host, int(port)))
                client.send(json.dumps(message).encode('utf-8'))
                client.close()
            except Exception as e:
                print(f"Error broadcasting transaction to peer {peer_url}: {e}")
    
    def broadcast_block(self, block: Block) -> None:
        """Broadcast a block to all peers."""
        message = {
            "type": "broadcast_block",
            "data": block.to_dict()
        }
        
        for peer_url in self.peers:
            try:
                host, port = peer_url.split(":")
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((host, int(port)))
                client.send(json.dumps(message).encode('utf-8'))
                client.close()
            except Exception as e:
                print(f"Error broadcasting block to peer {peer_url}: {e}")
    
    def verify_block(self, block: Block) -> bool:
        """Verify the validity of a block."""
        # Check if the block index is correct
        if block.index != len(self.blockchain.chain):
            return False
        
        # Check if the previous hash matches the last block in the chain
        if block.previous_hash != self.blockchain.get_latest_block().hash:
            return False
        
        # Check if the block hash is valid
        if block.hash != block.calculate_hash():
            return False
        
        # Check if the block hash meets the difficulty requirement
        if block.hash[:self.blockchain.difficulty] != "0" * self.blockchain.difficulty:
            return False
        
        return True
    
    def verify_blockchain(self, blockchain_data: Dict) -> bool:
        """Verify the validity of a blockchain."""
        # Create a temporary blockchain
        temp_blockchain = Blockchain(blockchain_data["difficulty"])
        temp_blockchain.chain = []
        
        # Add all blocks to the temporary blockchain
        for block_data in blockchain_data["chain"]:
            block = Block(
                block_data["index"],
                block_data["timestamp"],
                block_data["transactions"],
                block_data["previous_hash"],
                block_data["nonce"]
            )
            block.hash = block_data["hash"]
            temp_blockchain.chain.append(block)
        
        # Verify the blockchain
        return temp_blockchain.is_chain_valid()
    
    def mine_block(self) -> Block:
        """Mine a new block with the pending transactions."""
        if not self.wallet:
            raise ValueError("No wallet configured for mining rewards")
        
        # Add a mining reward transaction
        mining_reward = {
            "sender": "COINBASE",
            "recipient": self.wallet.address,
            "amount": self.blockchain.mining_reward,
            "timestamp": time.time()
        }
        self.blockchain.pending_transactions.append(mining_reward)
        
        # Create a new block
        new_block = Block(
            len(self.blockchain.chain),
            time.time(),
            self.blockchain.pending_transactions,
            self.blockchain.get_latest_block().hash
        )
        
        # Mine the block
        new_block.mine_block(self.blockchain.difficulty)
        
        # Add the block to the blockchain
        self.blockchain.chain.append(new_block)
        
        # Reset pending transactions
        self.blockchain.pending_transactions = []
        
        # Broadcast the new block
        self.broadcast_block(new_block)
        
        return new_block
    
    def create_transaction(self, recipient: str, amount: float) -> bool:
        """Create a new transaction and broadcast it to the network."""
        if not self.wallet:
            raise ValueError("No wallet configured for creating transactions")
        
        # Check if the sender has enough balance
        sender_balance = self.blockchain.get_balance(self.wallet.address)
        if sender_balance < amount:
            return False
        
        # Create a new transaction
        transaction = {
            "sender": self.wallet.address,
            "recipient": recipient,
            "amount": amount,
            "timestamp": time.time()
        }
        
        # Sign the transaction
        transaction["signature"] = self.wallet.sign_transaction(transaction)
        
        # Add the transaction to pending transactions
        self.blockchain.pending_transactions.append(transaction)
        
        # Broadcast the transaction
        self.broadcast_transaction(transaction)
        
        return True
    
    def set_wallet(self, wallet: Wallet) -> None:
        """Set the wallet for this node."""
        self.wallet = wallet
        print(f"Wallet set: {wallet.address}")
    
    def close(self) -> None:
        """Close the node server."""
        self.socket.close()
        print("Node closed")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Straz cryptocurrency node")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to")
    parser.add_argument("--connect", type=str, help="Peer to connect to in format host:port")
    args = parser.parse_args()
    
    # Create a node
    node = Node(args.host, args.port)
    
    # Create a wallet for the node
    wallet = Wallet()
    node.set_wallet(wallet)
    
    # Start the node
    node.start()
    
    # Connect to a peer if specified
    if args.connect:
        peer_host, peer_port = args.connect.split(":")
        if node.connect_to_peer(peer_host, int(peer_port)):
            print(f"Connected to peer {args.connect}")
        else:
            print(f"Failed to connect to peer {args.connect}")
    
    # Start a simple interactive console
    while True:
        try:
            command = input("straz> ").strip()
            
            if command == "exit":
                node.close()
                break
            
            elif command == "help":
                print("Available commands:")
                print("  help - Show this help message")
                print("  exit - Exit the node")
                print("  peers - Show the list of peers")
                print("  connect <host:port> - Connect to a peer")
                print("  balance - Show the wallet balance")
                print("  mine - Mine a new block")
                print("  send <recipient> <amount> - Send coins to a recipient")
                print("  chain - Show the blockchain")
                print("  save <filename> - Save the blockchain to a file")
                print("  load <filename> - Load the blockchain from a file")
            
            elif command == "peers":
                print(f"Peers: {', '.join(node.peers) if node.peers else 'None'}")
            
            elif command.startswith("connect "):
                peer_url = command.split(" ")[1]
                peer_host, peer_port = peer_url.split(":")
                if node.connect_to_peer(peer_host, int(peer_port)):
                    print(f"Connected to peer {peer_url}")
                else:
                    print(f"Failed to connect to peer {peer_url}")
            
            elif command == "balance":
                balance = node.blockchain.get_balance(node.wallet.address)
                print(f"Balance: {balance} STRZ")
            
            elif command == "mine":
                print("Mining a new block...")
                block = node.mine_block()
                print(f"Block mined: {block.hash}")
            
            elif command.startswith("send "):
                parts = command.split(" ")
                if len(parts) != 3:
                    print("Usage: send <recipient> <amount>")
                    continue
                
                recipient = parts[1]
                try:
                    amount = float(parts[2])
                except ValueError:
                    print("Amount must be a number")
                    continue
                
                if node.create_transaction(recipient, amount):
                    print(f"Transaction created: {amount} STRZ to {recipient}")
                else:
                    print("Failed to create transaction: insufficient balance")
            
            elif command == "chain":
                print(f"Blockchain: {len(node.blockchain.chain)} blocks")
                for block in node.blockchain.chain:
                    print(f"Block #{block.index}: {block.hash}")
            
            elif command.startswith("save "):
                filename = command.split(" ")[1]
                node.blockchain.save_to_file(filename)
                print(f"Blockchain saved to {filename}")
            
            elif command.startswith("load "):
                filename = command.split(" ")[1]
                node.blockchain = Blockchain.load_from_file(filename)
                print(f"Blockchain loaded from {filename}")
            
            else:
                print(f"Unknown command: {command}")
        
        except Exception as e:
            print(f"Error: {e}")
