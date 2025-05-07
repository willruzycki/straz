#!/usr/bin/env python3

import argparse
import os
import sys
import time
from typing import Dict, List, Any

from blockchain import Blockchain, Block
from wallet import Wallet, WalletManager
from node import Node

class StrazCLI:
    def __init__(self):
        self.blockchain = Blockchain()
        self.wallet_manager = WalletManager()
        self.node = None
        self.active_wallet = None
        
        # Create wallets directory if it doesn't exist
        os.makedirs("wallets", exist_ok=True)
        
        # Load existing wallets if any
        if os.path.exists("wallets"):
            self.wallet_manager.load_wallets("wallets")
            
            # Set the first wallet as active if available
            addresses = self.wallet_manager.get_all_addresses()
            if addresses:
                self.active_wallet = self.wallet_manager.get_wallet(addresses[0])
        
        # Create a wallet if none exists
        if not self.active_wallet:
            self.active_wallet = self.wallet_manager.create_wallet()
            self.wallet_manager.save_wallets("wallets")
            
    def start(self):
        """Start the Straz CLI."""
        parser = argparse.ArgumentParser(description="Straz Cryptocurrency")
        subparsers = parser.add_subparsers(dest="command", help="Command")
        
        # Node commands
        node_parser = subparsers.add_parser("node", help="Node operations")
        node_subparsers = node_parser.add_subparsers(dest="node_command", help="Node command")
        
        start_parser = node_subparsers.add_parser("start", help="Start a node")
        start_parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to")
        start_parser.add_argument("--port", type=int, default=5000, help="Port to bind to")
        start_parser.add_argument("--connect", type=str, help="Peer to connect to in format host:port")
        
        node_subparsers.add_parser("stop", help="Stop the node")
        node_subparsers.add_parser("status", help="Get node status")
        
        connect_parser = node_subparsers.add_parser("connect", help="Connect to a peer")
        connect_parser.add_argument("peer", type=str, help="Peer to connect to in format host:port")
        
        node_subparsers.add_parser("peers", help="List connected peers")
        
        # Wallet commands
        wallet_parser = subparsers.add_parser("wallet", help="Wallet operations")
        wallet_subparsers = wallet_parser.add_subparsers(dest="wallet_command", help="Wallet command")
        
        wallet_subparsers.add_parser("create", help="Create a new wallet")
        wallet_subparsers.add_parser("list", help="List all wallets")
        
        import_parser = wallet_subparsers.add_parser("import", help="Import a wallet from a private key")
        import_parser.add_argument("private_key", type=str, help="Private key to import")
        
        set_parser = wallet_subparsers.add_parser("set", help="Set active wallet")
        set_parser.add_argument("address", type=str, help="Address of the wallet to set as active")
        
        wallet_subparsers.add_parser("show", help="Show active wallet details")
        wallet_subparsers.add_parser("balance", help="Show wallet balance")
        
        export_parser = wallet_subparsers.add_parser("export", help="Export wallet to a file")
        export_parser.add_argument("--file", type=str, help="File to export to")
        
        # Mining commands
        mine_parser = subparsers.add_parser("mine", help="Mining operations")
        mine_subparsers = mine_parser.add_subparsers(dest="mine_command", help="Mining command")
        
        mine_subparsers.add_parser("start", help="Start mining")
        mine_subparsers.add_parser("stop", help="Stop mining")
        
        # Transaction commands
        tx_parser = subparsers.add_parser("tx", help="Transaction operations")
        tx_subparsers = tx_parser.add_subparsers(dest="tx_command", help="Transaction command")
        
        send_parser = tx_subparsers.add_parser("send", help="Send coins")
        send_parser.add_argument("recipient", type=str, help="Recipient address")
        send_parser.add_argument("amount", type=float, help="Amount to send")
        
        tx_subparsers.add_parser("pending", help="List pending transactions")
        
        # Blockchain commands
        chain_parser = subparsers.add_parser("chain", help="Blockchain operations")
        chain_subparsers = chain_parser.add_subparsers(dest="chain_command", help="Blockchain command")
        
        chain_subparsers.add_parser("info", help="Get blockchain info")
        
        block_parser = chain_subparsers.add_parser("block", help="Get block by index")
        block_parser.add_argument("index", type=int, help="Block index")
        
        save_parser = chain_subparsers.add_parser("save", help="Save blockchain to a file")
        save_parser.add_argument("--file", type=str, default="blockchain.json", help="File to save to")
        
        load_parser = chain_subparsers.add_parser("load", help="Load blockchain from a file")
        load_parser.add_argument("--file", type=str, default="blockchain.json", help="File to load from")
        
        chain_subparsers.add_parser("validate", help="Validate the blockchain")
        
        # Parse arguments
        args = parser.parse_args()
        
        if not args.command:
            self.interactive_mode()
            return
        
        # Handle commands
        if args.command == "node":
            self.handle_node_command(args)
        elif args.command == "wallet":
            self.handle_wallet_command(args)
        elif args.command == "mine":
            self.handle_mine_command(args)
        elif args.command == "tx":
            self.handle_tx_command(args)
        elif args.command == "chain":
            self.handle_chain_command(args)
    
    def handle_node_command(self, args):
        """Handle node commands."""
        if args.node_command == "start":
            if self.node:
                print("Node already running")
                return
            
            self.node = Node(args.host, args.port)
            self.node.set_wallet(self.active_wallet)
            self.node.start()
            
            if args.connect:
                peer_host, peer_port = args.connect.split(":")
                if self.node.connect_to_peer(peer_host, int(peer_port)):
                    print(f"Connected to peer {args.connect}")
                else:
                    print(f"Failed to connect to peer {args.connect}")
            
            print(f"Node started on {args.host}:{args.port}")
        
        elif args.node_command == "stop":
            if not self.node:
                print("No node running")
                return
            
            self.node.close()
            self.node = None
            print("Node stopped")
        
        elif args.node_command == "status":
            if not self.node:
                print("No node running")
                return
            
            print(f"Node running on {self.node.host}:{self.node.port}")
            print(f"Connected peers: {len(self.node.peers)}")
            print(f"Blockchain: {len(self.node.blockchain.chain)} blocks")
            print(f"Pending transactions: {len(self.node.blockchain.pending_transactions)}")
        
        elif args.node_command == "connect":
            if not self.node:
                print("No node running")
                return
            
            peer_host, peer_port = args.peer.split(":")
            if self.node.connect_to_peer(peer_host, int(peer_port)):
                print(f"Connected to peer {args.peer}")
            else:
                print(f"Failed to connect to peer {args.peer}")
        
        elif args.node_command == "peers":
            if not self.node:
                print("No node running")
                return
            
            print(f"Connected peers: {', '.join(self.node.peers) if self.node.peers else 'None'}")
    
    def handle_wallet_command(self, args):
        """Handle wallet commands."""
        if args.wallet_command == "create":
            wallet = self.wallet_manager.create_wallet()
            self.active_wallet = wallet
            self.wallet_manager.save_wallets("wallets")
            print(f"New wallet created: {wallet.address}")
            
            if self.node:
                self.node.set_wallet(wallet)
        
        elif args.wallet_command == "list":
            addresses = self.wallet_manager.get_all_addresses()
            if not addresses:
                print("No wallets found")
                return
            
            print("Wallets:")
            for i, address in enumerate(addresses):
                active = " (active)" if self.active_wallet and self.active_wallet.address == address else ""
                print(f"{i+1}. {address}{active}")
        
        elif args.wallet_command == "import":
            try:
                wallet = self.wallet_manager.import_wallet(args.private_key)
                self.active_wallet = wallet
                self.wallet_manager.save_wallets("wallets")
                print(f"Wallet imported: {wallet.address}")
                
                if self.node:
                    self.node.set_wallet(wallet)
            except Exception as e:
                print(f"Error importing wallet: {e}")
        
        elif args.wallet_command == "set":
            wallet = self.wallet_manager.get_wallet(args.address)
            if not wallet:
                print(f"Wallet not found: {args.address}")
                return
            
            self.active_wallet = wallet
            print(f"Active wallet set to: {wallet.address}")
            
            if self.node:
                self.node.set_wallet(wallet)
        
        elif args.wallet_command == "show":
            if not self.active_wallet:
                print("No active wallet")
                return
            
            print(f"Address: {self.active_wallet.address}")
            print(f"Private key: {self.active_wallet.private_key}")
            print(f"Public key: {self.active_wallet.public_key}")
        
        elif args.wallet_command == "balance":
            if not self.active_wallet:
                print("No active wallet")
                return
            
            balance = self.blockchain.get_balance(self.active_wallet.address)
            print(f"Balance: {balance} STRZ")
        
        elif args.wallet_command == "export":
            if not self.active_wallet:
                print("No active wallet")
                return
            
            filename = args.file or f"{self.active_wallet.address}.json"
            self.active_wallet.save_to_file(filename)
            print(f"Wallet exported to {filename}")
    
    def handle_mine_command(self, args):
        """Handle mining commands."""
        if not self.node:
            print("No node running, start a node first")
            return
        
        if args.mine_command == "start":
            print("Mining a new block...")
            block = self.node.mine_block()
            print(f"Block mined: {block.hash}")
        
        elif args.mine_command == "stop":
            print("Mining stopped")
    
    def handle_tx_command(self, args):
        """Handle transaction commands."""
        if not self.node:
            print("No node running, start a node first")
            return
        
        if args.tx_command == "send":
            if not self.active_wallet:
                print("No active wallet")
                return
            
            if self.node.create_transaction(args.recipient, args.amount):
                print(f"Transaction created: {args.amount} STRZ to {args.recipient}")
            else:
                print("Failed to create transaction: insufficient balance")
        
        elif args.tx_command == "pending":
            if not self.node.blockchain.pending_transactions:
                print("No pending transactions")
                return
            
            print(f"Pending transactions: {len(self.node.blockchain.pending_transactions)}")
            for i, tx in enumerate(self.node.blockchain.pending_transactions):
                print(f"{i+1}. {tx['sender']} -> {tx['recipient']}: {tx['amount']} STRZ")
    
    def handle_chain_command(self, args):
        """Handle blockchain commands."""
        if args.chain_command == "info":
            print(f"Blockchain: {len(self.blockchain.chain)} blocks")
            print(f"Difficulty: {self.blockchain.difficulty}")
            print(f"Mining reward: {self.blockchain.mining_reward} STRZ")
        
        elif args.chain_command == "block":
            if args.index >= len(self.blockchain.chain):
                print(f"Block index out of range: {args.index}")
                return
            
            block = self.blockchain.chain[args.index]
            print(f"Block #{block.index}")
            print(f"Timestamp: {block.timestamp}")
            print(f"Previous hash: {block.previous_hash}")
            print(f"Hash: {block.hash}")
            print(f"Nonce: {block.nonce}")
            print(f"Transactions: {len(block.transactions)}")
            
            for i, tx in enumerate(block.transactions):
                print(f"  {i+1}. {tx['sender']} -> {tx['recipient']}: {tx['amount']} STRZ")
        
        elif args.chain_command == "save":
            self.blockchain.save_to_file(args.file)
            print(f"Blockchain saved to {args.file}")
        
        elif args.chain_command == "load":
            if os.path.exists(args.file):
                self.blockchain = Blockchain.load_from_file(args.file)
                print(f"Blockchain loaded from {args.file}")
                
                if self.node:
                    self.node.blockchain = self.blockchain
            else:
                print(f"File not found: {args.file}")
        
        elif args.chain_command == "validate":
            is_valid = self.blockchain.is_chain_valid()
            print(f"Blockchain valid: {is_valid}")
    
    def interactive_mode(self):
        """Start an interactive command line interface."""
        print("Welcome to Straz CLI!")
        print("Type 'help' for a list of commands, 'exit' to quit.")
        
        while True:
            try:
                command = input("straz> ").strip()
                
                if command == "exit":
                    if self.node:
                        self.node.close()
                    break
                
                elif command == "help":
                    self.print_help()
                
                elif command == "clear":
                    os.system("clear" if os.name == "posix" else "cls")
                
                elif command.startswith("node "):
                    self.handle_interactive_node_command(command[5:])
                
                elif command.startswith("wallet "):
                    self.handle_interactive_wallet_command(command[7:])
                
                elif command.startswith("mine "):
                    self.handle_interactive_mine_command(command[5:])
                
                elif command.startswith("tx "):
                    self.handle_interactive_tx_command(command[3:])
                
                elif command.startswith("chain "):
                    self.handle_interactive_chain_command(command[6:])
                
                else:
                    print(f"Unknown command: {command}")
            
            except Exception as e:
                print(f"Error: {e}")
    
    def print_help(self):
        """Print help message."""
        print("Available commands:")
        print("  help - Show this help message")
        print("  exit - Exit the CLI")
        print("  clear - Clear the screen")
        print("  node start [host] [port] [peer] - Start a node")
        print("  node stop - Stop the node")
        print("  node status - Get node status")
        print("  node connect <host:port> - Connect to a peer")
        print("  node peers - List connected peers")
        print("  wallet create - Create a new wallet")
        print("  wallet list - List all wallets")
        print("  wallet import <private_key> - Import a wallet from a private key")
        print("  wallet set <address> - Set active wallet")
        print("  wallet show - Show active wallet details")
        print("  wallet balance - Show wallet balance")
        print("  wallet export [file] - Export wallet to a file")
        print("  mine start - Start mining")
        print("  tx send <recipient> <amount> - Send coins")
        print("  tx pending - List pending transactions")
        print("  chain info - Get blockchain info")
        print("  chain block <index> - Get block by index")
        print("  chain save [file] - Save blockchain to a file")
        print("  chain load [file] - Load blockchain from a file")
        print("  chain validate - Validate the blockchain")
    
    def handle_interactive_node_command(self, command):
        """Handle interactive node commands."""
        parts = command.split()
        
        if not parts:
            print("Missing node command")
            return
        
        if parts[0] == "start":
            if self.node:
                print("Node already running")
                return
            
            host = parts[1] if len(parts) > 1 else "0.0.0.0"
            port = int(parts[2]) if len(parts) > 2 else 5000
            
            self.node = Node(host, port)
            self.node.set_wallet(self.active_wallet)
            self.node.start()
            
            if len(parts) > 3:
                peer = parts[3]
                peer_host, peer_port = peer.split(":")
                if self.node.connect_to_peer(peer_host, int(peer_port)):
                    print(f"Connected to peer {peer}")
                else:
                    print(f"Failed to connect to peer {peer}")
            
            print(f"Node started on {host}:{port}")
        
        elif parts[0] == "stop":
            if not self.node:
                print("No node running")
                return
            
            self.node.close()
            self.node = None
            print("Node stopped")
        
        elif parts[0] == "status":
            if not self.node:
                print("No node running")
                return
            
            print(f"Node running on {self.node.host}:{self.node.port}")
            print(f"Connected peers: {len(self.node.peers)}")
            print(f"Blockchain: {len(self.node.blockchain.chain)} blocks")
            print(f"Pending transactions: {len(self.node.blockchain.pending_transactions)}")
        
        elif parts[0] == "connect":
            if not self.node:
                print("No node running")
                return
            
            if len(parts) < 2:
                print("Missing peer address")
                return
            
            peer = parts[1]
            peer_host, peer_port = peer.split(":")
            if self.node.connect_to_peer(peer_host, int(peer_port)):
                print(f"Connected to peer {peer}")
            else:
                print(f"Failed to connect to peer {peer}")
        
        elif parts[0] == "peers":
            if not self.node:
                print("No node running")
                return
            
            print(f"Connected peers: {', '.join(self.node.peers) if self.node.peers else 'None'}")
        
        else:
            print(f"Unknown node command: {parts[0]}")
    
    def handle_interactive_wallet_command(self, command):
        """Handle interactive wallet commands."""
        parts = command.split()
        
        if not parts:
            print("Missing wallet command")
            return
        
        if parts[0] == "create":
            wallet = self.wallet_manager.create_wallet()
            self.active_wallet = wallet
            self.wallet_manager.save_wallets("wallets")
            print(f"New wallet created: {wallet.address}")
            
            if self.node:
                self.node.set_wallet(wallet)
        
        elif parts[0] == "list":
            addresses = self.wallet_manager.get_all_addresses()
            if not addresses:
                print("No wallets found")
                return
            
            print("Wallets:")
            for i, address in enumerate(addresses):
                active = " (active)" if self.active_wallet and self.active_wallet.address == address else ""
                print(f"{i+1}. {address}{active}")
        
        elif parts[0] == "import":
            if len(parts) < 2:
                print("Missing private key")
                return
            
            try:
                wallet = self.wallet_manager.import_wallet(parts[1])
                self.active_wallet = wallet
                self.wallet_manager.save_wallets("wallets")
                print(f"Wallet imported: {wallet.address}")
                
                if self.node:
                    self.node.set_wallet(wallet)
            except Exception as e:
                print(f"Error importing wallet: {e}")
        
        elif parts[0] == "set":
            if len(parts) < 2:
                print("Missing address")
                return
            
            wallet = self.wallet_manager.get_wallet(parts[1])
            if not wallet:
                print(f"Wallet not found: {parts[1]}")
                return
            
            self.active_wallet = wallet
            print(f"Active wallet set to: {wallet.address}")
            
            if self.node:
                self.node.set_wallet(wallet)
        
        elif parts[0] == "show":
            if not self.active_wallet:
                print("No active wallet")
                return
            
            print(f"Address: {self.active_wallet.address}")
            print(f"Private key: {self.active_wallet.private_key}")
            print(f"Public key: {self.active_wallet.public_key}")
        
        elif parts[0] == "balance":
            if not self.active_wallet:
                print("No active wallet")
                return
            
            balance = self.blockchain.get_balance(self.active_wallet.address)
            print(f"Balance: {balance} STRZ")
        
        elif parts[0] == "export":
            if not self.active_wallet:
                print("No active wallet")
                return
            
            filename = parts[1] if len(parts) > 1 else f"{self.active_wallet.address}.json"
            self.active_wallet.save_to_file(filename)
            print(f"Wallet exported to {filename}")
        
        else:
            print(f"Unknown wallet command: {parts[0]}")
    
    def handle_interactive_mine_command(self, command):
        """Handle interactive mining commands."""
        parts = command.split()
        
        if not parts:
            print("Missing mining command")
            return
        
        if not self.node:
            print("No node running, start a node first")
            return
        
        if parts[0] == "start":
            print("Mining a new block...")
            block = self.node.mine_block()
            print(f"Block mined: {block.hash}")
        
        else:
            print(f"Unknown mining command: {parts[0]}")
    
    def handle_interactive_tx_command(self, command):
        """Handle interactive transaction commands."""
        parts = command.split()
        
        if not parts:
            print("Missing transaction command")
            return
        
        if not self.node:
            print("No node running, start a node first")
            return
        
        if parts[0] == "send":
            if len(parts) < 3:
                print("Usage: tx send <recipient> <amount>")
                return
            
            if not self.active_wallet:
                print("No active wallet")
                return
            
            try:
                recipient = parts[1]
                amount = float(parts[2])
                
                if self.node.create_transaction(recipient, amount):
                    print(f"Transaction created: {amount} STRZ to {recipient}")
                else:
                    print("Failed to create transaction: insufficient balance")
            except ValueError:
                print("Amount must be a number")
        
        elif parts[0] == "pending":
            if not self.node.blockchain.pending_transactions:
                print("No pending transactions")
                return
            
            print(f"Pending transactions: {len(self.node.blockchain.pending_transactions)}")
            for i, tx in enumerate(self.node.blockchain.pending_transactions):
                print(f"{i+1}. {tx['sender']} -> {tx['recipient']}: {tx['amount']} STRZ")
        
        else:
            print(f"Unknown transaction command: {parts[0]}")
    
    def handle_interactive_chain_command(self, command):
        """Handle interactive blockchain commands."""
        parts = command.split()
        
        if not parts:
            print("Missing blockchain command")
            return
        
        if parts[0] == "info":
            print(f"Blockchain: {len(self.blockchain.chain)} blocks")
            print(f"Difficulty: {self.blockchain.difficulty}")
            print(f"Mining reward: {self.blockchain.mining_reward} STRZ")
        
        elif parts[0] == "block":
            if len(parts) < 2:
                print("Missing block index")
                return
            
            try:
                index = int(parts[1])
                
                if index >= len(self.blockchain.chain):
                    print(f"Block index out of range: {index}")
                    return
                
                block = self.blockchain.chain[index]
                print(f"Block #{block.index}")
                print(f"Timestamp: {block.timestamp}")
                print(f"Previous hash: {block.previous_hash}")
                print(f"Hash: {block.hash}")
                print(f"Nonce: {block.nonce}")
                print(f"Transactions: {len(block.transactions)}")
                
                for i, tx in enumerate(block.transactions):
                    print(f"  {i+1}. {tx['sender']} -> {tx['recipient']}: {tx['amount']} STRZ")
            except ValueError:
                print("Block index must be a number")
        
        elif parts[0] == "save":
            filename = parts[1] if len(parts) > 1 else "blockchain.json"
            self.blockchain.save_to_file(filename)
            print(f"Blockchain saved to {filename}")
        
        elif parts[0] == "load":
            filename = parts[1] if len(parts) > 1 else "blockchain.json"
            
            if os.path.exists(filename):
                self.blockchain = Blockchain.load_from_file(filename)
                print(f"Blockchain loaded from {filename}")
                
                if self.node:
                    self.node.blockchain = self.blockchain
            else:
                print(f"File not found: {filename}")
        
        elif parts[0] == "validate":
            is_valid = self.blockchain.is_chain_valid()
            print(f"Blockchain valid: {is_valid}")
        
        else:
            print(f"Unknown blockchain command: {parts[0]}")


if __name__ == "__main__":
    cli = StrazCLI()
    cli.start()
