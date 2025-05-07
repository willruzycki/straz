#!/usr/bin/env python3

import hashlib
import json
import time
import binascii
from typing import List, Dict, Any
import struct
from smart_contract import ContractManager
from consensus import Consensus
import os

class Block:
    def __init__(self, index: int, timestamp: float, transactions: List[Dict], previous_hash: str, nonce: int = 0):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()
        self.validator_signatures: List[str] = []

    def calculate_hash(self) -> str:
        """Calculate the hash of the block contents."""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        
        return hashlib.sha256(block_string).hexdigest()
    
    def mine_block(self, difficulty: int) -> None:
        """Mine the block by finding a hash with the required number of leading zeros."""
        target = "0" * difficulty
        
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
            
        print(f"Block mined: {self.hash}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the block to a dictionary."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
            "validator_signatures": self.validator_signatures
        }


class Blockchain:
    def __init__(self, difficulty: int = 4):
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict] = []
        self.difficulty = difficulty
        self.mining_reward = 50  # 50 STRZ
        self.contract_manager = ContractManager()
        self.consensus = Consensus(difficulty)
        
        # Create the genesis block
        self.create_genesis_block()
    
    def create_genesis_block(self) -> None:
        """Create the genesis block for the blockchain."""
        # Import the genesis block creation from genesis.py
        from genesis import calc_hash_str
        
        # Create a simple genesis block with no transactions
        genesis_block = Block(0, time.time(), [], "0")
        
        # Set the hash directly from our genesis script
        genesis_block.hash = calc_hash_str(b'\x00' * 32)  # Simplified for now
        
        self.chain.append(genesis_block)
        print(f"Genesis block created with hash: {genesis_block.hash}")
    
    def get_latest_block(self) -> Block:
        """Return the latest block in the chain."""
        return self.chain[-1]
    
    async def mine_pending_transactions(self, mining_reward_address: str) -> None:
        """Mine pending transactions and add them to the blockchain."""
        # Create a reward transaction for the miner
        self.pending_transactions.append({
            "sender": "COINBASE",
            "recipient": mining_reward_address,
            "amount": self.mining_reward,
            "timestamp": time.time()
        })
        
        # Create a new block with pending transactions
        block = Block(
            len(self.chain),
            time.time(),
            self.pending_transactions,
            self.get_latest_block().hash
        )
        
        # Mine the block
        block.mine_block(self.difficulty)
        
        # Process block through consensus
        if await self.consensus.process_block(block.to_dict(), mining_reward_address):
            # Add the mined block to the chain
            self.chain.append(block)
            
            # Process smart contract transactions
            for tx in self.pending_transactions:
                if tx.get("type") == "contract":
                    self.contract_manager.execute_contract(
                        tx["contract_address"],
                        tx["method"],
                        tx["params"],
                        tx["sender"],
                        tx.get("value", 0)
                    )
            
            # Reset pending transactions
            self.pending_transactions = []
            
            print(f"Block #{block.index} has been mined and added to the chain")
        else:
            print("Block rejected by consensus")
    
    def create_transaction(self, sender: str, recipient: str, amount: float) -> None:
        """Add a new transaction to the pending transactions pool."""
        self.pending_transactions.append({
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
            "timestamp": time.time()
        })
    
    def create_contract_transaction(self, sender: str, contract_address: str, method: str, params: List[Any], value: float = 0) -> None:
        """Add a new contract transaction to the pending transactions pool."""
        self.pending_transactions.append({
            "type": "contract",
            "sender": sender,
            "contract_address": contract_address,
            "method": method,
            "params": params,
            "value": value,
            "timestamp": time.time()
        })
    
    def get_balance(self, address: str) -> float:
        """Calculate the balance of a given address based on all transactions in the blockchain."""
        balance = 0.0
        
        for block in self.chain:
            for transaction in block.transactions:
                if transaction["sender"] == address:
                    balance -= transaction["amount"]
                if transaction["recipient"] == address:
                    balance += transaction["amount"]
        
        return balance
    
    def is_chain_valid(self) -> bool:
        """Validate the integrity of the blockchain."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Verify the current block's hash
            if current_block.hash != current_block.calculate_hash():
                print("Current block's hash is invalid")
                return False
            
            # Verify the chain link
            if current_block.previous_hash != previous_block.hash:
                print("Chain link is broken")
                return False
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the blockchain to a dictionary."""
        return {
            "chain": [block.to_dict() for block in self.chain],
            "pending_transactions": self.pending_transactions,
            "difficulty": self.difficulty
        }
    
    def save_to_file(self, filename: str) -> None:
        """Save the blockchain to a file."""
        with open(filename, 'w') as f:
            json.dump(self.to_dict(), f, indent=4)
        
        # Save contracts and consensus state
        self.contract_manager.save_contracts("contracts.json")
        self.consensus.save_state("consensus.json")
        
        print(f"Blockchain saved to {filename}")
    
    @classmethod
    def load_from_file(cls, filename: str) -> 'Blockchain':
        """Load the blockchain from a file."""
        blockchain = cls()  # Create a new instance
        
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            blockchain.difficulty = data["difficulty"]
            blockchain.chain = []
            
            for block_data in data["chain"]:
                block = Block(
                    block_data["index"],
                    block_data["timestamp"],
                    block_data["transactions"],
                    block_data["previous_hash"],
                    block_data["nonce"]
                )
                block.hash = block_data["hash"]
                block.validator_signatures = block_data.get("validator_signatures", [])
                blockchain.chain.append(block)
            
            blockchain.pending_transactions = data["pending_transactions"]
            
            # Load contracts if they exist
            if os.path.exists("contracts.json"):
                blockchain.contract_manager.load_contracts("contracts.json")
            
            # Load consensus state if it exists
            if os.path.exists("consensus.json"):
                blockchain.consensus.load_state("consensus.json")
            
            print(f"Blockchain loaded from {filename}")
            return blockchain
            
        except FileNotFoundError:
            print(f"No existing blockchain found at {filename}")
            return blockchain  # Return a fresh blockchain
        except json.JSONDecodeError:
            print(f"Error decoding blockchain file {filename}")
            return blockchain  # Return a fresh blockchain
        except Exception as e:
            print(f"Error loading blockchain: {str(e)}")
            return blockchain  # Return a fresh blockchain


if __name__ == "__main__":
    # Example usage
    straz_chain = Blockchain(difficulty=4)
    
    print("Mining genesis block...")
    straz_chain.mine_pending_transactions("miner-address-1")
    
    print("\nCreating some transactions...")
    straz_chain.create_transaction("address-1", "address-2", 10)
    straz_chain.create_transaction("address-2", "address-1", 5)
    
    print("\nMining block...")
    straz_chain.mine_pending_transactions("miner-address-1")
    
    print("\nBlockchain valid:", straz_chain.is_chain_valid())
    print("\nMiner's balance:", straz_chain.get_balance("miner-address-1"))
    
    print("\nSaving blockchain...")
    straz_chain.save_to_file("straz_blockchain.json")
