#!/usr/bin/env python3

import hashlib
import json
import time
import binascii
from typing import List, Dict, Any, Optional
import struct
from smart_contract import ContractManager
from consensus import Consensus
from zk_quantum import ZKRollup, QuantumResistantCrypto, ZKTransaction
import os
import logging
from dataclasses import dataclass
from quantum_crypto import AdvancedQuantumCrypto, QuantumKeyPair
import base64

logger = logging.getLogger(__name__)

@dataclass
class ShardInfo:
    id: int
    validators: List[str]
    transactions: List[Dict]
    state_root: str
    last_block: int
    zk_rollup: Optional[ZKRollup] = None

class Block:
    def __init__(self, index: int, timestamp: float, transactions: List[Dict], previous_hash: str, nonce: int = 0):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()
        self.validator_signatures: List[str] = []
        self.shard_id: Optional[int] = None
        self.cross_chain_refs: List[Dict] = []
        self.state_root: str = ""
        self.receipt_root: str = ""
        self.zk_proof: Optional[bytes] = None  # Zero-knowledge proof for the block

    def calculate_hash(self) -> str:
        """Calculate the hash of the block contents."""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "shard_id": self.shard_id,
            "cross_chain_refs": self.cross_chain_refs,
            "state_root": self.state_root,
            "receipt_root": self.receipt_root,
            "zk_proof": self.zk_proof.hex() if self.zk_proof else None
        }, sort_keys=True).encode()
        
        return hashlib.sha3_256(block_string).hexdigest()  # Using SHA3-256 for quantum resistance
    
    def mine_block(self, difficulty: int) -> None:
        """Mine the block by finding a hash with the required number of leading zeros."""
        target = "0" * difficulty
        
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
            
        logger.info(f"Block mined: {self.hash}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the block to a dictionary."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
            "validator_signatures": self.validator_signatures,
            "shard_id": self.shard_id,
            "cross_chain_refs": self.cross_chain_refs,
            "state_root": self.state_root,
            "receipt_root": self.receipt_root,
            "zk_proof": self.zk_proof.hex() if self.zk_proof else None
        }

class Blockchain:
    def __init__(self, difficulty: int = 4):
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict] = []
        self.difficulty = difficulty
        self.mining_reward = 50  # 50 STRZ
        self.contract_manager = ContractManager()
        self.consensus = Consensus(difficulty)
        self.transaction_pool: Dict[str, Dict] = {}  # tx_hash -> transaction
        self.max_transactions_per_block = 1000
        self.min_transaction_fee = 0.001  # Minimum fee in STRZ
        
        # Initialize quantum-resistant cryptography
        self.quantum_crypto = AdvancedQuantumCrypto()
        
        # Sharding configuration
        self.num_shards = 4
        self.shards: Dict[int, ShardInfo] = {}
        self.cross_chain_bridges: Dict[str, Dict] = {}
        
        # Initialize shards with ZK-rollups
        for i in range(self.num_shards):
            self.shards[i] = ShardInfo(
                id=i,
                validators=[],
                transactions=[],
                state_root="",
                last_block=0,
                zk_rollup=ZKRollup()
            )
        
        # Create the genesis block
        self.create_genesis_block()
        
        self.validator_keys = {}  # Store validator quantum key pairs
    
    def create_genesis_block(self) -> None:
        """Create the genesis block for the blockchain."""
        genesis_block = Block(0, time.time(), [], "0")
        genesis_block.hash = hashlib.sha256(b'\x00' * 32).hexdigest()
        genesis_block.state_root = self._calculate_state_root({})
        genesis_block.receipt_root = self._calculate_receipt_root([])
        
        self.chain.append(genesis_block)
        logger.info(f"Genesis block created with hash: {genesis_block.hash}")
    
    def _calculate_state_root(self, state: Dict) -> str:
        """Calculate the Merkle root of the state trie."""
        # Simplified implementation - in a real blockchain, this would use a proper Merkle Patricia Trie
        return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()
    
    def _calculate_receipt_root(self, receipts: List[Dict]) -> str:
        """Calculate the Merkle root of the transaction receipts."""
        # Simplified implementation
        return hashlib.sha256(json.dumps(receipts, sort_keys=True).encode()).hexdigest()
    
    def get_latest_block(self) -> Block:
        """Return the latest block in the chain."""
        return self.chain[-1]
    
    def validate_transaction(self, transaction: Dict) -> bool:
        """Validate a transaction before adding it to the pool"""
        required_fields = ["sender", "recipient", "amount", "timestamp", "signature"]
        if not all(field in transaction for field in required_fields):
            return False
        
        # Skip validation for coinbase transactions
        if transaction["sender"] == "COINBASE":
            return True
        
        # Check if sender has sufficient balance
        sender_balance = self.get_balance(transaction["sender"])
        if sender_balance < transaction["amount"]:
            return False
        
        # Verify transaction signature
        if not self.verify_transaction_signature(transaction):
            return False
        
        # Check for double spending
        tx_hash = self.calculate_transaction_hash(transaction)
        if tx_hash in self.transaction_pool:
            return False
        
        return True

    def calculate_transaction_hash(self, transaction: Dict) -> str:
        """Calculate the hash of a transaction"""
        tx_string = json.dumps({
            "sender": transaction["sender"],
            "recipient": transaction["recipient"],
            "amount": transaction["amount"],
            "timestamp": transaction["timestamp"]
        }, sort_keys=True).encode()
        return hashlib.sha256(tx_string).hexdigest()

    def verify_transaction_signature(self, transaction: Dict) -> bool:
        """Verify the signature of a transaction using quantum-resistant cryptography"""
        if "signature" not in transaction:
            return False
        
        try:
            # For ZK transactions, verify the ZK proof
            if transaction.get("is_zk", False):
                shard_id = int(hashlib.sha256(transaction["sender"].encode()).hexdigest(), 16) % self.num_shards
                zk_rollup = self.shards[shard_id].zk_rollup
                if zk_rollup and "zk_proof" in transaction:
                    return zk_rollup.verify_zk_proof(transaction["zk_proof"])
            
            # For regular transactions, verify the quantum-resistant signature
            message = json.dumps({
                "sender": transaction["sender"],
                "recipient": transaction["recipient"],
                "amount": transaction["amount"],
                "timestamp": transaction["timestamp"]
            }).encode()
            
            return self.quantum_crypto.verify_signature(
                message,
                transaction["signature"],
                self.quantum_crypto.generate_key_pair()[1]  # Public key
            )
        except Exception as e:
            logger.error(f"Error verifying transaction signature: {e}")
            return False

    def create_transaction(self, sender: str, recipient: str, amount: float, fee: float = 0.001, use_zk: bool = False, use_quantum: bool = True) -> bool:
        """Add a new transaction to the pending transactions pool."""
        if fee < self.min_transaction_fee:
            return False
        
        transaction = {
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
            "fee": fee,
            "timestamp": time.time()
        }
        
        if use_zk:
            # Generate zero-knowledge proof for the transaction
            shard_id = int(hashlib.sha256(sender.encode()).hexdigest(), 16) % self.num_shards
            zk_rollup = self.shards[shard_id].zk_rollup
            
            if zk_rollup:
                proof = zk_rollup.generate_zk_proof(transaction)
                if proof:
                    # Create ZK transaction
                    zk_tx = ZKTransaction(
                        sender=sender,
                        recipient=recipient,
                        amount=amount,
                        proof=proof,
                        timestamp=time.time(),
                        signature=self.quantum_crypto.sign(
                            json.dumps(transaction).encode(),
                            self.quantum_crypto.generate_key_pair()[0]
                        )
                    )
                    
                    # Add to ZK-rollup batch
                    if zk_rollup.add_transaction_to_batch(zk_tx):
                        transaction["zk_proof"] = proof
                        transaction["is_zk"] = True
        
        if use_quantum:
            # Generate quantum key pair if not exists
            if sender not in self.validator_keys:
                self.validator_keys[sender] = self.quantum_crypto.generate_quantum_key_pair()
            
            # Create transaction
            transaction = {
                "sender": sender,
                "recipient": recipient,
                "amount": amount,
                "fee": fee,
                "timestamp": time.time()
            }
            
            # Sign with multiple quantum-resistant algorithms
            message = f"{sender}{recipient}{amount}".encode()
            signatures = self.quantum_crypto.multi_sign(
                message,
                self.validator_keys[sender]
            )
            
            # Store signatures in transaction
            transaction["signature"] = json.dumps({
                'signatures': {
                    k: base64.b64encode(v).decode()
                    for k, v in signatures.items()
                }
            })
        
        if self.validate_transaction(transaction):
            tx_hash = self.calculate_transaction_hash(transaction)
            self.transaction_pool[tx_hash] = transaction
            return True
        return False

    async def mine_pending_transactions(self, mining_reward_address: str) -> None:
        """Mine pending transactions and add them to the blockchain."""
        # Sort transactions by fee (higher fees first)
        sorted_transactions = sorted(
            self.transaction_pool.values(),
            key=lambda x: x.get("fee", 0),
            reverse=True
        )
        
        # Take only the maximum number of transactions per block
        transactions_to_process = sorted_transactions[:self.max_transactions_per_block]
        
        # Create a reward transaction for the miner
        total_fees = sum(tx.get("fee", 0) for tx in transactions_to_process)
        self.pending_transactions.append({
            "sender": "COINBASE",
            "recipient": mining_reward_address,
            "amount": self.mining_reward + total_fees,
            "timestamp": time.time()
        })
        
        # Add selected transactions
        self.pending_transactions.extend(transactions_to_process)
        
        # Create a new block with pending transactions
        block = Block(
            len(self.chain),
            time.time(),
            self.pending_transactions,
            self.get_latest_block().hash
        )
        
        # Assign transactions to shards and generate ZK proofs
        self._assign_transactions_to_shards(block)
        
        # Generate ZK proof for the block if it contains ZK transactions
        if any(tx.get("is_zk", False) for tx in block.transactions):
            shard_id = block.shard_id
            if shard_id is not None:
                zk_rollup = self.shards[shard_id].zk_rollup
                if zk_rollup:
                    batch_proof = zk_rollup.generate_batch_proof()
                    if batch_proof:
                        block.zk_proof = batch_proof.proof
        
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
            
            # Remove processed transactions from the pool
            for tx in transactions_to_process:
                tx_hash = self.calculate_transaction_hash(tx)
                self.transaction_pool.pop(tx_hash, None)
            
            # Reset pending transactions
            self.pending_transactions = []
            
            logger.info(f"Block #{block.index} has been mined and added to the chain")
        else:
            logger.warning("Block rejected by consensus")
    
    def _assign_transactions_to_shards(self, block: Block) -> None:
        """Assign transactions to different shards based on sender address"""
        shard_transactions: Dict[int, List[Dict]] = {i: [] for i in range(self.num_shards)}
        
        for tx in block.transactions:
            # Skip coinbase transactions
            if tx["sender"] == "COINBASE":
                continue
            
            # Assign to shard based on sender address hash
            shard_id = int(hashlib.sha256(tx["sender"].encode()).hexdigest(), 16) % self.num_shards
            shard_transactions[shard_id].append(tx)
        
        # Update shard information
        for shard_id, transactions in shard_transactions.items():
            self.shards[shard_id].transactions.extend(transactions)
            self.shards[shard_id].last_block = block.index
    
    def create_cross_chain_bridge(self, target_chain: str, bridge_address: str) -> bool:
        """Create a cross-chain bridge to another blockchain"""
        if target_chain in self.cross_chain_bridges:
            return False
        
        self.cross_chain_bridges[target_chain] = {
            "bridge_address": bridge_address,
            "active": True,
            "last_sync": time.time(),
            "total_transfers": 0
        }
        return True
    
    def process_cross_chain_transaction(self, source_chain: str, transaction: Dict) -> bool:
        """Process a transaction from another blockchain"""
        if source_chain not in self.cross_chain_bridges:
            return False
        
        bridge = self.cross_chain_bridges[source_chain]
        if not bridge["active"]:
            return False
        
        # Verify the transaction is from the bridge
        if transaction["sender"] != bridge["bridge_address"]:
            return False
        
        # Process the transaction
        success = self.create_transaction(
            transaction["sender"],
            transaction["recipient"],
            transaction["amount"]
        )
        
        if success:
            bridge["total_transfers"] += 1
            bridge["last_sync"] = time.time()
        
        return success
    
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
                logger.error("Current block's hash is invalid")
                return False
            
            # Verify the chain link
            if current_block.previous_hash != previous_block.hash:
                logger.error("Chain link is broken")
                return False
            
            # Verify state roots
            if current_block.state_root != self._calculate_state_root({}):  # Simplified
                logger.error("Invalid state root")
                return False
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the blockchain to a dictionary."""
        return {
            "chain": [block.to_dict() for block in self.chain],
            "pending_transactions": self.pending_transactions,
            "difficulty": self.difficulty,
            "shards": {
                shard_id: {
                    "validators": shard.validators,
                    "last_block": shard.last_block,
                    "state_root": shard.state_root
                }
                for shard_id, shard in self.shards.items()
            },
            "cross_chain_bridges": self.cross_chain_bridges
        }
    
    def save_to_file(self, filename: str) -> None:
        """Save the blockchain to a file."""
        with open(filename, 'w') as f:
            json.dump(self.to_dict(), f, indent=4)
        
        # Save contracts and consensus state
        self.contract_manager.save_contracts("contracts.json")
        self.consensus.save_state("consensus.json")
        
        logger.info(f"Blockchain saved to {filename}")
    
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
                block.shard_id = block_data.get("shard_id")
                block.cross_chain_refs = block_data.get("cross_chain_refs", [])
                block.state_root = block_data.get("state_root", "")
                block.receipt_root = block_data.get("receipt_root", "")
                block.zk_proof = bytes.fromhex(block_data.get("zk_proof", "")) if block_data.get("zk_proof") else None
                blockchain.chain.append(block)
            
            blockchain.pending_transactions = data["pending_transactions"]
            
            # Load shard information
            for shard_id, shard_data in data.get("shards", {}).items():
                blockchain.shards[int(shard_id)] = ShardInfo(
                    id=int(shard_id),
                    validators=shard_data["validators"],
                    transactions=[],
                    state_root=shard_data["state_root"],
                    last_block=shard_data["last_block"],
                    zk_rollup=ZKRollup()
                )
            
            # Load cross-chain bridges
            blockchain.cross_chain_bridges = data.get("cross_chain_bridges", {})
            
            # Load contracts if they exist
            if os.path.exists("contracts.json"):
                blockchain.contract_manager.load_contracts("contracts.json")
            
            # Load consensus state if it exists
            if os.path.exists("consensus.json"):
                blockchain.consensus.load_state("consensus.json")
            
            logger.info(f"Blockchain loaded from {filename}")
            return blockchain
            
        except FileNotFoundError:
            logger.warning(f"No existing blockchain found at {filename}")
            return blockchain
        except json.JSONDecodeError:
            logger.error(f"Error decoding blockchain file {filename}")
            return blockchain
        except Exception as e:
            logger.error(f"Error loading blockchain: {str(e)}")
            return blockchain


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
