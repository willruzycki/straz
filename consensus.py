#!/usr/bin/env python3

from typing import List, Dict, Any, Set
import asyncio
import time
from dataclasses import dataclass
import hashlib
import json

@dataclass
class Validator:
    address: str
    stake: float
    last_vote: float
    is_active: bool

class Consensus:
    def __init__(self, difficulty: int = 4):
        self.difficulty = difficulty
        self.validators: Dict[str, Validator] = {}
        self.min_stake = 1000  # Minimum stake to become a validator
        self.epoch_length = 100  # Number of blocks per epoch
        self.current_epoch = 0
        self.leader_schedule: Dict[int, str] = {}  # Block height -> validator address
        self.votes: Dict[str, Set[str]] = {}  # Block hash -> set of validator addresses

    def register_validator(self, address: str, stake: float) -> bool:
        """Register a new validator"""
        if stake >= self.min_stake:
            self.validators[address] = Validator(
                address=address,
                stake=stake,
                last_vote=time.time(),
                is_active=True
            )
            return True
        return False

    def update_validator_stake(self, address: str, new_stake: float) -> bool:
        """Update a validator's stake"""
        if address in self.validators:
            self.validators[address].stake = new_stake
            self.validators[address].is_active = new_stake >= self.min_stake
            return True
        return False

    def generate_leader_schedule(self, epoch: int) -> Dict[int, str]:
        """Generate the leader schedule for an epoch"""
        active_validators = [
            v for v in self.validators.values() 
            if v.is_active
        ]
        
        if not active_validators:
            return {}
        
        # Sort validators by stake
        sorted_validators = sorted(
            active_validators,
            key=lambda v: v.stake,
            reverse=True
        )
        
        # Generate schedule based on stake weight
        schedule = {}
        total_stake = sum(v.stake for v in sorted_validators)
        
        for i in range(self.epoch_length):
            block_height = epoch * self.epoch_length + i
            # Weighted random selection based on stake
            r = hash(f"{block_height}{epoch}") % total_stake
            current_sum = 0
            for validator in sorted_validators:
                current_sum += validator.stake
                if r < current_sum:
                    schedule[block_height] = validator.address
                    break
        
        return schedule

    async def process_block(self, block: Dict[str, Any], validator_address: str) -> bool:
        """Process a block and collect validator votes"""
        block_hash = block["hash"]
        
        # Check if validator is active
        if validator_address not in self.validators or not self.validators[validator_address].is_active:
            return False
        
        # Check if validator is the leader for this block
        block_height = block["index"]
        if self.leader_schedule.get(block_height) != validator_address:
            return False
        
        # Initialize votes for this block if not exists
        if block_hash not in self.votes:
            self.votes[block_hash] = set()
        
        # Add vote
        self.votes[block_hash].add(validator_address)
        
        # Update validator's last vote time
        self.validators[validator_address].last_vote = time.time()
        
        # Check if block has enough votes (2/3 of active validators)
        active_validators_count = len([v for v in self.validators.values() if v.is_active])
        required_votes = (2 * active_validators_count) // 3
        
        return len(self.votes[block_hash]) >= required_votes

    def get_validator_info(self, address: str) -> Dict[str, Any]:
        """Get information about a validator"""
        if address not in self.validators:
            return {"error": "Validator not found"}
        
        validator = self.validators[address]
        return {
            "address": validator.address,
            "stake": validator.stake,
            "is_active": validator.is_active,
            "last_vote": validator.last_vote
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert consensus state to dictionary"""
        return {
            "difficulty": self.difficulty,
            "validators": {
                addr: {
                    "stake": v.stake,
                    "last_vote": v.last_vote,
                    "is_active": v.is_active
                }
                for addr, v in self.validators.items()
            },
            "current_epoch": self.current_epoch,
            "leader_schedule": self.leader_schedule
        }

    def save_state(self, filename: str):
        """Save consensus state to file"""
        with open(filename, 'w') as f:
            json.dump(self.to_dict(), f, indent=4)

    @classmethod
    def load_state(cls, filename: str) -> 'Consensus':
        """Load consensus state from file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            consensus = cls(difficulty=data["difficulty"])
            consensus.current_epoch = data["current_epoch"]
            consensus.leader_schedule = data["leader_schedule"]
            
            for addr, validator_data in data["validators"].items():
                consensus.validators[addr] = Validator(
                    address=addr,
                    stake=validator_data["stake"],
                    last_vote=validator_data["last_vote"],
                    is_active=validator_data["is_active"]
                )
            
            return consensus
        except FileNotFoundError:
            return cls() 