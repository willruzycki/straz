#!/usr/bin/env python3

from typing import List, Dict, Any, Set, Optional
import asyncio
import time
from dataclasses import dataclass
import hashlib
import json
import logging
from enum import Enum

logger = logging.getLogger(__name__)

class ValidatorStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SLASHED = "slashed"
    PENDING = "pending"

@dataclass
class Validator:
    address: str
    stake: float
    last_vote: float
    status: ValidatorStatus
    performance_score: float
    total_rewards: float
    total_slashes: float
    last_rotation: float
    shard_id: Optional[int]

class Consensus:
    def __init__(self, difficulty: int = 4):
        self.difficulty = difficulty
        self.validators: Dict[str, Validator] = {}
        self.min_stake = 1000  # Minimum stake to become a validator
        self.epoch_length = 100  # Number of blocks per epoch
        self.current_epoch = 0
        self.leader_schedule: Dict[int, str] = {}  # Block height -> validator address
        self.votes: Dict[str, Set[str]] = {}  # Block hash -> set of validator addresses
        self.validator_rewards: Dict[str, float] = {}  # Validator address -> accumulated rewards
        self.slashing_conditions: Dict[str, int] = {}  # Validator address -> number of violations
        self.reward_rate = 0.05  # 5% annual reward rate
        self.slashing_threshold = 3  # Number of violations before slashing
        self.finality_threshold = 0.67  # 67% of validators must vote for finality
        self.rotation_interval = 86400  # 24 hours in seconds
        self.performance_threshold = 0.8  # Minimum performance score to remain active
        self.max_validators_per_shard = 100
        self.validator_rotation_queue: List[str] = []

    def register_validator(self, address: str, stake: float, shard_id: Optional[int] = None) -> bool:
        """Register a new validator"""
        if stake >= self.min_stake:
            # Check if shard is full
            if shard_id is not None:
                shard_validators = [v for v in self.validators.values() if v.shard_id == shard_id]
                if len(shard_validators) >= self.max_validators_per_shard:
                    return False
            
            self.validators[address] = Validator(
                address=address,
                stake=stake,
                last_vote=time.time(),
                status=ValidatorStatus.PENDING,
                performance_score=1.0,
                total_rewards=0.0,
                total_slashes=0.0,
                last_rotation=time.time(),
                shard_id=shard_id
            )
            return True
        return False

    def update_validator_stake(self, address: str, new_stake: float) -> bool:
        """Update a validator's stake"""
        if address in self.validators:
            validator = self.validators[address]
            validator.stake = new_stake
            validator.status = ValidatorStatus.ACTIVE if new_stake >= self.min_stake else ValidatorStatus.INACTIVE
            return True
        return False

    def rotate_validators(self) -> None:
        """Rotate validators based on performance and stake"""
        current_time = time.time()
        
        # Update performance scores
        for validator in self.validators.values():
            if validator.status == ValidatorStatus.ACTIVE:
                # Calculate performance based on voting history and stake
                votes_count = sum(1 for votes in self.votes.values() if validator.address in votes)
                total_blocks = len(self.votes)
                voting_performance = votes_count / total_blocks if total_blocks > 0 else 0
                
                # Update performance score with exponential moving average
                validator.performance_score = 0.7 * validator.performance_score + 0.3 * voting_performance
                
                # Check if validator should be rotated
                if (current_time - validator.last_rotation > self.rotation_interval and
                    validator.performance_score < self.performance_threshold):
                    validator.status = ValidatorStatus.INACTIVE
                    self.validator_rotation_queue.append(validator.address)
        
        # Activate new validators from the queue
        while self.validator_rotation_queue and len([v for v in self.validators.values() if v.status == ValidatorStatus.ACTIVE]) < self.max_validators_per_shard:
            new_validator = self.validator_rotation_queue.pop(0)
            self.validators[new_validator].status = ValidatorStatus.ACTIVE
            self.validators[new_validator].last_rotation = current_time

    def generate_leader_schedule(self, epoch: int) -> Dict[int, str]:
        """Generate the leader schedule for an epoch"""
        active_validators = [
            v for v in self.validators.values() 
            if v.status == ValidatorStatus.ACTIVE
        ]
        
        if not active_validators:
            return {}
        
        # Sort validators by stake and performance
        sorted_validators = sorted(
            active_validators,
            key=lambda v: (v.stake * v.performance_score),
            reverse=True
        )
        
        # Generate schedule based on stake weight and performance
        schedule = {}
        total_weight = sum(v.stake * v.performance_score for v in sorted_validators)
        
        for i in range(self.epoch_length):
            block_height = epoch * self.epoch_length + i
            # Weighted random selection based on stake and performance
            r = hash(f"{block_height}{epoch}") % total_weight
            current_sum = 0
            for validator in sorted_validators:
                current_sum += validator.stake * validator.performance_score
                if r < current_sum:
                    schedule[block_height] = validator.address
                    break
        
        return schedule

    def calculate_validator_reward(self, validator_address: str, block_reward: float) -> float:
        """Calculate validator reward based on stake, performance, and participation"""
        if validator_address not in self.validators:
            return 0.0
        
        validator = self.validators[validator_address]
        if validator.status != ValidatorStatus.ACTIVE:
            return 0.0
        
        # Calculate reward based on stake weight, performance, and participation
        total_stake = sum(v.stake for v in self.validators.values() if v.status == ValidatorStatus.ACTIVE)
        stake_weight = validator.stake / total_stake if total_stake > 0 else 0
        
        # Apply performance multiplier
        performance_multiplier = validator.performance_score
        
        # Apply slashing penalty if applicable
        violations = self.slashing_conditions.get(validator_address, 0)
        penalty = 1.0 - (violations * 0.1)  # 10% penalty per violation
        
        # Calculate final reward
        reward = block_reward * stake_weight * performance_multiplier * penalty
        
        # Update validator's total rewards
        validator.total_rewards += reward
        
        return reward

    def process_slashing(self, validator_address: str, violation_type: str) -> None:
        """Process validator slashing for violations"""
        if validator_address not in self.slashing_conditions:
            self.slashing_conditions[validator_address] = 0
        
        self.slashing_conditions[validator_address] += 1
        validator = self.validators[validator_address]
        
        # Update validator's total slashes
        slash_amount = validator.stake * 0.5  # Slash 50% of stake
        validator.total_slashes += slash_amount
        
        # Check if validator should be slashed
        if self.slashing_conditions[validator_address] >= self.slashing_threshold:
            validator.status = ValidatorStatus.SLASHED
            validator.stake *= 0.5  # Slash 50% of stake
            logger.warning(f"Validator {validator_address} has been slashed")

    async def process_block(self, block: Dict[str, Any], validator_address: str) -> bool:
        """Process a block and collect validator votes"""
        block_hash = block["hash"]
        
        # Check if validator is active
        if validator_address not in self.validators or self.validators[validator_address].status != ValidatorStatus.ACTIVE:
            return False
        
        # Check if validator is the leader for this block
        block_height = block["index"]
        if self.leader_schedule.get(block_height) != validator_address:
            # Process slashing for invalid block proposal
            self.process_slashing(validator_address, "invalid_proposal")
            return False
        
        # Initialize votes for this block if not exists
        if block_hash not in self.votes:
            self.votes[block_hash] = set()
        
        # Add vote
        self.votes[block_hash].add(validator_address)
        
        # Update validator's last vote time
        self.validators[validator_address].last_vote = time.time()
        
        # Check if block has enough votes for finality
        active_validators_count = len([v for v in self.validators.values() if v.status == ValidatorStatus.ACTIVE])
        required_votes = int(active_validators_count * self.finality_threshold)
        
        if len(self.votes[block_hash]) >= required_votes:
            # Calculate and distribute rewards
            block_reward = 50  # Base block reward
            for voter in self.votes[block_hash]:
                reward = self.calculate_validator_reward(voter, block_reward)
                if voter not in self.validator_rewards:
                    self.validator_rewards[voter] = 0
                self.validator_rewards[voter] += reward
            
            # Rotate validators if needed
            self.rotate_validators()
            
            return True
        
        return False

    def get_validator_info(self, address: str) -> Dict[str, Any]:
        """Get information about a validator"""
        if address not in self.validators:
            return {"error": "Validator not found"}
        
        validator = self.validators[address]
        return {
            "address": validator.address,
            "stake": validator.stake,
            "status": validator.status.value,
            "performance_score": validator.performance_score,
            "total_rewards": validator.total_rewards,
            "total_slashes": validator.total_slashes,
            "last_vote": validator.last_vote,
            "last_rotation": validator.last_rotation,
            "shard_id": validator.shard_id
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert consensus state to dictionary"""
        return {
            "difficulty": self.difficulty,
            "validators": {
                addr: {
                    "stake": v.stake,
                    "last_vote": v.last_vote,
                    "status": v.status.value,
                    "performance_score": v.performance_score,
                    "total_rewards": v.total_rewards,
                    "total_slashes": v.total_slashes,
                    "last_rotation": v.last_rotation,
                    "shard_id": v.shard_id
                }
                for addr, v in self.validators.items()
            },
            "current_epoch": self.current_epoch,
            "leader_schedule": self.leader_schedule,
            "validator_rewards": self.validator_rewards,
            "slashing_conditions": self.slashing_conditions
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
            consensus.validator_rewards = data.get("validator_rewards", {})
            consensus.slashing_conditions = data.get("slashing_conditions", {})
            
            for addr, validator_data in data["validators"].items():
                consensus.validators[addr] = Validator(
                    address=addr,
                    stake=validator_data["stake"],
                    last_vote=validator_data["last_vote"],
                    status=ValidatorStatus(validator_data["status"]),
                    performance_score=validator_data.get("performance_score", 1.0),
                    total_rewards=validator_data.get("total_rewards", 0.0),
                    total_slashes=validator_data.get("total_slashes", 0.0),
                    last_rotation=validator_data.get("last_rotation", time.time()),
                    shard_id=validator_data.get("shard_id")
                )
            
            return consensus
        except FileNotFoundError:
            return cls()
        except Exception as e:
            logger.error(f"Error loading consensus state: {e}")
            return cls() 