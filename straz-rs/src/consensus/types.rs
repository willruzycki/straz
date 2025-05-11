use crate::Result;
use crate::crypto::KeyPair;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::crypto::{Address, PublicKey, Signature};
use crate::blockchain::Block;

// Core consensus parameters
pub const BLOCK_TIME: u64 = 3; // seconds
pub const EPOCH_LENGTH: u64 = 2000; // blocks
pub const MIN_STAKE: u128 = 1000; // STZ tokens
pub const MAX_VALIDATORS: usize = 100;
pub const REWARD_RATE: f64 = 0.10; // 10% APY
pub const SLASH_DOUBLE_SIGN: f64 = 0.05; // 5% of stake
pub const SLASH_DOWNTIME: f64 = 0.01; // 1% of stake
pub const UNBONDING_PERIOD: u64 = 3; // epochs
pub const SLASH_DOUBLE_SIGN_PERCENTAGE: u8 = 5;
pub const SLASH_DOWNTIME_PERCENTAGE: u8 = 1;
pub const UNBONDING_PERIOD_EPOCHS: u64 = 3;
pub const MAX_ROUNDS_PER_BLOCK: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub address: String,
    pub pubkey: Vec<u8>,
    pub stake: u128,
    pub bonded_at: u64,
    pub last_active: u64,
    pub missed_votes: u64,
    pub total_votes: u64,
    pub is_active: bool,
    pub first_seen_epoch: u64,
    pub last_seen_epoch: u64,
    pub missed_votes_in_epoch: u64,
    pub proposed_blocks_in_epoch: u64,
    pub unbonding_epoch: Option<u64>,
    pub unbonding_amount: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeTx {
    pub validator_pubkey: Vec<u8>,
    pub amount: u128,
    pub delegatee: Option<String>,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnstakeTx {
    pub validator_address: Address,
    pub amount: u128,
    pub nonce: u64,
    pub signature: Signature,
    pub target_epoch_for_withdrawal: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMsg {
    Proposal {
        epoch: u64,
        round: u64,
        block_hash: Vec<u8>,
        signature: Vec<u8>,
    },
    Vote {
        epoch: u64,
        round: u64,
        block_hash: Vec<u8>,
        signature: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashTx {
    pub offender: String,
    pub evidence: Vec<ConsensusMsg>,
    pub reporter: String,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: HashMap<String, Validator>,
    pub total_stake: u128,
    pub active_validators: Vec<String>,
    pub current_epoch: u64,
    pub current_round: u64,
    pub total_stake_active: u128,
}

impl ValidatorSet {
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            total_stake: 0,
            active_validators: Vec::new(),
            current_epoch: 0,
            current_round: 0,
            total_stake_active: 0,
        }
    }
    
    pub fn register_validator(&mut self, validator_address: Address, pubkey: PublicKey, amount: u128) -> Result<(), String> {
        if amount < MIN_STAKE {
            return Err(format!("Stake amount {} is less than minimum stake {}", amount, MIN_STAKE));
        }
        if self.validators.contains_key(&validator_address) {
            let validator = self.validators.get_mut(&validator_address).unwrap();
            validator.stake += amount;
            validator.unbonding_epoch = None;
            validator.unbonding_amount = 0;
        } else {
            self.validators.insert(validator_address.clone(), Validator::new(pubkey, amount, self.current_epoch));
        }
        Ok(())
    }
    
    pub fn unstake(&mut self, tx: UnstakeTx) -> Result<()> {
        let validator = self.validators.get_mut(&tx.validator_address)
            .ok_or_else(|| crate::StrazError::Consensus("Validator not found".into()))?;
            
        if tx.amount > validator.stake {
            return Err(crate::StrazError::Consensus("Insufficient stake".into()));
        }
        
        validator.stake -= tx.amount;
        self.total_stake -= tx.amount;
        
        if validator.stake < MIN_STAKE {
            validator.is_active = false;
            self.update_active_validators();
        }
        
        Ok(())
    }
    
    pub fn update_active_validators(&mut self) {
        let mut eligible_validators: Vec<_> = self.validators.values()
            .filter(|v| v.stake >= MIN_STAKE && v.unbonding_epoch.is_none())
            .collect();
            
        eligible_validators.sort_by(|a, b| b.stake.cmp(&a.stake));
        
        self.active_validators = eligible_validators.into_iter()
            .take(MAX_VALIDATORS)
            .map(|v| v.address.clone())
            .collect();
            
        self.total_stake_active = self.active_validators.iter()
            .filter_map(|addr| self.validators.get(addr))
            .map(|v| v.stake)
            .sum();
        
        let active_set: std::collections::HashSet<_> = self.active_validators.iter().cloned().collect();
        for validator in self.validators.values_mut() {
            validator.is_active = active_set.contains(&validator.address);
            if validator.is_active {
                validator.last_seen_epoch = self.current_epoch;
            }
        }
    }
    
    pub fn record_vote(&mut self, validator: &str, block_hash: &[u8]) -> Result<()> {
        let validator = self.validators.get_mut(validator)
            .ok_or_else(|| crate::StrazError::Consensus("Validator not found".into()))?;
            
        validator.last_active = self.current_epoch;
        validator.total_votes += 1;
        
        Ok(())
    }
    
    pub fn record_missed_vote(&mut self, validator: &str) -> Result<()> {
        let validator = self.validators.get_mut(validator)
            .ok_or_else(|| crate::StrazError::Consensus("Validator not found".into()))?;
            
        validator.missed_votes += 1;
        
        if validator.total_votes > 0 {
            let miss_rate = validator.missed_votes as f64 / validator.total_votes as f64;
            if miss_rate > 0.5 {
                self.slash_validator(validator, SLASH_DOWNTIME_PERCENTAGE as f64)?;
            }
        }
        
        Ok(())
    }
    
    pub fn slash_validator(&mut self, validator: &mut Validator, slash_rate: f64) -> Result<()> {
        let slash_amount = (validator.stake as f64 * slash_rate) as u128;
        validator.stake -= slash_amount;
        self.total_stake -= slash_amount;
        
        if validator.stake < MIN_STAKE {
            validator.is_active = false;
            self.update_active_validators();
        }
        
        Ok(())
    }
    
    pub fn end_epoch(&mut self) {
        self.current_epoch += 1;
        self.current_round = 0;
        
        for validator in self.validators.values_mut() {
            validator.missed_votes = 0;
            validator.total_votes = 0;
        }
        
        self.update_active_validators();
    }

    pub fn initiate_unstake(&mut self, validator_address: &Address, amount: u128) -> Result<u64, String> {
        let validator = self.validators.get_mut(validator_address)
            .ok_or_else(|| "Validator not found".to_string())?;

        if amount > validator.stake {
            return Err("Unstake amount exceeds bonded stake".to_string());
        }
        if validator.unbonding_epoch.is_some() {
            return Err("Validator is already unbonding".to_string());
        }

        validator.stake -= amount;
        validator.unbonding_amount = amount;
        validator.unbonding_epoch = Some(self.current_epoch);
        let withdrawal_epoch = self.current_epoch + UNBONDING_PERIOD_EPOCHS;
        Ok(withdrawal_epoch)
    }

    pub fn process_stake_withdrawal(&mut self, validator_address: &Address, current_epoch: u64) -> Result<u128, String> {
        let validator = self.validators.get_mut(validator_address)
            .ok_or_else(|| "Validator not found".to_string())?;

        if let Some(unbonding_start_epoch) = validator.unbonding_epoch {
            if current_epoch >= unbonding_start_epoch + UNBONDING_PERIOD_EPOCHS {
                let withdrawn_amount = validator.unbonding_amount;
                validator.unbonding_amount = 0;
                validator.unbonding_epoch = None;
                if validator.stake == 0 && !validator.is_active {
                    // To be fully removed, they should not be in active_validators either.
                    // This check should be more robust based on when active_validators is updated.
                    // For now, just reset unbonding fields. The update_active_validators will handle eviction if stake is too low.
                }
                Ok(withdrawn_amount)
            } else {
                Err("Unbonding period not yet complete".to_string())
            }
        } else {
            Err("Validator is not unbonding".to_string())
        }
    }

    pub fn record_block_proposed(&mut self, proposer_address: &Address) {
        if let Some(validator) = self.validators.get_mut(proposer_address) {
            validator.proposed_blocks_in_epoch += 1;
        }
    }

    pub fn record_vote_missed(&mut self, voter_address: &Address) {
        if let Some(validator) = self.validators.get_mut(voter_address) {
            validator.missed_votes_in_epoch += 1;
        }
    }
    
    pub fn get_active_validators_details(&self) -> Vec<&Validator> {
        self.active_validators.iter()
            .filter_map(|addr| self.validators.get(addr))
            .collect()
    }
    
    pub fn get_validator_stats(&self, validator_address: &Address) -> Option<(u64, u64)> {
        self.validators.get(validator_address).map(|v| (v.proposed_blocks_in_epoch, v.missed_votes_in_epoch))
    }

    pub fn reset_epoch_stats(&mut self) {
        for validator in self.validators.values_mut() {
            validator.missed_votes_in_epoch = 0;
            validator.proposed_blocks_in_epoch = 0;
        }
    }
    
    pub fn end_epoch_transition(&mut self) -> Vec<(Address, u128)> { // Returns (offender, slashed_amount)
        self.current_epoch += 1;
        self.current_round = 0;
        
        let mut slashed_validators: Vec<(Address, u128)> = Vec::new();
        let total_expected_votes_per_validator_in_epoch = EPOCH_LENGTH; // Simplified: assuming 1 vote opportunity per block

        // Apply liveness fault slashing before resetting stats
        // Need to collect addresses first to avoid borrowing issues while mutating
        let validator_addresses: Vec<Address> = self.validators.keys().cloned().collect();
        for addr in validator_addresses {
            if let Some(validator) = self.validators.get_mut(&addr) {
                if validator.is_active { // Only slash active validators for liveness
                    // A more robust way to count expected votes might be needed if rounds vary a lot.
                    // For now, assume EPOCH_LENGTH blocks means EPOCH_LENGTH opportunities to vote.
                    if validator.missed_votes_in_epoch * 2 > total_expected_votes_per_validator_in_epoch {
                        println!(
                            "Liveness fault for {:?}: missed {} / {} votes in epoch {}. Slashing by {}%.", 
                            addr, 
                            validator.missed_votes_in_epoch, 
                            total_expected_votes_per_validator_in_epoch,
                            self.current_epoch -1, // Slashing for the concluded epoch
                            SLASH_DOWNTIME_PERCENTAGE
                        );
                        match self.slash_validator(&addr, SLASH_DOWNTIME_PERCENTAGE) {
                            Ok(slashed_amount) => slashed_validators.push((addr.clone(), slashed_amount)),
                            Err(e) => eprintln!("Error slashing validator {:?} for liveness: {}", addr, e),
                        }
                    }
                }
            }
        }

        self.reset_epoch_stats();
        self.update_active_validators(); // Recalculate active set for the new epoch
        
        // Process stake withdrawals that are due
        let mut withdrawal_candidates: Vec<Address> = Vec::new();
        // Need to clone to avoid borrowing issues when calling process_stake_withdrawal
        let addresses_to_check: Vec<Address> = self.validators.keys().cloned().collect();

        for addr in addresses_to_check {
            if let Some(validator) = self.validators.get(&addr) { // Read-only check first
                if let Some(unbonding_start_epoch) = validator.unbonding_epoch {
                    if self.current_epoch >= unbonding_start_epoch + UNBONDING_PERIOD_EPOCHS {
                        withdrawal_candidates.push(addr.clone());
                    }
                }
            }
        }
        for addr in withdrawal_candidates {
            if let Err(e) = self.process_stake_withdrawal(&addr, self.current_epoch) {
                 eprintln!("Error processing withdrawal for {:?}: {}", addr, e);
            }
        }
        slashed_validators
    }
} 