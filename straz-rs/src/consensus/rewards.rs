use crate::Result;
use crate::crypto::KeyPair;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

// Reward parameters
pub const BASE_REWARD_RATE: f64 = 0.10; // 10% APY
pub const PROPOSER_BONUS: f64 = 0.05; // 5% bonus for block proposers
pub const VOTER_REWARD: f64 = 0.02; // 2% for voting
pub const REPORTING_BOUNTY: f64 = 0.005; // 0.5% of slashed stake

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorReward {
    pub validator_address: String,
    pub epoch: u64,
    pub base_reward: u128,
    pub proposer_bonus: u128,
    pub voter_reward: u128,
    pub total_reward: u128,
    pub blocks_proposed: u64,
    pub votes_cast: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashBounty {
    pub reporter_address: String,
    pub offender_address: String,
    pub epoch: u64,
    pub slashed_amount: u128,
    pub bounty_amount: u128,
}

pub struct RewardManager {
    rewards: HashMap<(String, u64), ValidatorReward>, // (validator, epoch) -> reward
    bounties: HashMap<(String, u64), SlashBounty>, // (reporter, epoch) -> bounty
    total_rewards: u128,
    total_bounties: u128,
}

impl RewardManager {
    pub fn new() -> Self {
        Self {
            rewards: HashMap::new(),
            bounties: HashMap::new(),
            total_rewards: 0,
            total_bounties: 0,
        }
    }
    
    pub fn calculate_rewards(
        &mut self,
        epoch: u64,
        validators: &[(String, u128, u64, u64)], // (address, stake, blocks_proposed, votes_cast)
        total_stake: u128,
    ) -> Result<()> {
        for (address, stake, blocks_proposed, votes_cast) in validators {
            // Calculate base reward (proportional to stake)
            let base_reward = (stake as f64 * BASE_REWARD_RATE / 365.0) as u128;
            
            // Calculate proposer bonus
            let proposer_bonus = if *blocks_proposed > 0 {
                (base_reward as f64 * PROPOSER_BONUS * *blocks_proposed as f64) as u128
            } else {
                0
            };
            
            // Calculate voter reward
            let voter_reward = if *votes_cast > 0 {
                (base_reward as f64 * VOTER_REWARD * *votes_cast as f64) as u128
            } else {
                0
            };
            
            let total_reward = base_reward + proposer_bonus + voter_reward;
            
            let reward = ValidatorReward {
                validator_address: address.clone(),
                epoch: *epoch,
                base_reward,
                proposer_bonus,
                voter_reward,
                total_reward,
                blocks_proposed: *blocks_proposed,
                votes_cast: *votes_cast,
            };
            
            self.rewards.insert((address.clone(), *epoch), reward);
            self.total_rewards += total_reward;
        }
        
        Ok(())
    }
    
    pub fn process_slash_bounty(
        &mut self,
        reporter: String,
        offender: String,
        epoch: u64,
        slashed_amount: u128,
    ) -> Result<()> {
        let bounty_amount = (slashed_amount as f64 * REPORTING_BOUNTY) as u128;
        
        let bounty = SlashBounty {
            reporter_address: reporter.clone(),
            offender_address: offender,
            epoch,
            slashed_amount,
            bounty_amount,
        };
        
        self.bounties.insert((reporter, epoch), bounty);
        self.total_bounties += bounty_amount;
        
        Ok(())
    }
    
    pub fn get_validator_reward(&self, validator: &str, epoch: u64) -> Option<&ValidatorReward> {
        self.rewards.get(&(validator.to_string(), epoch))
    }
    
    pub fn get_reporter_bounty(&self, reporter: &str, epoch: u64) -> Option<&SlashBounty> {
        self.bounties.get(&(reporter.to_string(), epoch))
    }
    
    pub fn get_epoch_rewards(&self, epoch: u64) -> Vec<&ValidatorReward> {
        self.rewards.values()
            .filter(|r| r.epoch == epoch)
            .collect()
    }
    
    pub fn get_epoch_bounties(&self, epoch: u64) -> Vec<&SlashBounty> {
        self.bounties.values()
            .filter(|b| b.epoch == epoch)
            .collect()
    }
    
    pub fn get_total_rewards(&self) -> u128 {
        self.total_rewards
    }
    
    pub fn get_total_bounties(&self) -> u128 {
        self.total_bounties
    }

    pub fn pay_out(&mut self, receipt: &crate::blockchain::types::Receipt) {
        // TODO: Distribute rewards based on receipt.events or validator stats from the epoch.
        //       This current receipt is for a single block, epoch rewards are usually handled
        //       at epoch boundaries. This function might be for immediate per-block payouts if any,
        //       or it could accumulate data for epoch-end payout.

        // For now, as a stub, let's imagine updating some internal balances.
        // This `balances` map would need to be a field in RewardManager.
        // HashMap<Address, u128> called `balances`
        // self.balances = HashMap::new(); // Example: if balances is a field

        log::info!("RewardManager::pay_out called for block producing receipt: {:?}", receipt);
        log::warn!("RewardManager::pay_out is a STUB and does not yet distribute actual rewards.");

        // Example of interacting with receipt events if they indicated rewards:
        for event in &receipt.events {
            if event.event_type == "ValidatorRewardPaid" {
                // let recipient = event.attributes.iter().find(|(k,_)| k == "recipient").map(|(_,v)| v);
                // let amount = event.attributes.iter().find(|(k,_)| k == "amount").map(|(_,v)| v.parse::<u128>().ok());
                // if let (Some(addr), Some(Some(value))) = (recipient, amount) {
                //     let bal = self.balances.entry(addr.clone()).or_insert(0);
                //     *bal += value;
                //     log::info!("Stub: Credited {} with {} from event", addr, value);
                // }
            }
        }
    }
}
// To make the HashMap example work, `balances` would need to be added to `RewardManager` struct:
// pub struct RewardManager {
//    rewards: HashMap<(String, u64), ValidatorReward>,
//    bounties: HashMap<(String, u64), SlashBounty>,
//    total_rewards: u128,
//    total_bounties: u128,
//    balances: HashMap<Address, u128>, // <-- New field
// }
// And initialized in new():
// balances: HashMap::new(), 