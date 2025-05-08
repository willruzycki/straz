use crate::Result;
use crate::blockchain::{Block, Blockchain};
use crate::crypto::KeyPair;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub address: String,
    pub stake: u64,
    pub keypair: KeyPair,
    pub last_block_time: u64,
    pub total_blocks: u64,
    pub missed_blocks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consensus {
    validators: Arc<RwLock<HashMap<String, Validator>>>,
    min_stake: u64,
    block_time: u64,
    blockchain: Arc<RwLock<Blockchain>>,
}

impl Consensus {
    pub fn new(blockchain: Blockchain, min_stake: u64, block_time: u64) -> Self {
        Self {
            validators: Arc::new(RwLock::new(HashMap::new())),
            min_stake,
            block_time,
            blockchain: Arc::new(RwLock::new(blockchain)),
        }
    }
    
    pub async fn register_validator(&self, address: String, stake: u64, keypair: KeyPair) -> Result<()> {
        if stake < self.min_stake {
            return Err(crate::StrazError::Consensus("Insufficient stake".into()));
        }
        
        let mut validators = self.validators.write().await;
        if validators.contains_key(&address) {
            return Err(crate::StrazError::Consensus("Validator already registered".into()));
        }
        
        validators.insert(address.clone(), Validator {
            address,
            stake,
            keypair,
            last_block_time: 0,
            total_blocks: 0,
            missed_blocks: 0,
        });
        
        Ok(())
    }
    
    pub async fn select_validator(&self) -> Result<Option<Validator>> {
        let validators = self.validators.read().await;
        if validators.is_empty() {
            return Ok(None);
        }
        
        // Calculate total stake
        let total_stake: u64 = validators.values().map(|v| v.stake).sum();
        
        // Select validator based on stake and performance
        let mut best_validator = None;
        let mut best_score = 0.0;
        
        for validator in validators.values() {
            let performance = 1.0 - (validator.missed_blocks as f64 / validator.total_blocks as f64);
            let stake_ratio = validator.stake as f64 / total_stake as f64;
            let score = performance * stake_ratio;
            
            if score > best_score {
                best_score = score;
                best_validator = Some(validator.clone());
            }
        }
        
        Ok(best_validator)
    }
    
    pub async fn validate_block(&self, block: &Block, validator: &Validator) -> Result<bool> {
        // Check if validator is eligible
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        if current_time - validator.last_block_time < self.block_time {
            return Ok(false);
        }
        
        // Verify block hash
        if block.hash != block.calculate_hash()? {
            return Ok(false);
        }
        
        // Verify block signature
        if !validator.keypair.verify(&block.hash.as_bytes(), &block.signature)? {
            return Ok(false);
        }
        
        // Update validator stats
        let mut validators = self.validators.write().await;
        if let Some(v) = validators.get_mut(&validator.address) {
            v.last_block_time = current_time;
            v.total_blocks += 1;
        }
        
        Ok(true)
    }
    
    pub async fn process_block(&self, block: Block) -> Result<()> {
        // Validate block
        let validator = self.select_validator().await?;
        if let Some(validator) = validator {
            if !self.validate_block(&block, &validator).await? {
                // Update validator stats for missed block
                let mut validators = self.validators.write().await;
                if let Some(v) = validators.get_mut(&validator.address) {
                    v.missed_blocks += 1;
                }
                return Err(crate::StrazError::Consensus("Invalid block".into()));
            }
        }
        
        // Add block to blockchain
        let mut blockchain = self.blockchain.write().await;
        blockchain.chain.push(block);
        
        Ok(())
    }
    
    pub async fn get_validator_stats(&self, address: &str) -> Result<Option<Validator>> {
        let validators = self.validators.read().await;
        Ok(validators.get(address).cloned())
    }
    
    pub async fn get_total_stake(&self) -> Result<u64> {
        let validators = self.validators.read().await;
        Ok(validators.values().map(|v| v.stake).sum())
    }
} 