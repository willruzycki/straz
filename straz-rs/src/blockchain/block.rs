use crate::Result;
use crate::blockchain::Transaction;
use crate::crypto::PublicKey;
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub hash: String,
    pub nonce: u64,
    pub difficulty: u32,
    pub merkle_root: String,
    pub proposer: PublicKey,
}

impl Block {
    pub fn new(index: u64, transactions: Vec<Transaction>, previous_hash: String, proposer: PublicKey) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let merkle_root = Self::calculate_merkle_root(&transactions);
        
        let mut block = Self {
            index,
            timestamp,
            transactions,
            previous_hash,
            hash: String::new(),
            nonce: 0,
            difficulty: 0,
            merkle_root,
            proposer,
        };
        
        block.hash = block.calculate_hash().unwrap();
        block
    }
    
    pub fn genesis() -> Self {
        let transactions = vec![Transaction::new(
            "COINBASE".to_string(),
            "GENESIS".to_string(),
            0,
            0,
        )];
        
        let genesis_proposer_pk = PublicKey {
            key: vec![0; 32],
            algorithm: "dummy_genesis".to_string(),
        };

        let mut block = Self::new(0, transactions, "0".to_string(), genesis_proposer_pk);
        block
    }
    
    pub fn mine(&mut self, difficulty: u32) -> Result<()> {
        self.difficulty = difficulty;
        let target = "0".repeat(difficulty as usize);
        
        while &self.hash[..difficulty as usize] != target {
            self.nonce += 1;
            self.hash = self.calculate_hash()?;
        }
        
        Ok(())
    }
    
    pub fn calculate_hash(&self) -> Result<String> {
        let mut hasher = Sha3_256::new();
        
        hasher.update(self.index.to_le_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.previous_hash.as_bytes());
        hasher.update(self.nonce.to_le_bytes());
        hasher.update(self.merkle_root.as_bytes());
        hasher.update(&self.proposer.key);
        
        Ok(hex::encode(hasher.finalize()))
    }
    
    fn calculate_merkle_root(transactions: &[Transaction]) -> String {
        if transactions.is_empty() {
            return "0".to_string();
        }
        
        let mut hashes: Vec<String> = transactions
            .iter()
            .map(|tx| tx.hash())
            .collect();
        
        while hashes.len() > 1 {
            let mut new_hashes = Vec::new();
            
            for i in (0..hashes.len()).step_by(2) {
                let left = &hashes[i];
                let right = if i + 1 < hashes.len() {
                    &hashes[i + 1]
                } else {
                    left
                };
                
                let mut hasher = Sha3_256::new();
                hasher.update(left.as_bytes());
                hasher.update(right.as_bytes());
                new_hashes.push(hex::encode(hasher.finalize()));
            }
            
            hashes = new_hashes;
        }
        
        hashes[0].clone()
    }
} 