mod block;
mod transaction;
mod state;

pub use block::Block;
pub use transaction::Transaction;
pub use state::State;

use crate::Result;
use crate::crypto::{KeyPair, ZKRollup};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blockchain {
    chain: Vec<Block>,
    pending_transactions: Vec<Transaction>,
    difficulty: u32,
    mining_reward: u64,
    transaction_pool: HashMap<String, Transaction>,
    state: Arc<RwLock<State>>,
    zk_rollup: ZKRollup,
}

impl Blockchain {
    pub fn new(difficulty: u32) -> Self {
        let mut chain = Vec::new();
        let genesis_block = Block::genesis();
        chain.push(genesis_block);
        
        Self {
            chain,
            pending_transactions: Vec::new(),
            difficulty,
            mining_reward: 50, // 50 STRZ
            transaction_pool: HashMap::new(),
            state: Arc::new(RwLock::new(State::new())),
            zk_rollup: ZKRollup::new(),
        }
    }
    
    pub async fn create_transaction(
        &mut self,
        sender: String,
        recipient: String,
        amount: u64,
        fee: u64,
    ) -> Result<()> {
        let transaction = Transaction::new(sender, recipient, amount, fee);
        
        // Validate transaction
        if !self.validate_transaction(&transaction).await? {
            return Err(crate::StrazError::Blockchain("Invalid transaction".into()));
        }
        
        // Add to transaction pool
        let tx_hash = transaction.hash();
        self.transaction_pool.insert(tx_hash.clone(), transaction);
        
        // Add to ZK-rollup if it's a private transaction
        if transaction.is_private() {
            self.zk_rollup.add_transaction(transaction.into())?;
        }
        
        Ok(())
    }
    
    pub async fn mine_pending_transactions(&mut self, miner_address: String) -> Result<()> {
        // Get transactions from pool
        let transactions: Vec<Transaction> = self.transaction_pool.values().cloned().collect();
        
        // Create mining reward transaction
        let reward_tx = Transaction::new(
            "COINBASE".to_string(),
            miner_address,
            self.mining_reward,
            0,
        );
        
        // Create new block
        let mut block = Block::new(
            self.chain.len() as u64,
            transactions,
            self.chain.last().unwrap().hash.clone(),
        );
        
        // Mine the block
        block.mine(self.difficulty)?;
        
        // Add block to chain
        self.chain.push(block);
        
        // Update state
        let mut state = self.state.write().await;
        state.apply_block(&self.chain.last().unwrap())?;
        
        // Clear transaction pool
        self.transaction_pool.clear();
        
        Ok(())
    }
    
    async fn validate_transaction(&self, transaction: &Transaction) -> Result<bool> {
        // Check if sender has sufficient balance
        let state = self.state.read().await;
        let balance = state.get_balance(&transaction.sender)?;
        
        if balance < transaction.amount + transaction.fee {
            return Ok(false);
        }
        
        // Verify transaction signature
        if !transaction.verify_signature()? {
            return Ok(false);
        }
        
        // Check for double spending
        if self.transaction_pool.contains_key(&transaction.hash()) {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    pub fn get_balance(&self, address: &str) -> Result<u64> {
        let state = self.state.blocking_read();
        state.get_balance(address)
    }
    
    pub fn is_chain_valid(&self) -> Result<bool> {
        for i in 1..self.chain.len() {
            let current = &self.chain[i];
            let previous = &self.chain[i - 1];
            
            // Verify block hash
            if current.hash != current.calculate_hash()? {
                return Ok(false);
            }
            
            // Verify chain link
            if current.previous_hash != previous.hash {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
} 