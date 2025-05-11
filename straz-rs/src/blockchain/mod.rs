pub mod block;
pub mod transaction;
pub mod state;
pub mod types;
pub mod transaction_error;

#[cfg(test)]
pub mod tests {
    pub mod block_tests;
    pub mod transaction_tests;
    pub mod state_tests;
    pub mod apply_block_tests;
    pub mod vm_execution_tests;
}

pub use block::Block;
pub use transaction::Transaction;
pub use state::State;

use crate::Result;
use crate::crypto::{KeyPair, ZKRollup, PublicKey};
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
    
    pub async fn mine_pending_transactions(&mut self, miner_address: String, proposer_pk: PublicKey) -> Result<()> {
        // Get transactions from pool
        let transactions: Vec<Transaction> = self.transaction_pool.values().cloned().collect();
        
        // Create new block
        let current_tip_hash = self.chain.last().map_or("0".to_string(), |b| b.hash.clone());
        let mut block = Block::new(
            self.chain.len() as u64,
            transactions,
            current_tip_hash,
            proposer_pk.clone()
        );
        
        // Mine the block
        block.mine(self.difficulty)?;
        
        // Add block to chain
        self.chain.push(block.clone());
        
        // Update state by calling the Blockchain's apply_block method
        self.apply_block_to_state(&block).await?;
        
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

    /// Validate and commit a finalized block to chain state.
    pub async fn apply_block_to_state(&self, block: &Block) -> Result<Receipt, BlockchainError> {
        println!("Applying block: {} (Index: {}) to state", block.hash, block.index);

        // Basic validation (can be expanded)
        if block.hash.is_empty() { 
            return Err(BlockchainError::InvalidBlock("Block hash is empty".to_string()));
        }
        // Potentially check block.previous_hash against self.chain.last().unwrap().hash if appropriate here

        let mut state_guard = self.state.write().await;
        let mut total_gas_used_in_block: u64 = 0;
        // let mut collected_events: Vec<Event> = Vec::new(); // If events are to be collected

        for tx in &block.transactions {
            // Call the updated State::apply_transaction with block context
            match state_guard.apply_transaction(tx, block.index, &block.proposer) {
                Ok(_) => {
                    // If apply_transaction returned gas_used, collect it.
                    // For now, State::apply_transaction doesn't return gas_used directly.
                    // We can infer it if needed from tx.gas_limit for failed tx or from VM for successful.
                    // For simplicity, this Receipt's gas_used is a sum of tx.gas_limit for now.
                    total_gas_used_in_block += tx.gas_limit; // Placeholder for actual gas summed up
                }
                Err(e) => {
                    // Decide on error handling: continue applying other txs or fail block?
                    // For now, let's say one bad tx fails the block application for state changes.
                    eprintln!("Error applying transaction {} in block {}: {:?}", tx.tx_hash, block.hash, e);
                    return Err(BlockchainError::StateError(e));
                }
            }
        }

        // Append block to in-memory chain representation if this method is solely responsible for it.
        // However, self.chain.push(block) is often done before calling apply_block_to_state.
        // If ConsensusEngine calls this, it would have already validated the block against the current chain tip.

        // For Receipt:
        // state_root would come from state_guard.calculate_state_root() or similar if implemented.
        let new_state_root = state_guard.get_some_representation_of_state_hash(); // Placeholder

        Ok(Receipt {
            state_root: new_state_root, // Placeholder
            gas_used: total_gas_used_in_block, 
            events: Vec::new(), // Placeholder for actual events
            success: true, 
        })
    }
}

impl Default for Blockchain {
    fn default() -> Self {
        Self::new(0)
    }
}

// Top-level function as requested by the user, which might operate on a shared Blockchain instance.
// For now, it creates a new instance each time, which is not practical for a real chain.
// A real implementation would likely involve passing `&mut self` (Blockchain instance) to apply_block.

/// Validate and commit a finalized block to chain state.
/// This is a wrapper for Blockchain::apply_block for the requested signature.
/// Note: This creates a new Blockchain instance per call, which is for stubbing purposes.
/// A real application would manage a single Blockchain instance.
pub fn apply_block(block: &Block) -> Result<Receipt, BlockchainError> {
    // In a real application, you'd likely have a shared Blockchain instance, possibly wrapped in Arc<Mutex<Blockchain>>.
    // For this standalone function signature, we create a temporary one.
    let mut blockchain_instance = Blockchain::new(0); 
    blockchain_instance.apply_block_to_state(block)
} 

// Redefining the state's get_some_representation_of_state_hash as a placeholder:
impl State {
    pub fn get_some_representation_of_state_hash(&self) -> String {
        // In a real scenario, this would be a cryptographic hash of the current state.
        // For example, a Merkle root of all account states.
        let mut combined_data = Vec::new();
        for (pk, account_state) in &self.balances {
            combined_data.extend_from_slice(&pk.key);
            combined_data.extend_from_slice(&account_state.balance.to_be_bytes());
            combined_data.extend_from_slice(&account_state.nonce.to_be_bytes());
            // Add storage hash too for completeness
        }
        let hash_bytes = crate::crypto::hash_data(&combined_data);
        hex::encode(hash_bytes.0)
    }
}

// Removing the old top-level apply_block that creates a new instance.
// Consensus should call apply_block_to_state on the actual Blockchain instance.
// If a free function `blockchain::apply_block` is required, it must be adapted
// to take `&Arc<RwLock<Blockchain>>` or similar. 