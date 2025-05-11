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

    /// Validate and commit a finalized block to chain state.
    /// This is a placeholder implementation.
    pub fn apply_block(&mut self, block: &Block) -> Result<Receipt, BlockchainError> {
        println!("Applying block: {} (Index: {})", hex::encode(&block.hash), block.index);

        // 1. Validate header & transactions
        //    - Check previous_hash matches current chain tip (not done here, assumes consensus provides valid sequence)
        //    - Validate block signature (if any, depends on block structure)
        //    - Validate Merkle root against transactions
        //    - For each transaction: check signature, nonce, balance for sender
        if block.hash.is_empty() { // Simplified validation
            return Err(BlockchainError::InvalidBlock("Block hash is empty".to_string()));
        }

        // 2. Execute each tx (StakeTx, UnstakeTx, contract calls) and update balances
        //    This part is highly complex and involves a VM for contract calls,
        //    and specific logic for native transactions like staking.
        //    For now, we'll assume all transactions are valid and produce some dummy events.
        let mut total_gas_used = 0;
        let mut collected_events: Vec<Event> = Vec::new();

        // Placeholder: Iterate through transactions if Block struct has them
        // for tx in &block.transactions {
        //     match self.execute_transaction(tx) {
        //         Ok(tx_receipt) => {
        //             total_gas_used += tx_receipt.gas_used;
        //             collected_events.extend(tx_receipt.events);
        //         }
        //         Err(e) => return Err(BlockchainError::InvalidTransaction(format!("Tx failed: {}", e))),
        //     }
        // }

        // 3. Append block to storage (DB or in‐memory)
        //    - Store the block itself
        //    - Update account states, contract storage
        //    - Update chain metadata (e.g., current block height, chain tip hash)
        //    Example: self.db_connection.insert(&block.hash, bincode::serialize(block)?)?;

        // 4. Compute new state_root, total gas used, and collect events
        //    The state_root would be derived from the updated state (e.g., Merkle root of account states).
        //    For this stub, we use the block's own state_root if it has one, or a dummy value.
        let new_state_root = block.merkle_root.clone(); // Assuming Block has merkle_root as state_root placeholder
        
        // self.current_state_root = new_state_root.clone(); // Update chain's state root

        Ok(Receipt {
            state_root: new_state_root,
            gas_used: total_gas_used, // Placeholder
            events: collected_events, // Placeholder
            success: true, // Assume success for stub
        })
    }

    // Placeholder for a function that might exist on the Block struct
    // For the stub `apply_block` to compile if `block.state_root()` was intended as a method.
    // If Block has a field `state_root` or `merkle_root`, this is not needed.
    // fn get_block_state_root(block: &Block) -> Hash {
    //    block.merkle_root.clone() // Assuming merkle_root acts as state_root
    // }
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
    blockchain_instance.apply_block(block)
} 