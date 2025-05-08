use crate::Result;
use crate::blockchain::Block;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct State {
    balances: HashMap<String, u64>,
    nonces: HashMap<String, u64>,
}

impl State {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
            nonces: HashMap::new(),
        }
    }
    
    pub fn get_balance(&self, address: &str) -> Result<u64> {
        Ok(self.balances.get(address).copied().unwrap_or(0))
    }
    
    pub fn apply_block(&mut self, block: &Block) -> Result<()> {
        for transaction in &block.transactions {
            // Skip coinbase transactions
            if transaction.sender == "COINBASE" {
                let balance = self.balances.entry(transaction.recipient.clone())
                    .or_insert(0);
                *balance += transaction.amount;
                continue;
            }
            
            // Update sender balance
            let sender_balance = self.balances.entry(transaction.sender.clone())
                .or_insert(0);
            if *sender_balance < transaction.amount + transaction.fee {
                return Err(crate::StrazError::Blockchain("Insufficient balance".into()));
            }
            *sender_balance -= transaction.amount + transaction.fee;
            
            // Update recipient balance
            let recipient_balance = self.balances.entry(transaction.recipient.clone())
                .or_insert(0);
            *recipient_balance += transaction.amount;
            
            // Update nonce
            let nonce = self.nonces.entry(transaction.sender.clone())
                .or_insert(0);
            *nonce += 1;
        }
        
        Ok(())
    }
    
    pub fn get_nonce(&self, address: &str) -> u64 {
        self.nonces.get(address).copied().unwrap_or(0)
    }
    
    pub fn validate_transaction(&self, transaction: &crate::blockchain::Transaction) -> bool {
        // Check if sender has sufficient balance
        let balance = self.get_balance(&transaction.sender).unwrap_or(0);
        if balance < transaction.amount + transaction.fee {
            return false;
        }
        
        // Check if nonce is valid
        let nonce = self.get_nonce(&transaction.sender);
        if nonce != 0 { // Skip nonce check for first transaction
            return false;
        }
        
        true
    }
} 