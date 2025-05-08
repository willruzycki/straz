use crate::Result;
use crate::crypto::KeyPair;
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub fee: u64,
    pub timestamp: u64,
    pub signature: Option<Vec<u8>>,
    pub is_private: bool,
}

impl Transaction {
    pub fn new(sender: String, recipient: String, amount: u64, fee: u64) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            sender,
            recipient,
            amount,
            fee,
            timestamp,
            signature: None,
            is_private: false,
        }
    }
    
    pub fn sign(&mut self, keypair: &KeyPair) -> Result<()> {
        let message = self.message_to_sign();
        self.signature = Some(keypair.sign(&message)?);
        Ok(())
    }
    
    pub fn verify_signature(&self) -> Result<bool> {
        if let Some(signature) = &self.signature {
            let message = self.message_to_sign();
            let keypair = KeyPair::new()?; // This should be the sender's keypair
            Ok(keypair.verify(&message, signature)?)
        } else {
            Ok(false)
        }
    }
    
    pub fn hash(&self) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(self.sender.as_bytes());
        hasher.update(self.recipient.as_bytes());
        hasher.update(&self.amount.to_le_bytes());
        hasher.update(&self.fee.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        
        if let Some(signature) = &self.signature {
            hasher.update(signature);
        }
        
        hex::encode(hasher.finalize())
    }
    
    pub fn is_private(&self) -> bool {
        self.is_private
    }
    
    fn message_to_sign(&self) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(self.sender.as_bytes());
        message.extend_from_slice(self.recipient.as_bytes());
        message.extend_from_slice(&self.amount.to_le_bytes());
        message.extend_from_slice(&self.fee.to_le_bytes());
        message.extend_from_slice(&self.timestamp.to_le_bytes());
        message
    }
}

impl From<Transaction> for crate::crypto::ZKTransaction {
    fn from(tx: Transaction) -> Self {
        Self {
            sender: tx.sender,
            recipient: tx.recipient,
            amount: tx.amount,
            timestamp: tx.timestamp,
            proof: tx.signature.unwrap_or_default(),
        }
    }
} 