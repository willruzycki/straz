mod quantum;
mod pqc;
mod zk;

pub use quantum::{KeyPair, PublicKey, PrivateKey};
pub use pqc::PostQuantumCrypto;
pub use zk::ZKRollup;

use crate::Result;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub key: Vec<u8>,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKey {
    pub key: Vec<u8>,
    pub algorithm: String,
}

impl KeyPair {
    pub fn new() -> Result<Self> {
        // Generate a hybrid key pair using both classical and post-quantum algorithms
        let (classical_pub, classical_priv) = quantum::generate_classical_keypair()?;
        let (pq_pub, pq_priv) = pqc::generate_keypair()?;
        
        Ok(KeyPair {
            public_key: PublicKey {
                key: classical_pub,
                algorithm: "hybrid".to_string(),
            },
            private_key: PrivateKey {
                key: classical_priv,
                algorithm: "hybrid".to_string(),
            },
        })
    }
    
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        // Implement hybrid signing using both classical and post-quantum algorithms
        let classical_sig = quantum::sign(message, &self.private_key)?;
        let pq_sig = pqc::sign(message, &self.private_key)?;
        
        // Combine signatures
        let mut combined = Vec::new();
        combined.extend_from_slice(&classical_sig);
        combined.extend_from_slice(&pq_sig);
        
        Ok(combined)
    }
    
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        // Split and verify both signatures
        let classical_sig = &signature[..32];
        let pq_sig = &signature[32..];
        
        let classical_valid = quantum::verify(message, classical_sig, &self.public_key)?;
        let pq_valid = pqc::verify(message, pq_sig, &self.public_key)?;
        
        Ok(classical_valid && pq_valid)
    }
} 