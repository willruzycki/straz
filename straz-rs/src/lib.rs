pub mod blockchain;
pub mod crypto;
pub mod consensus;
pub mod network;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StrazError {
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    #[error("Blockchain error: {0}")]
    Blockchain(String),
    
    #[error("Consensus error: {0}")]
    Consensus(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StrazError>;

// Re-export commonly used types
pub use blockchain::{Block, Transaction, Blockchain};
pub use crypto::{KeyPair, PublicKey, PrivateKey};
pub use consensus::Consensus;
pub use network::Node; 