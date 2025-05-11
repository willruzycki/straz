use serde::{Deserialize, Serialize};

// Define Hash as a vector of bytes (e.g., a 32-byte hash)
pub type Hash = Vec<u8>;

// Placeholder for blockchain events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub event_type: String, // e.g., "Transfer", "ContractDeployed"
    pub attributes: Vec<(String, String)>, // e.g., [("from", "addr1"), ("to", "addr2"), ("amount", "100")]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    pub state_root: Hash,    // The state root after the block is applied
    pub gas_used: u64,       // Total gas used by transactions in the block
    pub events: Vec<Event>,  // Events emitted by transactions in the block
    pub success: bool,       // Whether block application was successful overall
}

// Define custom error types for the blockchain module
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlockchainError {
    InvalidBlock(String),
    InvalidTransaction(String),
    StateUpdateFailure(String),
    DatabaseError(String),
    UnknownError(String),
}

impl std::fmt::Display for BlockchainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockchainError::InvalidBlock(msg) => write!(f, "Invalid Block: {}", msg),
            BlockchainError::InvalidTransaction(msg) => write!(f, "Invalid Transaction: {}", msg),
            BlockchainError::StateUpdateFailure(msg) => write!(f, "State Update Failure: {}", msg),
            BlockchainError::DatabaseError(msg) => write!(f, "Database Error: {}", msg),
            BlockchainError::UnknownError(msg) => write!(f, "Unknown Blockchain Error: {}", msg),
        }
    }
}

impl std::error::Error for BlockchainError {} 