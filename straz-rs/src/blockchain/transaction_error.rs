use std::fmt;
use crate::crypto::CryptoError; // Assuming you have a CryptoError type

#[derive(Debug)]
pub enum TransactionError {
    MissingSender,
    MissingRecipient,
    InvalidAmount,
    InvalidFee,
    SignatureError(CryptoError),
    VerificationFailed,
    HashingFailed,
    InvalidBytecode(String),
    SerializationError(String),
    VmExecutionError(String), // For errors during VM execution of bytecode
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionError::MissingSender => write!(f, "Transaction sender is missing"),
            TransactionError::MissingRecipient => write!(f, "Transaction recipient is missing"),
            TransactionError::InvalidAmount => write!(f, "Invalid transaction amount"),
            TransactionError::InvalidFee => write!(f, "Invalid transaction fee"),
            TransactionError::SignatureError(e) => write!(f, "Signature error: {}", e),
            TransactionError::VerificationFailed => write!(f, "Transaction verification failed"),
            TransactionError::HashingFailed => write!(f, "Failed to hash transaction"),
            TransactionError::InvalidBytecode(s) => write!(f, "Invalid bytecode: {}", s),
            TransactionError::SerializationError(s) => write!(f, "Transaction serialization error: {}", s),
            TransactionError::VmExecutionError(s) => write!(f, "VM execution error: {}", s),
        }
    }
}

impl std::error::Error for TransactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransactionError::SignatureError(e) => Some(e),
            _ => None,
        }
    }
}

// If your CryptoError is compatible, you can implement From
// impl From<CryptoError> for TransactionError {
//     fn from(err: CryptoError) -> Self {
//         TransactionError::SignatureError(err)
//     }
// } 