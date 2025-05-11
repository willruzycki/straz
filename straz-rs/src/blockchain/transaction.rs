use crate::Result;
use crate::crypto::{KeyPair, PublicKey, Signature, Hash, hash_data, sign_data, verify_signature, StrazError as CryptoError, PqcPublicKey, PqcSignature, QuantumSignature, HybridSignature, HybridKey};
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::vm::compiler::assemble;
use super::transaction_error::TransactionError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    pub sender: PublicKey,
    pub recipient: PublicKey,
    pub amount: u64,
    pub fee: u64,
    pub timestamp: u64,
    pub signature: HybridSignature,
    pub is_private: bool,
    pub tx_hash: Hash,
    pub bytecode: Vec<u8>,
    pub gas_limit: u64,
    pub gas_price: u128,
}

impl Transaction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender: PublicKey,
        recipient: PublicKey,
        amount: u64,
        fee: u64,
        is_private: bool,
        contract_source: Option<&str>,
        key_pair: &HybridKey,
        gas_limit: u64,
        gas_price: u128,
    ) -> Result<Self, TransactionError> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let bytecode = match contract_source {
            Some(source) => {
                assemble(source).map_err(|e| TransactionError::InvalidBytecode(e.to_string()))?
            }
            None => Vec::new(),
        };

        let mut preliminary_tx = Transaction {
            sender: sender.clone(),
            recipient: recipient.clone(),
            amount,
            fee,
            timestamp,
            signature: HybridSignature::default(),
            is_private,
            tx_hash: Hash([0; 32]),
            bytecode: bytecode.clone(),
            gas_limit,
            gas_price,
        };

        let tx_bytes_for_hash = preliminary_tx.to_bytes_for_hashing();
        let tx_hash = hash_data(&tx_bytes_for_hash);
        preliminary_tx.tx_hash = tx_hash;

        let signature = key_pair.sign(&tx_hash.0).map_err(|e| TransactionError::SignatureError(e))?;
        preliminary_tx.signature = signature;

        Ok(preliminary_tx)
    }

    pub fn to_bytes_for_hashing(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.sender.pqc_key.0);
        bytes.extend_from_slice(&self.sender.quantum_key.0);
        bytes.extend_from_slice(&self.recipient.pqc_key.0);
        bytes.extend_from_slice(&self.recipient.quantum_key.0);
        bytes.extend_from_slice(&self.amount.to_be_bytes());
        bytes.extend_from_slice(&self.fee.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.push(self.is_private as u8);
        bytes.extend_from_slice(&self.bytecode);
        bytes.extend_from_slice(&self.gas_limit.to_be_bytes());
        bytes.extend_from_slice(&self.gas_price.to_be_bytes());
        bytes
    }

    pub fn hash(&self) -> Hash {
        self.tx_hash
    }

    pub fn verify_signature(&self) -> Result<bool, CryptoError> {
        self.sender.verify(&self.tx_hash.0, &self.signature)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_and_sign(
        sender_pk: PublicKey,
        recipient_pk: PublicKey,
        amount: u64,
        fee: u64,
        is_private: bool,
        contract_source: Option<&str>,
        key_pair: &HybridKey,
        gas_limit: u64,
        gas_price: u128,
    ) -> Result<Self, TransactionError> {
        if gas_limit == 0 && !contract_source.unwrap_or("").is_empty() {
            return Err(TransactionError::InvalidBytecode("Gas limit must be > 0 for contracts".to_string()));
        }

        Self::new(
            sender_pk,
            recipient_pk,
            amount,
            fee,
            is_private,
            contract_source,
            key_pair,
            gas_limit,
            gas_price,
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{PqcKeyPair, QuantumKeyPair, hybrid::HybridKey};

    fn mock_hybrid_keypair() -> HybridKey {
        let pqc_kp = PqcKeyPair::generate();
        let quantum_kp = QuantumKeyPair::generate();
        HybridKey::new(pqc_kp, quantum_kp)
    }

    fn mock_public_key_from_hybrid(hybrid_key: &HybridKey) -> PublicKey {
        hybrid_key.public_key()
    }

    #[test]
    fn test_transaction_creation_with_gas() {
        let key_pair1 = mock_hybrid_keypair();
        let pk1 = mock_public_key_from_hybrid(&key_pair1);
        let key_pair2 = mock_hybrid_keypair();
        let pk2 = mock_public_key_from_hybrid(&key_pair2);

        let tx = Transaction::create_and_sign(
            pk1.clone(),
            pk2.clone(),
            100,
            10,
            false,
            Some("PUSH 1; ADD; STOP"),
            &key_pair1,
            20000,
            100,
        ).unwrap();

        assert!(!tx.bytecode.is_empty());
        assert_eq!(tx.gas_limit, 20000);
        assert_eq!(tx.gas_price, 100);
        let hash1 = tx.hash();
        
        let tx_recreated_for_hash_check = Transaction {
            sender: pk1.clone(),
            recipient: pk2.clone(),
            amount: tx.amount,
            fee: tx.fee,
            timestamp: tx.timestamp,
            signature: HybridSignature::default(),
            is_private: tx.is_private,
            tx_hash: Hash([0;32]),
            bytecode: tx.bytecode.clone(),
            gas_limit: tx.gas_limit,
            gas_price: tx.gas_price,
        };
        let bytes_for_hash = tx_recreated_for_hash_check.to_bytes_for_hashing();
        let re_hash = hash_data(&bytes_for_hash);
        assert_eq!(hash1, re_hash, "Hashes should match for identical content excluding signature");

        assert!(tx.verify_signature().unwrap(), "Signature verification should succeed");
    }

    #[test]
    fn test_transaction_with_no_bytecode() {
        let key_pair = mock_hybrid_keypair();
        let pk_sender = mock_public_key_from_hybrid(&key_pair);
        let pk_recipient = mock_public_key_from_hybrid(&mock_hybrid_keypair());

        let tx = Transaction::create_and_sign(
            pk_sender,
            pk_recipient,
            50,
            5,
            false,
            None,
            &key_pair,
            0,
            0,
        ).unwrap();
        assert!(tx.bytecode.is_empty());
        assert!(tx.verify_signature().unwrap());
    }

    #[test]
    fn test_transaction_invalid_bytecode_assembly() {
        let key_pair = mock_hybrid_keypair();
        let pk_sender = mock_public_key_from_hybrid(&key_pair);
        let pk_recipient = mock_public_key_from_hybrid(&mock_hybrid_keypair());

        let result = Transaction::create_and_sign(
            pk_sender,
            pk_recipient,
            50,
            5,
            false,
            Some("PUSH BAD_LITERAL"),
            &key_pair,
            0,
            0,
        );
        assert!(matches!(result, Err(TransactionError::InvalidBytecode(_))));
    }
} 