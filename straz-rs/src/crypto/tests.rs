#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, PostQuantumCrypto, ZKRollup, ZKTransaction};
    
    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::new().unwrap();
        assert!(!keypair.public_key.key.is_empty());
        assert!(!keypair.private_key.key.is_empty());
    }
    
    #[test]
    fn test_signature_verification() {
        let keypair = KeyPair::new().unwrap();
        let message = b"Hello, quantum world!";
        
        let signature = keypair.sign(message).unwrap();
        assert!(keypair.verify(message, &signature).unwrap());
        
        // Test with modified message
        let modified_message = b"Hello, classical world!";
        assert!(!keypair.verify(modified_message, &signature).unwrap());
    }
    
    #[test]
    fn test_pqc_operations() {
        let (public_key, private_key) = PostQuantumCrypto::generate_keypair().unwrap();
        let message = b"Test message for PQC";
        
        let signature = PostQuantumCrypto::sign(message, &private_key).unwrap();
        assert!(PostQuantumCrypto::verify(message, &signature, &public_key).unwrap());
    }
    
    #[test]
    fn test_zk_rollup() {
        let mut rollup = ZKRollup::new();
        
        // Create a test transaction
        let transaction = ZKTransaction {
            sender: "Alice".to_string(),
            recipient: "Bob".to_string(),
            amount: 100,
            timestamp: 1234567890,
            proof: vec![1, 2, 3, 4], // Placeholder proof
        };
        
        // Add transaction to rollup
        assert!(rollup.add_transaction(transaction.clone()).is_ok());
        
        // Generate and verify batch proof
        let batch_proof = rollup.generate_batch_proof().unwrap();
        assert!(rollup.verify_batch_proof(&batch_proof).unwrap());
    }
} 