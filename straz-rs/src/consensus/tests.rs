#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::Blockchain;
    use crate::crypto::KeyPair;
    
    #[tokio::test]
    async fn test_validator_registration() {
        let blockchain = Blockchain::new(4);
        let consensus = Consensus::new(blockchain, 1000, 10);
        let keypair = KeyPair::generate();
        
        // Register validator
        let result = consensus.register_validator(
            "validator1".to_string(),
            2000,
            keypair,
        ).await;
        
        assert!(result.is_ok());
        
        // Try registering with insufficient stake
        let keypair = KeyPair::generate();
        let result = consensus.register_validator(
            "validator2".to_string(),
            500,
            keypair,
        ).await;
        
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_validator_selection() {
        let blockchain = Blockchain::new(4);
        let consensus = Consensus::new(blockchain, 1000, 10);
        
        // Register multiple validators with different stakes
        let keypair1 = KeyPair::generate();
        consensus.register_validator(
            "validator1".to_string(),
            2000,
            keypair1,
        ).await.unwrap();
        
        let keypair2 = KeyPair::generate();
        consensus.register_validator(
            "validator2".to_string(),
            3000,
            keypair2,
        ).await.unwrap();
        
        // Select validator
        let validator = consensus.select_validator().await.unwrap();
        assert!(validator.is_some());
        
        // Validator with higher stake should be selected
        assert_eq!(validator.unwrap().stake, 3000);
    }
    
    #[tokio::test]
    async fn test_block_validation() {
        let blockchain = Blockchain::new(4);
        let consensus = Consensus::new(blockchain, 1000, 10);
        let keypair = KeyPair::generate();
        
        // Register validator
        consensus.register_validator(
            "validator1".to_string(),
            2000,
            keypair.clone(),
        ).await.unwrap();
        
        // Create and sign a block
        let mut block = Block::new(
            1,
            vec![],
            "previous_hash".to_string(),
        );
        block.sign(&keypair).unwrap();
        
        // Validate block
        let validator = consensus.select_validator().await.unwrap().unwrap();
        let result = consensus.validate_block(&block, &validator).await;
        assert!(result.unwrap());
        
        // Try validating with tampered block
        block.hash = "tampered".to_string();
        let result = consensus.validate_block(&block, &validator).await;
        assert!(!result.unwrap());
    }
    
    #[tokio::test]
    async fn test_block_processing() {
        let blockchain = Blockchain::new(4);
        let consensus = Consensus::new(blockchain, 1000, 10);
        let keypair = KeyPair::generate();
        
        // Register validator
        consensus.register_validator(
            "validator1".to_string(),
            2000,
            keypair.clone(),
        ).await.unwrap();
        
        // Create and sign a block
        let mut block = Block::new(
            1,
            vec![],
            "previous_hash".to_string(),
        );
        block.sign(&keypair).unwrap();
        
        // Process block
        let result = consensus.process_block(block.clone()).await;
        assert!(result.is_ok());
        
        // Check validator stats
        let stats = consensus.get_validator_stats("validator1").await.unwrap();
        assert!(stats.is_some());
        let stats = stats.unwrap();
        assert_eq!(stats.total_blocks, 1);
        assert_eq!(stats.missed_blocks, 0);
    }
    
    #[tokio::test]
    async fn test_validator_performance() {
        let blockchain = Blockchain::new(4);
        let consensus = Consensus::new(blockchain, 1000, 10);
        let keypair = KeyPair::generate();
        
        // Register validator
        consensus.register_validator(
            "validator1".to_string(),
            2000,
            keypair.clone(),
        ).await.unwrap();
        
        // Create and process multiple blocks
        for i in 0..5 {
            let mut block = Block::new(
                i + 1,
                vec![],
                "previous_hash".to_string(),
            );
            block.sign(&keypair).unwrap();
            consensus.process_block(block).await.unwrap();
        }
        
        // Check validator stats
        let stats = consensus.get_validator_stats("validator1").await.unwrap();
        assert!(stats.is_some());
        let stats = stats.unwrap();
        assert_eq!(stats.total_blocks, 5);
        assert_eq!(stats.missed_blocks, 0);
    }
} 