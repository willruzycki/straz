#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    
    #[tokio::test]
    async fn test_blockchain_creation() {
        let blockchain = Blockchain::new(4);
        assert_eq!(blockchain.chain.len(), 1); // Genesis block
        assert_eq!(blockchain.difficulty, 4);
        assert_eq!(blockchain.mining_reward, 50);
    }
    
    #[tokio::test]
    async fn test_transaction_creation() {
        let mut blockchain = Blockchain::new(4);
        let keypair = KeyPair::generate();
        
        // Create a transaction
        let result = blockchain.create_transaction(
            keypair.public_key(),
            "recipient".to_string(),
            100,
            1,
        ).await;
        
        assert!(result.is_ok());
        assert_eq!(blockchain.transaction_pool.len(), 1);
    }
    
    #[tokio::test]
    async fn test_mining() {
        let mut blockchain = Blockchain::new(4);
        let miner_address = "miner".to_string();
        
        // Create some transactions
        blockchain.create_transaction(
            "sender1".to_string(),
            "recipient1".to_string(),
            100,
            1,
        ).await.unwrap();
        
        blockchain.create_transaction(
            "sender2".to_string(),
            "recipient2".to_string(),
            200,
            2,
        ).await.unwrap();
        
        // Mine a block
        let result = blockchain.mine_pending_transactions(miner_address.clone()).await;
        assert!(result.is_ok());
        
        // Check chain state
        assert_eq!(blockchain.chain.len(), 2); // Genesis + mined block
        assert!(blockchain.transaction_pool.is_empty());
        
        // Check miner's balance
        let balance = blockchain.get_balance(&miner_address).unwrap();
        assert_eq!(balance, 50); // Mining reward
    }
    
    #[tokio::test]
    async fn test_chain_validation() {
        let mut blockchain = Blockchain::new(4);
        
        // Create and mine some blocks
        blockchain.create_transaction(
            "sender".to_string(),
            "recipient".to_string(),
            100,
            1,
        ).await.unwrap();
        
        blockchain.mine_pending_transactions("miner".to_string()).await.unwrap();
        
        // Verify chain
        assert!(blockchain.is_chain_valid().unwrap());
        
        // Tamper with chain
        if let Some(block) = blockchain.chain.last_mut() {
            block.hash = "tampered".to_string();
        }
        
        // Verify chain is invalid
        assert!(!blockchain.is_chain_valid().unwrap());
    }
    
    #[tokio::test]
    async fn test_private_transactions() {
        let mut blockchain = Blockchain::new(4);
        let keypair = KeyPair::generate();
        
        // Create a private transaction
        let result = blockchain.create_transaction(
            keypair.public_key(),
            "recipient".to_string(),
            100,
            1,
        ).await;
        
        assert!(result.is_ok());
        
        // Verify transaction was added to ZK-rollup
        assert!(!blockchain.zk_rollup.get_pending_transactions().is_empty());
    }
} 