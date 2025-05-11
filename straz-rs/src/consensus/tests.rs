#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::Blockchain;
    use crate::crypto::KeyPair;
    
    #[tokio::test]
    async fn test_validator_registration() {
        let mut validator_set = ValidatorSet::new();
        let keypair = KeyPair::new().unwrap();
        
        // Register validator
        let tx = StakeTx {
            validator_pubkey: keypair.public_key(),
            amount: MIN_STAKE,
            delegatee: None,
            nonce: 0,
            signature: vec![],
        };
        
        validator_set.register_validator(tx).unwrap();
        assert_eq!(validator_set.validators.len(), 1);
        assert_eq!(validator_set.total_stake, MIN_STAKE);
        
        // Try registering with insufficient stake
        let tx = StakeTx {
            validator_pubkey: KeyPair::new().unwrap().public_key(),
            amount: MIN_STAKE - 1,
            delegatee: None,
            nonce: 0,
            signature: vec![],
        };
        
        assert!(validator_set.register_validator(tx).is_err());
    }
    
    #[tokio::test]
    async fn test_validator_unstaking() {
        let mut validator_set = ValidatorSet::new();
        let keypair = KeyPair::new().unwrap();
        let address = hex::encode(&keypair.public_key());
        
        // Register validator
        let tx = StakeTx {
            validator_pubkey: keypair.public_key(),
            amount: MIN_STAKE * 2,
            delegatee: None,
            nonce: 0,
            signature: vec![],
        };
        
        validator_set.register_validator(tx).unwrap();
        
        // Unstake half
        let tx = UnstakeTx {
            validator_address: address.clone(),
            amount: MIN_STAKE,
            nonce: 0,
            signature: vec![],
        };
        
        validator_set.unstake(tx).unwrap();
        assert_eq!(validator_set.total_stake, MIN_STAKE);
        
        // Try unstaking more than available
        let tx = UnstakeTx {
            validator_address: address,
            amount: MIN_STAKE + 1,
            nonce: 0,
            signature: vec![],
        };
        
        assert!(validator_set.unstake(tx).is_err());
    }
    
    #[tokio::test]
    async fn test_active_validator_selection() {
        let mut validator_set = ValidatorSet::new();
        let mut keypairs = Vec::new();
        
        // Register MAX_VALIDATORS + 1 validators
        for i in 0..MAX_VALIDATORS + 1 {
            let keypair = KeyPair::new().unwrap();
            keypairs.push(keypair.clone());
            
            let tx = StakeTx {
                validator_pubkey: keypair.public_key(),
                amount: MIN_STAKE + i as u128,
                delegatee: None,
                nonce: 0,
                signature: vec![],
            };
            
            validator_set.register_validator(tx).unwrap();
        }
        
        // Check that only top MAX_VALIDATORS are active
        assert_eq!(validator_set.active_validators.len(), MAX_VALIDATORS);
        
        // Verify active validators are sorted by stake
        let mut stakes: Vec<_> = validator_set.validators.values()
            .filter(|v| v.is_active)
            .map(|v| v.stake)
            .collect();
            
        stakes.sort_by(|a, b| b.cmp(a));
        assert_eq!(stakes, validator_set.validators.values()
            .filter(|v| v.is_active)
            .map(|v| v.stake)
            .collect::<Vec<_>>());
    }
    
    #[tokio::test]
    async fn test_consensus_engine() {
        let validator_set = ValidatorSet::new();
        let keypair = KeyPair::new().unwrap();
        let engine = ConsensusEngine::new(validator_set, keypair);
        
        // Test proposer selection
        let is_proposer = engine.is_proposer(0, 0).await.unwrap();
        assert!(!is_proposer); // No validators registered
        
        // Register validator
        let mut validator_set = ValidatorSet::new();
        let tx = StakeTx {
            validator_pubkey: keypair.public_key(),
            amount: MIN_STAKE,
            delegatee: None,
            nonce: 0,
            signature: vec![],
        };
        
        validator_set.register_validator(tx).unwrap();
        let engine = ConsensusEngine::new(validator_set, keypair);
        
        // Now should be proposer
        let is_proposer = engine.is_proposer(0, 0).await.unwrap();
        assert!(is_proposer);
    }
    
    #[tokio::test]
    async fn test_voting_and_finality() {
        let mut validator_set = ValidatorSet::new();
        let keypair = KeyPair::new().unwrap();
        
        // Register validator
        let tx = StakeTx {
            validator_pubkey: keypair.public_key(),
            amount: MIN_STAKE,
            delegatee: None,
            nonce: 0,
            signature: vec![],
        };
        
        validator_set.register_validator(tx).unwrap();
        let engine = ConsensusEngine::new(validator_set, keypair);
        
        // Create and handle proposal
        let block_hash = vec![1, 2, 3];
        let proposal = ConsensusMsg::Proposal {
            epoch: 0,
            round: 0,
            block_hash: block_hash.clone(),
            signature: keypair.sign(&block_hash).unwrap(),
        };
        
        engine.handle_proposal(proposal).await.unwrap();
        
        // Handle vote
        let vote = ConsensusMsg::Vote {
            epoch: 0,
            round: 0,
            block_hash: block_hash.clone(),
            signature: keypair.sign(&block_hash).unwrap(),
        };
        
        engine.handle_vote(vote).await.unwrap();
        
        // Check finality
        let is_finalized = engine.check_finality(0, 0, &block_hash).await.unwrap();
        assert!(is_finalized); // Single validator, so 1/1 > 2/3
    }
    
    #[tokio::test]
    async fn test_slashing() {
        let mut validator_set = ValidatorSet::new();
        let keypair = KeyPair::new().unwrap();
        let address = hex::encode(&keypair.public_key());
        
        // Register validator
        let tx = StakeTx {
            validator_pubkey: keypair.public_key(),
            amount: MIN_STAKE * 2,
            delegatee: None,
            nonce: 0,
            signature: vec![],
        };
        
        validator_set.register_validator(tx).unwrap();
        
        // Record some votes
        validator_set.record_vote(&address, &[1, 2, 3]).unwrap();
        validator_set.record_vote(&address, &[4, 5, 6]).unwrap();
        
        // Record missed votes
        for _ in 0..3 {
            validator_set.record_missed_vote(&address).unwrap();
        }
        
        // Should be slashed for >50% missed votes
        let validator = validator_set.validators.get(&address).unwrap();
        assert!(validator.stake < MIN_STAKE * 2);
        assert!(!validator.is_active);
    }
} 