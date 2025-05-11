#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vrf_proof_generation() {
        let keypair = KeyPair::new().unwrap();
        let mut vrf = VRF::new(keypair);
        
        // Generate proof
        let output = vrf.generate_proof(0, 0).unwrap();
        
        // Verify proof
        let is_valid = vrf.verify_proof(
            0,
            0,
            &keypair.public_key(),
            &output.proof,
            &output.value,
        ).unwrap();
        
        assert!(is_valid);
    }
    
    #[test]
    fn test_vrf_proof_verification() {
        let keypair = KeyPair::new().unwrap();
        let mut vrf = VRF::new(keypair);
        
        // Generate proof
        let output = vrf.generate_proof(0, 0).unwrap();
        
        // Try to verify with wrong epoch
        let is_valid = vrf.verify_proof(
            1,
            0,
            &keypair.public_key(),
            &output.proof,
            &output.value,
        ).unwrap();
        
        assert!(!is_valid);
        
        // Try to verify with wrong round
        let is_valid = vrf.verify_proof(
            0,
            1,
            &keypair.public_key(),
            &output.proof,
            &output.value,
        ).unwrap();
        
        assert!(!is_valid);
        
        // Try to verify with wrong public key
        let wrong_keypair = KeyPair::new().unwrap();
        let is_valid = vrf.verify_proof(
            0,
            0,
            &wrong_keypair.public_key(),
            &output.proof,
            &output.value,
        ).unwrap();
        
        assert!(!is_valid);
    }
    
    #[test]
    fn test_proposer_selection() {
        let keypair = KeyPair::new().unwrap();
        let mut vrf = VRF::new(keypair);
        
        // Generate proof
        vrf.generate_proof(0, 0).unwrap();
        
        // Create validators with different stakes
        let validators = vec![
            (KeyPair::new().unwrap().public_key(), 1000),
            (KeyPair::new().unwrap().public_key(), 2000),
            (KeyPair::new().unwrap().public_key(), 3000),
        ];
        
        let total_stake: u128 = validators.iter().map(|(_, stake)| stake).sum();
        
        // Select proposer
        let proposer = vrf.get_proposer(0, 0, &validators, total_stake).unwrap();
        
        // Verify proposer is one of the validators
        assert!(validators.iter().any(|(pubkey, _)| pubkey == &proposer));
    }
    
    #[test]
    fn test_stake_weighted_selection() {
        let keypair = KeyPair::new().unwrap();
        let mut vrf = VRF::new(keypair);
        
        // Generate multiple proofs
        for epoch in 0..10 {
            for round in 0..10 {
                vrf.generate_proof(epoch, round).unwrap();
            }
        }
        
        // Create validators with different stakes
        let validators = vec![
            (KeyPair::new().unwrap().public_key(), 1000),
            (KeyPair::new().unwrap().public_key(), 2000),
            (KeyPair::new().unwrap().public_key(), 3000),
        ];
        
        let total_stake: u128 = validators.iter().map(|(_, stake)| stake).sum();
        
        // Count proposer selections
        let mut selections = HashMap::new();
        for epoch in 0..10 {
            for round in 0..10 {
                let proposer = vrf.get_proposer(epoch, round, &validators, total_stake).unwrap();
                *selections.entry(proposer).or_insert(0) += 1;
            }
        }
        
        // Verify selection distribution roughly matches stake distribution
        for (pubkey, stake) in &validators {
            let selection_count = selections.get(pubkey).unwrap_or(&0);
            let expected_count = (stake * 100) / total_stake;
            let actual_count = (selection_count * 100) / 100;
            
            // Allow for some variance (e.g., ±10%)
            assert!((actual_count as i32 - expected_count as i32).abs() <= 10);
        }
    }
} 