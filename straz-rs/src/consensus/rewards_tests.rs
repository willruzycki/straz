#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_reward_calculation() {
        let mut reward_manager = RewardManager::new();
        
        // Create test validators with different stakes and participation
        let validators = vec![
            ("validator1".to_string(), 1000, 5, 100), // High stake, active
            ("validator2".to_string(), 500, 2, 80),  // Medium stake, moderate activity
            ("validator3".to_string(), 100, 0, 50),  // Low stake, minimal activity
        ];
        
        let total_stake: u128 = validators.iter().map(|(_, stake, _, _)| stake).sum();
        
        // Calculate rewards for epoch 1
        reward_manager.calculate_rewards(1, &validators, total_stake).unwrap();
        
        // Verify rewards
        let reward1 = reward_manager.get_validator_reward("validator1", 1).unwrap();
        let reward2 = reward_manager.get_validator_reward("validator2", 1).unwrap();
        let reward3 = reward_manager.get_validator_reward("validator3", 1).unwrap();
        
        // Check base rewards are proportional to stake
        assert!(reward1.base_reward > reward2.base_reward);
        assert!(reward2.base_reward > reward3.base_reward);
        
        // Check proposer bonuses
        assert!(reward1.proposer_bonus > reward2.proposer_bonus);
        assert_eq!(reward3.proposer_bonus, 0);
        
        // Check voter rewards
        assert!(reward1.voter_reward > reward2.voter_reward);
        assert!(reward2.voter_reward > reward3.voter_reward);
        
        // Check total rewards
        assert!(reward1.total_reward > reward2.total_reward);
        assert!(reward2.total_reward > reward3.total_reward);
    }
    
    #[test]
    fn test_slash_bounty() {
        let mut reward_manager = RewardManager::new();
        
        // Process a slash bounty
        let slashed_amount = 1000;
        reward_manager.process_slash_bounty(
            "reporter1".to_string(),
            "offender1".to_string(),
            1,
            slashed_amount,
        ).unwrap();
        
        // Verify bounty
        let bounty = reward_manager.get_reporter_bounty("reporter1", 1).unwrap();
        
        assert_eq!(bounty.slashed_amount, slashed_amount);
        assert_eq!(bounty.bounty_amount, (slashed_amount as f64 * REPORTING_BOUNTY) as u128);
        assert_eq!(bounty.reporter_address, "reporter1");
        assert_eq!(bounty.offender_address, "offender1");
    }
    
    #[test]
    fn test_epoch_rewards() {
        let mut reward_manager = RewardManager::new();
        
        // Create test validators
        let validators = vec![
            ("validator1".to_string(), 1000, 5, 100),
            ("validator2".to_string(), 500, 2, 80),
        ];
        
        let total_stake: u128 = validators.iter().map(|(_, stake, _, _)| stake).sum();
        
        // Calculate rewards for multiple epochs
        reward_manager.calculate_rewards(1, &validators, total_stake).unwrap();
        reward_manager.calculate_rewards(2, &validators, total_stake).unwrap();
        
        // Get rewards for epoch 1
        let epoch1_rewards = reward_manager.get_epoch_rewards(1);
        assert_eq!(epoch1_rewards.len(), 2);
        
        // Get rewards for epoch 2
        let epoch2_rewards = reward_manager.get_epoch_rewards(2);
        assert_eq!(epoch2_rewards.len(), 2);
        
        // Verify total rewards
        let total_rewards = reward_manager.get_total_rewards();
        assert!(total_rewards > 0);
    }
    
    #[test]
    fn test_reward_distribution() {
        let mut reward_manager = RewardManager::new();
        
        // Create validators with equal stake but different participation
        let validators = vec![
            ("validator1".to_string(), 1000, 10, 100), // High participation
            ("validator2".to_string(), 1000, 5, 50),   // Medium participation
            ("validator3".to_string(), 1000, 0, 0),    // No participation
        ];
        
        let total_stake: u128 = validators.iter().map(|(_, stake, _, _)| stake).sum();
        
        // Calculate rewards
        reward_manager.calculate_rewards(1, &validators, total_stake).unwrap();
        
        // Get rewards
        let reward1 = reward_manager.get_validator_reward("validator1", 1).unwrap();
        let reward2 = reward_manager.get_validator_reward("validator2", 1).unwrap();
        let reward3 = reward_manager.get_validator_reward("validator3", 1).unwrap();
        
        // Verify base rewards are equal (same stake)
        assert_eq!(reward1.base_reward, reward2.base_reward);
        assert_eq!(reward2.base_reward, reward3.base_reward);
        
        // Verify total rewards reflect participation
        assert!(reward1.total_reward > reward2.total_reward);
        assert!(reward2.total_reward > reward3.total_reward);
        
        // Verify no rewards for inactive validator
        assert_eq!(reward3.proposer_bonus, 0);
        assert_eq!(reward3.voter_reward, 0);
    }
} 