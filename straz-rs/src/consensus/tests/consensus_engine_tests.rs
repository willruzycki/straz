#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tokio::time::{timeout, Duration};
    use std::collections::HashMap;

    use crate::crypto::{KeyPair, Address, PublicKey, Signature};
    use crate::consensus::engine::ConsensusEngine;
    use crate::consensus::types::{
        ValidatorSet, ConsensusMsg, Proposal, Vote, Validator, StakeTx, UnstakeTx,
        MIN_STAKE, EPOCH_LENGTH, MAX_ROUNDS_PER_BLOCK, SLASH_DOUBLE_SIGN_PERCENTAGE, 
        SLASH_DOWNTIME_PERCENTAGE
    };
    use crate::consensus::rewards::RewardManager;
    use crate::network::{Network, NetworkMsg}; // Assuming a basic Network struct for mocking
    use crate::blockchain::Block; // Assuming Block is accessible
    use crate::blockchain::types::Receipt as BlockchainReceipt; // Alias to avoid conflict with consensus Receipt if any

    fn new_keypair(id: u8) -> KeyPair {
        // In a real test, you might load from fixture or use a more robust generation
        // For simplicity, using a basic new() assuming it works for testing
        KeyPair::new_from_seed(&[id; 32]) // Assuming a seed-based constructor
    }

    fn get_address_from_pk(pk: &PublicKey) -> Address {
        hex::encode(pk)
    }

    // Mock Network for testing consensus engine
    struct MockNetwork {
        // pub outgoing_messages: Arc<RwLock<Vec<ConsensusMsg>>>,
        // For now, we don't need to inspect outgoing, just ensure engine calls broadcast
        consensus_tx: tokio::sync::mpsc::Sender<ConsensusMsg>,
        consensus_rx: Arc<RwLock<tokio::sync::mpsc::Receiver<ConsensusMsg>>>,
    }

    impl MockNetwork {
        fn new() -> (Arc<RwLock<Network>>, tokio::sync::mpsc::Receiver<ConsensusMsg>) {
            // let outgoing_messages = Arc::new(RwLock::new(Vec::new()));
            let (consensus_tx, consensus_rx_internal) = tokio::sync::mpsc::channel(100);
            let network_adapter = Network::new_mock(consensus_tx.clone()); // Assuming Network has a mock constructor or way to inject sender
            (network_adapter, consensus_rx_internal)
        }
    }
    
    // Helper to create a basic block for testing consensus
    fn create_test_block(epoch: u64, round: u64, proposer_pk: PublicKey, previous_hash: Vec<u8>) -> Block {
        let index = epoch * EPOCH_LENGTH + round;
        let mut block = Block::new(index, vec![], previous_hash);
        block.hash = block.calculate_hash().unwrap_or_default(); // Ensure hash is set
        // block.proposer = Some(proposer_pk); // If block stores proposer
        block
    }

    async fn setup_engine(num_validators: usize) -> (ConsensusEngine, Vec<KeyPair>, Arc<RwLock<ValidatorSet>>, Arc<RwLock<Network>>, tokio::sync::mpsc::Receiver<ConsensusMsg>) {
        let mut vs = ValidatorSet::new();
        let mut keypairs = Vec::new();

        for i in 0..num_validators {
            let kp = new_keypair(i as u8 + 1);
            let addr = get_address_from_pk(&kp.public_key());
            vs.register_validator(addr.clone(), kp.public_key(), MIN_STAKE + 1000).expect("Failed to register validator");
            keypairs.push(kp);
        }
        vs.update_active_validators();
        let validator_set_arc = Arc::new(RwLock::new(vs));

        let (network_arc, consensus_rx) = MockNetwork::new();
        
        // For engine tests, we typically use the first keypair for the engine instance
        let engine_keypair = keypairs[0].clone(); 

        let engine = ConsensusEngine::new(validator_set_arc.clone(), engine_keypair, network_arc.clone());
        (engine, keypairs, validator_set_arc, network_arc, consensus_rx)
    }

    #[tokio::test]
    async fn test_single_proposer_finalizes_block() {
        let (engine, keypairs, vs_arc, network_arc, mut consensus_rx) = setup_engine(1).await;
        let proposer_kp = &keypairs[0];
        let proposer_addr = get_address_from_pk(&proposer_kp.public_key());

        // Manually set the engine's VRF to make this node the proposer for (0,0)
        {
            let mut vrf_guard = engine.vrf.write().await;
            // This is tricky; VRF internals are not easily mockable without changing VRF design.
            // For this test, we rely on the engine's is_proposer logic which should pick the sole validator.
            // If not, this test would need more complex VRF mocking or a way to force proposer.
            assert!(engine.is_proposer(0,0).await.unwrap(), "The single validator should be the proposer");
        }
        
        // The engine.start() runs a loop. For a test, we might call internal steps or a test-specific run_one_round.
        // Let's simulate the proposal and vote part that engine.start() would drive.

        // 1. Proposer (engine itself) proposes a block
        engine.propose_block(0, 0).await.expect("Propose block failed");

        // 2. Check if proposal was broadcast (optional, mock network would check)
        let proposal_msg = timeout(Duration::from_secs(1), consensus_rx.recv()).await
            .expect("Timeout waiting for proposal broadcast")
            .expect("Failed to receive proposal from mock network");
        
        let received_proposal = match proposal_msg {
            ConsensusMsg::Proposal(p) => p,
            _ => panic!("Expected a proposal message"),
        };
        assert_eq!(received_proposal.epoch, 0);
        assert_eq!(received_proposal.round, 0);
        assert_eq!(received_proposal.proposer_pubkey, proposer_kp.public_key());

        // 3. Engine (as voter) should see its own proposal and vote
        // In the current engine, handle_proposal also triggers a vote if self is active validator.
        // The broadcasted proposal will be "received" by handle_network_message if we mock that part.
        // For simplicity, let's assume propose_block also makes the engine vote for its own proposal if it's a validator.
        // (This is true if handle_proposal is called internally, or if it processes its own broadcast).
        
        // Check for the vote broadcast by the engine for its own proposal
        let vote_msg = timeout(Duration::from_secs(1), consensus_rx.recv()).await
            .expect("Timeout waiting for vote broadcast")
            .expect("Failed to receive vote from mock network");

        let received_vote = match vote_msg {
            ConsensusMsg::Vote(v) => v,
            _ => panic!("Expected a vote message"),
        };
        assert_eq!(received_vote.epoch, 0);
        assert_eq!(received_vote.round, 0);
        assert_eq!(received_vote.voter_pubkey, proposer_kp.public_key());
        assert_eq!(received_vote.block_hash, received_proposal.block_hash);

        // 4. Attempt to finalize (engine should have enough votes - its own)
        engine.attempt_finalize_or_next_round(0, 0).await.expect("Finalization failed");

        // 5. Verify block is considered finalized (e.g., round reset, epoch potentially incremented if EPOCH_LENGTH is 1)
        let vs_read = vs_arc.read().await;
        assert_eq!(vs_read.current_round, 0, "Round should reset after finalization");
        // If EPOCH_LENGTH > 1, epoch should not increment yet.
        // println!("Epoch after finalization: {}", vs_read.current_epoch);
    }

    #[tokio::test]
    async fn test_double_signing_triggers_slashing() {
        let (engine, keypairs, vs_arc, network_arc, mut consensus_rx) = setup_engine(1).await;
        let proposer_kp = keypairs[0].clone();
        let proposer_pk_bytes = proposer_kp.public_key();
        let proposer_addr = get_address_from_pk(&proposer_pk_bytes);

        // Ensure this node is the proposer (as in previous test)
        assert!(engine.is_proposer(0,0).await.unwrap(), "Proposer setup failed");

        // Propose first block
        let block1 = create_test_block(0, 0, proposer_pk_bytes.clone(), vec![0;32]);
        let proposal1 = Proposal {
            epoch: 0, round: 0, block_hash: block1.hash.clone(), block: Arc::new(block1.clone()),
            proposer_pubkey: proposer_pk_bytes.clone(), signature: proposer_kp.sign(&block1.hash).unwrap(),
        };
        engine.handle_proposal(proposal1.clone()).await.expect("Handling proposal 1 failed");
        
        // Consume broadcasts (proposal & vote)
        consensus_rx.recv().await; consensus_rx.recv().await;

        let stake_before_slash = vs_arc.read().await.validators.get(&proposer_addr).unwrap().stake;

        // Propose a conflicting block (different hash, same epoch, round, proposer)
        let block2 = create_test_block(0, 0, proposer_pk_bytes.clone(), vec![1;32]); // Different prev_hash for different block_hash
        let proposal2 = Proposal {
            epoch: 0, round: 0, block_hash: block2.hash.clone(), block: Arc::new(block2.clone()),
            proposer_pubkey: proposer_pk_bytes.clone(), signature: proposer_kp.sign(&block2.hash).unwrap(),
        };
        
        // This should trigger slashing due to double-signing detection in handle_proposal
        let result = engine.handle_proposal(proposal2.clone()).await;
        assert!(result.is_err(), "Handling conflicting proposal should fail due to double-signing");
        assert!(format!("{:?}", result.unwrap_err()).contains("Conflicting proposal (double-sign)"));

        let stake_after_slash = vs_arc.read().await.validators.get(&proposer_addr).unwrap().stake;
        let expected_slash_amount = (stake_before_slash * SLASH_DOUBLE_SIGN_PERCENTAGE as u128) / 100;
        assert_eq!(stake_after_slash, stake_before_slash - expected_slash_amount, "Validator stake not slashed correctly for double signing.");
    }

    #[tokio::test]
    async fn test_liveness_slashing_at_epoch_end() {
        let (engine, keypairs, vs_arc, network_arc, _) = setup_engine(1).await;
        let validator_kp = &keypairs[0];
        let validator_addr = get_address_from_pk(&validator_kp.public_key());

        let stake_before_slash;
        let mut missed_votes_to_record;
        {
            let vs_read = vs_arc.read().await;
            stake_before_slash = vs_read.validators.get(&validator_addr).unwrap().stake;
            // Simulate missing > 50% of votes. EPOCH_LENGTH is number of blocks.
            // Assuming 1 voting opportunity per block for simplicity in this test.
            missed_votes_to_record = (EPOCH_LENGTH / 2) + 1;
        }

        {
            let mut vs_write = vs_arc.write().await;
            let validator_mut = vs_write.validators.get_mut(&validator_addr).unwrap();
            validator_mut.missed_votes_in_epoch = missed_votes_to_record;
            
            // Manually trigger epoch transition to test liveness slashing
            // Normally, this is driven by the engine's main loop and block finalization.
            println!("Current epoch before transition: {}", vs_write.current_epoch);
            let _slashed_validators = vs_write.end_epoch_transition(); 
            // `end_epoch_transition` in types.rs already prints if slashing happens
            println!("Current epoch after transition: {}", vs_write.current_epoch);
        }
        
        let stake_after_slash = vs_arc.read().await.validators.get(&validator_addr).unwrap().stake;
        let expected_slash_amount = (stake_before_slash * SLASH_DOWNTIME_PERCENTAGE as u128) / 100;
        
        assert_eq!(stake_after_slash, stake_before_slash.saturating_sub(expected_slash_amount), 
                   "Validator stake not slashed correctly for liveness fault.");
    }
} 