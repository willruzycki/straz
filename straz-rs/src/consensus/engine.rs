use crate::Result;
use crate::blockchain::Block;
use crate::crypto::{KeyPair, Address, Signature, PublicKey};
use crate::network::{Network, NetworkMsg};
use super::types::{
    ValidatorSet, ConsensusMsg, Proposal, Vote, SlashTx, StakeTx, UnstakeTx, Validator,
    BLOCK_TIME, EPOCH_LENGTH, MAX_ROUNDS_PER_BLOCK, 
    SLASH_DOWNTIME_PERCENTAGE, SLASH_DOUBLE_SIGN_PERCENTAGE
};
use super::vrf::VRF;
use super::rewards::{RewardManager, ValidatorReward, SlashBounty, REPORTING_BOUNTY};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration, timeout};

#[derive(Debug, Clone)]
pub struct ConsensusEngine {
    validator_set: Arc<RwLock<ValidatorSet>>,
    proposals: Arc<RwLock<HashMap<(u64, u64), Proposal>>>, // (epoch, round) -> proposal
    // Store votes with block hash to detect conflicting votes for slashing
    votes: Arc<RwLock<HashMap<(u64, u64, Address), Vote>>>, // (epoch, round, voter_address) -> Vote
    keypair: KeyPair,
    network: Arc<RwLock<Network>>,
    vrf: Arc<RwLock<VRF>>,
    reward_manager: Arc<RwLock<RewardManager>>,
    // To prevent processing the same slash evidence multiple times
    processed_slash_evidence: Arc<RwLock<HashSet<Vec<u8>>>>,
}

impl ConsensusEngine {
    pub fn new(validator_set: ValidatorSet, keypair: KeyPair, network: Network) -> Self {
        let shared_validator_set = Arc::new(RwLock::new(validator_set));
        Self {
            validator_set: shared_validator_set.clone(),
            proposals: Arc::new(RwLock::new(HashMap::new())),
            votes: Arc::new(RwLock::new(HashMap::new())),
            keypair: keypair.clone(),
            network: Arc::new(RwLock::new(network)),
            vrf: Arc::new(RwLock::new(VRF::new(keypair, shared_validator_set))),
            reward_manager: Arc::new(RwLock::new(RewardManager::new())),
            processed_slash_evidence: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub async fn start(&self) -> Result<()> {
        let network_clone = Arc::clone(&self.network);
        tokio::spawn(async move {
            if let Err(e) = network_clone.write().await.start().await {
                eprintln!("Network error: {}", e); // Proper logging needed
            }
        });
        
        // Listen for messages from the network
        let self_clone = self.clone();
        tokio::spawn(async move {
            let network_reader = self_clone.network.read().await;
            let mut rx = network_reader.get_message_receiver().await;
            while let Some(msg) = rx.recv().await {
                let engine = self_clone.clone();
                tokio::spawn(async move {
                    if let Err(e) = engine.handle_network_message(msg).await {
                        eprintln!("Error handling network message: {}", e); // Proper logging
                    }
                });
            }
        });

        loop {
            let mut current_epoch;
            let mut current_round;
            {
                let vs = self.validator_set.read().await;
                current_epoch = vs.current_epoch;
                current_round = vs.current_round;
            }

            // VRF proof generation
            {
                let mut vrf_guard = self.vrf.write().await;
                if vrf_guard.get_output(current_epoch, current_round).is_none() {
                    if let Err(e) = vrf_guard.generate_proof(current_epoch, current_round).await {
                        eprintln!("Failed to generate VRF proof for E:{}, R:{}: {}", current_epoch, current_round, e);
                        sleep(Duration::from_secs(1)).await; // Wait before retrying
                        continue;
                    }
                }
            }

            if self.is_proposer(current_epoch, current_round).await? {
                if let Err(e) = self.propose_block(current_epoch, current_round).await {
                    eprintln!("Proposer error E:{}, R:{}: {}", current_epoch, current_round, e);
                }
            } else {
                // Wait for proposal with timeout based on BLOCK_TIME
                match timeout(Duration::from_secs(BLOCK_TIME / 2), self.wait_for_proposal(current_epoch, current_round)).await {
                    Ok(Ok(_)) => { /* Proposal received */ }
                    Ok(Err(e)) => eprintln!("Error waiting for proposal E:{}, R:{}: {}", current_epoch, current_round, e),
                    Err(_) => eprintln!("Timeout waiting for proposal E:{}, R:{}", current_epoch, current_round),
                }
            }
            
            // Attempt to finalize block or move to next round
            self.attempt_finalize_or_next_round(current_epoch, current_round).await?;

            // Short delay before next iteration, aligned with block time expectation
            sleep(Duration::from_millis(500)).await; 
        }
    }

    async fn handle_network_message(&self, msg: NetworkMsg) -> Result<()> {
        match msg {
            NetworkMsg::Consensus(consensus_msg) => {
                match consensus_msg {
                    ConsensusMsg::Proposal(proposal) => self.handle_proposal(proposal).await?,
                    ConsensusMsg::Vote(vote) => self.handle_vote(vote).await?,
                }
            },
            NetworkMsg::Transaction(tx_bytes) => { /* Handle incoming transactions */ },
            NetworkMsg::Block(block_bytes) => { /* Handle incoming blocks if needed for sync */ },
            // ... other NetworkMsg types
            _ => {}
        }
        Ok(())
    }

    async fn is_proposer(&self, epoch: u64, round: u64) -> Result<bool> {
        let vrf_guard = self.vrf.read().await;
        match vrf_guard.get_proposer(epoch, round).await {
            Ok(proposer_pk) => Ok(proposer_pk == self.keypair.public_key()),
            Err(e) => {
                eprintln!("Could not determine proposer for E:{}, R:{}: {}", epoch, round, e);
                Ok(false) // Default to not being proposer on error
            }
        }
    }

    async fn propose_block(&self, epoch: u64, round: u64) -> Result<()> {
        println!("Node {:?} proposing block for E:{}, R:{}", self.keypair.public_key_short(), epoch, round);
        
        // TODO: Actual block creation with transactions from mempool
        // For now, create a block with a dummy transaction that changes with epoch/round
        let dummy_tx_data = format!("tx_for_epoch_{}_round_{}", epoch, round).into_bytes();
        let previous_block_hash = self.get_previous_block_hash(epoch, round).await; // Needs implementation

        // Assuming Block::new signature is (index, transactions_data, previous_hash, nonce, difficulty)
        // The index here is simplified. A real chain would have a proper block height.
        let block_index = epoch * EPOCH_LENGTH + round; 
        let block = Block::new(
            block_index, 
            vec![dummy_tx_data], // Dummy transaction data 
            previous_block_hash, // Placeholder for actual previous block hash
            0, // Nonce - to be set by a mining function if PoW, or 0 for PoS if not used
            1  // Difficulty - placeholder
        ); 
        let block_hash = block.hash.clone();
        
        let proposal_msg = Proposal {
            epoch,
            round,
            block_hash: block_hash.clone(),
            block: Arc::new(block), // Include the block itself
            proposer_pubkey: self.keypair.public_key(),
            signature: self.keypair.sign(&block_hash)?,
        };

        {
            let mut proposals_guard = self.proposals.write().await;
            proposals_guard.insert((epoch, round), proposal_msg.clone());
        }
        
        // Record proposed block for reward calculation
        {
            let mut vs_guard = self.validator_set.write().await;
            vs_guard.record_block_proposed(&self.keypair.public_key_address()); 
        }

        self.broadcast_consensus_message(ConsensusMsg::Proposal(proposal_msg)).await
    }

    async fn wait_for_proposal(&self, epoch: u64, round: u64) -> Result<()> {
        // Check if proposal already exists
        let proposals_guard = self.proposals.read().await;
        if proposals_guard.contains_key(&(epoch, round)) {
            return Ok(());
        }
        // If not, we depend on the network handler to receive and process it.
        // The timeout is handled in the main loop.
        Ok(())
    }
    
    async fn broadcast_consensus_message(&self, msg: ConsensusMsg) -> Result<()> {
        let network = self.network.read().await;
        network.broadcast_consensus(msg).await
    }

    pub async fn handle_proposal(&self, proposal: Proposal) -> Result<()> {
        println!("Node {:?} received proposal for E:{}, R:{}", self.keypair.public_key_short(), proposal.epoch, proposal.round);
        // TODO: Validate block content (transactions, state transitions)
        let proposer_kp = KeyPair::from_public_key(&proposal.proposer_pubkey)?;
        if !proposer_kp.verify(&proposal.block_hash, &proposal.signature)? {
            return Err("Invalid proposal signature".into());
        }

        // Verify proposer is the legitimate one for this epoch/round via VRF
        let vrf_guard = self.vrf.read().await;
        let legitimate_proposer = vrf_guard.get_proposer(proposal.epoch, proposal.round).await?;
        if legitimate_proposer != proposal.proposer_pubkey {
            return Err(format!("Proposal from invalid proposer. Expected {:?}, got {:?}", legitimate_proposer, proposal.proposer_pubkey).into());
        }

        {
            let mut proposals_guard = self.proposals.write().await;
            if let Some(existing_proposal) = proposals_guard.get(&(proposal.epoch, proposal.round)) {
                if existing_proposal.block_hash != proposal.block_hash && existing_proposal.proposer_pubkey == proposal.proposer_pubkey {
                    // Double-signing by the same proposer in the same epoch/round
                    println!("Detected double-signing by {:?} for E:{}, R:{}", proposal.proposer_pubkey, proposal.epoch, proposal.round);
                    self.handle_slashing(
                        proposal.proposer_pubkey.clone(), 
                        SLASH_DOUBLE_SIGN_PERCENTAGE, 
                        // Provide evidence for SlashTx if needed
                        // For now, direct slashing based on detection
                    ).await?;
                    return Err("Conflicting proposal (double-sign)".into());
                }
            } else {
                proposals_guard.insert((proposal.epoch, proposal.round), proposal.clone());
            }
        }
        // If this node is an active validator, vote for the proposal
        let vs_guard = self.validator_set.read().await;
        if vs_guard.active_validators.contains(&self.keypair.public_key_address()) {
             drop(vs_guard); // Release read lock before acquiring write lock or calling other async funcs
            self.vote(proposal.epoch, proposal.round, &proposal.block_hash).await?;
        }
        Ok(())
    }

    async fn vote(&self, epoch: u64, round: u64, block_hash: &[u8]) -> Result<()> {
        let signature = self.keypair.sign(block_hash)?;
        let vote_msg = Vote {
            epoch,
            round,
            block_hash: block_hash.to_vec(),
            voter_pubkey: self.keypair.public_key(),
            signature,
        };

        {
            let mut votes_guard = self.votes.write().await;
            // Store vote, potentially overwriting if a validator re-votes (though this shouldn't happen for same block hash)
            votes_guard.insert((epoch, round, self.keypair.public_key_address()), vote_msg.clone());
        }
        self.broadcast_consensus_message(ConsensusMsg::Vote(vote_msg)).await
    }

    pub async fn handle_vote(&self, vote: Vote) -> Result<()> {
        println!("Node {:?} received vote for E:{}, R:{} from {:?}", self.keypair.public_key_short(), vote.epoch, vote.round, KeyPair::public_key_short_from_bytes(&vote.voter_pubkey));
        // Verify voter is an active validator
        let vs_guard = self.validator_set.read().await;
        if !vs_guard.active_validators.contains(&KeyPair::public_key_address_from_bytes(&vote.voter_pubkey)?) {
            return Err("Vote from non-active validator".into());
        }
        drop(vs_guard);

        let voter_kp = KeyPair::from_public_key(&vote.voter_pubkey)?;
        if !voter_kp.verify(&vote.block_hash, &vote.signature)? {
            return Err("Invalid vote signature".into());
        }

        {
            let mut votes_guard = self.votes.write().await;
            let voter_address = KeyPair::public_key_address_from_bytes(&vote.voter_pubkey)?;
            if let Some(existing_vote) = votes_guard.get(&(vote.epoch, vote.round, voter_address.clone())) {
                if existing_vote.block_hash != vote.block_hash {
                    // Voter changed their vote for the same epoch/round - potential slashing scenario (equivocation)
                    println!("Detected vote equivocation by {:?} for E:{}, R:{}", vote.voter_pubkey, vote.epoch, vote.round);
                     self.handle_slashing(
                        vote.voter_pubkey.clone(), 
                        SLASH_DOUBLE_SIGN_PERCENTAGE, // Treat equivocation similar to double-signing
                    ).await?;
                    return Err("Conflicting vote (equivocation)".into());
                }
            }
            votes_guard.insert((vote.epoch, vote.round, voter_address), vote.clone());
        }
        Ok(())
    }
    
    async fn handle_slashing(&self, offender_pubkey: PublicKey, slash_percentage: u8) -> Result<()> {
        let offender_address = KeyPair::public_key_address_from_bytes(&offender_pubkey)?;
        let mut vs_guard = self.validator_set.write().await;
        let slashed_amount = vs_guard.slash_validator(&offender_address, slash_percentage)?;
        println!("Slashed validator {:?} by {}% ({} tokens)", offender_address, slash_percentage, slashed_amount);
        
        // If we want to enable reporter bounties, we'd need a SlashTx submission mechanism.
        // For now, slashing is handled directly by the engine upon detection.
        // If reporter bounties are active, the node submitting SlashTx would get a reward.
        // Example: 
        // let mut reward_manager = self.reward_manager.write().await;
        // reward_manager.process_slash_bounty(
        // self.keypair.public_key_address(), // Reporter (this node)
        // offender_address,
        // vs_guard.current_epoch, 
        // slashed_amount
        // ).await?;
        Ok(())
    }

    async fn attempt_finalize_or_next_round(&self, epoch: u64, round: u64) -> Result<()> {
        let proposals_guard = self.proposals.read().await;
        if let Some(proposal) = proposals_guard.get(&(epoch, round)) {
            let votes_guard = self.votes.read().await;
            let mut current_block_votes: HashMap<Address, Signature> = HashMap::new();

            for ((e, r, voter_addr), vote_data) in votes_guard.iter() {
                if *e == epoch && *r == round && vote_data.block_hash == proposal.block_hash {
                    current_block_votes.insert(voter_addr.clone(), vote_data.signature.clone());
                }
            }
            drop(votes_guard); // Release votes read lock

            let vs_guard = self.validator_set.read().await;
            let active_validators_count = vs_guard.active_validators.len();
            let required_votes = (active_validators_count * 2) / 3 + 1; // 2/3 + 1

            if current_block_votes.len() >= required_votes {
                println!("Block E:{}, R:{} finalized with {} votes!", epoch, round, current_block_votes.len());
                // TODO: Apply block to blockchain state
                // self.blockchain.apply_block(proposal.block.clone()).await?;

                // Record who voted for reward purposes (or penalize who didn't)
                // This is partially handled by ValidatorSet.record_vote_missed elsewhere.
                
                let mut vs_write_guard = self.validator_set.write().await;
                vs_write_guard.current_round = 0; // Reset round for next block
                if (epoch * EPOCH_LENGTH + round + 1) % EPOCH_LENGTH == 0 { // Simplified check, needs refinement
                    println!("End of Epoch {} reached.", epoch);
                    self.distribute_epoch_rewards(epoch).await?; // Distribute before ending epoch
                    vs_write_guard.end_epoch_transition();
                }
                return Ok(());
            }
        }
        drop(proposals_guard); // Release proposals read lock

        // If not finalized, and max rounds reached, reset round and new proposer (implicitly by VRF in next loop)
        let mut vs_write_guard = self.validator_set.write().await;
        if round + 1 >= MAX_ROUNDS_PER_BLOCK {
            println!("Max rounds reached for E:{}, R:{}. Resetting round.", epoch, round);
            vs_write_guard.current_round = 0;
            // Potentially penalize validators who didn't vote for the dominant proposal if one existed
            // This is complex: need to identify dominant proposal if any, then those who didn't vote for it.
            // For now, liveness faults (missing >50% votes in epoch) are handled at epoch end.
        } else {
            vs_write_guard.current_round = round + 1;
        }
        Ok(())
    }
    
    async fn distribute_epoch_rewards(&self, epoch: u64) -> Result<()> {
        let vs_guard = self.validator_set.read().await;
        let mut reward_manager_guard = self.reward_manager.write().await;

        let mut validator_stats: Vec<(Address, u128, u64, u64)> = Vec::new();
        let total_votes_in_epoch = EPOCH_LENGTH * MAX_ROUNDS_PER_BLOCK; // Approximation

        for validator_detail in vs_guard.get_active_validators_details() {
            let missed_votes = validator_detail.missed_votes_in_epoch;
            let votes_cast = total_votes_in_epoch.saturating_sub(missed_votes);
            validator_stats.push((
                validator_detail.pubkey.clone(), // Assuming Address can be derived or pubkey is Address
                validator_detail.stake,
                validator_detail.proposed_blocks_in_epoch,
                votes_cast,
            ));
            
            // Liveness fault slashing check
            if missed_votes * 2 > total_votes_in_epoch { // Missed > 50%
                 // This needs to be called on a mutable vs_guard, so can't do it here directly.
                 // Slashing should ideally happen before reward calculation.
                 // Or, rewards are calculated, then slashing applied to the validator's balance/stake.
                 println!("Liveness fault detected for {:?} (missed {} / {} votes)", validator_detail.pubkey, missed_votes, total_votes_in_epoch);
                 // Consider queueing this slash to be applied by a write lock section.
            }
        }
        drop(vs_guard); // Release read lock

        let total_active_stake;
        {
            let vs_read_again = self.validator_set.read().await;
            total_active_stake = vs_read_again.total_stake_active;
        }

        reward_manager_guard.calculate_rewards(epoch, &validator_stats, total_active_stake)?;
        println!("Rewards calculated for Epoch {}", epoch);
        // Actual transfer of rewards to validator accounts would happen here or be queued.
        Ok(())
    }

    // Methods for handling StakeTx, UnstakeTx, SlashTx from network/RPC
    pub async fn handle_stake_tx(&self, tx: StakeTx) -> Result<()> {
        // TODO: Validate StakeTx signature and nonce against an account model
        let mut vs_guard = self.validator_set.write().await;
        vs_guard.register_validator(tx.validator_address, tx.validator_pubkey, tx.amount)
            .map_err(|e| e.into()) // Convert String error to crate::Error
    }

    pub async fn handle_unstake_tx(&self, tx: UnstakeTx) -> Result<u64> {
        // TODO: Validate UnstakeTx signature and nonce
        let mut vs_guard = self.validator_set.write().await;
        let target_epoch = vs_guard.initiate_unstake(&tx.validator_address, tx.amount)
            .map_err(|e| e.into())?;
        // Update the transaction with the target epoch for user feedback or storage
        Ok(target_epoch)
    }
    
    // This method would be called if a node constructs and broadcasts a SlashTx.
    // The engine itself handles direct slashing on detection for now.
    pub async fn handle_slash_tx(&self, tx: SlashTx) -> Result<()> {
        // 1. Verify evidence in tx (this is complex)
        // For example, if evidence is two conflicting proposals/votes, verify their signatures
        // and that they indeed conflict (e.g., same proposer/voter, same epoch/round, different hash).
        // To prevent replay attacks, hash the evidence and check if already processed.
        let evidence_hash = crate::crypto::hash_bytes(&serde_json::to_vec(&tx.evidence)?);
        {
            let mut processed_guard = self.processed_slash_evidence.write().await;
            if processed_guard.contains(&evidence_hash) {
                return Err("Slash evidence already processed".into());
            }
            processed_guard.insert(evidence_hash);
        }

        // 2. If evidence is valid, slash the offender
        let slash_percentage = if self.is_double_sign_evidence(&tx.evidence) { 
            SLASH_DOUBLE_SIGN_PERCENTAGE 
        } else if self.is_liveness_fault_evidence(&tx.evidence) { 
            SLASH_DOWNTIME_PERCENTAGE 
        } else {
            return Err("Unknown slash evidence type".into());
        };
        
        let slashed_amount = {
            let mut vs_guard = self.validator_set.write().await;
            vs_guard.slash_validator(&tx.offender, slash_percentage)?
        };

        // 3. Reward the reporter
        {
            let mut reward_manager_guard = self.reward_manager.write().await;
            let current_epoch = self.validator_set.read().await.current_epoch;
            reward_manager_guard.process_slash_bounty(
                tx.reporter, 
                tx.offender, 
                current_epoch, 
                slashed_amount
            )?;
        }
        Ok(())
    }

    fn is_double_sign_evidence(&self, evidence: &[ConsensusMsg]) -> bool {
        if evidence.len() != 2 { return false; }

        match (&evidence[0], &evidence[1]) {
            (ConsensusMsg::Proposal(p1), ConsensusMsg::Proposal(p2)) => {
                // Check: Same proposer, same epoch, same round, different block hashes
                p1.proposer_pubkey == p2.proposer_pubkey &&
                p1.epoch == p2.epoch &&
                p1.round == p2.round &&
                p1.block_hash != p2.block_hash
                // TODO: Optionally, verify signatures on p1 and p2 here, though they should have been verified when first received.
            },
            (ConsensusMsg::Vote(v1), ConsensusMsg::Vote(v2)) => {
                // Check: Same voter, same epoch, same round, different block hashes (vote equivocation)
                v1.voter_pubkey == v2.voter_pubkey &&
                v1.epoch == v2.epoch &&
                v1.round == v2.round &&
                v1.block_hash != v2.block_hash
                // TODO: Optionally, verify signatures on v1 and v2.
            }
            _ => false, // Not two proposals or two votes
        }
    }

    fn is_liveness_fault_evidence(&self, evidence: &[ConsensusMsg]) -> bool {
        // Liveness fault evidence is trickier. It might be a claim that a validator
        // missed X out of Y voting opportunities. This would require a proof structure containing:
        // 1. The epoch in question.
        // 2. The validator accused.
        // 3. A list of block proposals (or their hashes) they failed to vote on.
        // 4. Proof that these proposals were valid and reached consensus (or should have been voted on).
        // 5. Signatures from a supermajority attesting to this observation.

        // For now, this is complex to verify from generic ConsensusMsg. 
        // The engine handles liveness slashing internally at epoch end based on its own vote tracking.
        // A SlashTx for liveness would need a more specialized evidence structure.
        // Let's assume for now that a SlashTx cannot easily prove liveness faults with just ConsensusMsgs.
        if evidence.is_empty() { return false; } // Placeholder to use evidence
        
        // Example: if evidence contained a special LivenessReportMsg (not yet defined)
        // match &evidence[0] {
        //     ConsensusMsg::LivenessReport(report) => { ... verify report ... }
        //     _ => false
        // }
        false // Placeholder: True liveness fault evidence for SlashTx is non-trivial
    }

    // Placeholder for fetching the previous block hash
    // This would typically involve querying the blockchain state / database
    async fn get_previous_block_hash(&self, _epoch: u64, _round: u64) -> Vec<u8> {
        // In a real scenario, this would be the hash of the last finalized block.
        // For round 0 of epoch 0, it might be a genesis hash.
        // Needs access to blockchain state.
        vec![0u8; 32] // Return a dummy 32-byte hash for now
    }

    // ... (get_validator_reward, get_epoch_rewards, get_total_rewards methods as previously defined) ...
}

// Helper for short pubkey display
impl KeyPair {
    fn public_key_short(&self) -> String {
        let pk_hex = hex::encode(self.public_key());
        format!("{}...{}", &pk_hex[..4], &pk_hex[pk_hex.len()-4..])
    }
    fn public_key_short_from_bytes(pk_bytes: &[u8]) -> String {
        let pk_hex = hex::encode(pk_bytes);
        if pk_hex.len() > 8 {
            format!("{}...{}", &pk_hex[..4], &pk_hex[pk_hex.len()-4..])
        } else {
            pk_hex
        }
    }
    // Assuming Address is derived from PublicKey, e.g. last 20 bytes or a specific hash
    // This needs to be consistent with how Address is defined and used.
    // For now, let's assume PublicKey itself can be used as an address string or a hash of it.
    fn public_key_address(&self) -> Address {
        // Placeholder: In a real system, Address would be derived correctly.
        // For example, hex encode the public key.
        hex::encode(self.public_key())
    }
    fn public_key_address_from_bytes(pk_bytes: &[u8]) -> Result<Address> {
        Ok(hex::encode(pk_bytes))
    }
} 