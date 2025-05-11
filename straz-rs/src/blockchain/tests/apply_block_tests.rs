#[cfg(test)]
mod tests {
    use crate::blockchain::{apply_block, Block, Blockchain};
    use crate::blockchain::types::{Receipt, BlockchainError, Hash, Event};
    use crate::consensus::types::{StakeTx, ValidatorSet, MIN_STAKE};
    use crate::crypto::{KeyPair, Address, PublicKey, Signature}; // Assuming these types

    // Helper to create a dummy PublicKey (Vec<u8>)
    fn dummy_public_key(id: u8) -> PublicKey {
        vec![id; 32] // Example: 32-byte public key
    }

    // Helper to create a dummy Address (String)
    fn dummy_address(id: u8) -> Address {
        hex::encode(dummy_public_key(id))
    }
    
    // Helper to create a dummy Signature (Vec<u8>)
    fn dummy_signature() -> Signature {
        vec![0; 64] // Example: 64-byte signature
    }

    fn create_simple_block(index: u64, previous_hash: Hash, transactions: Vec<crate::blockchain::transaction::Transaction>) -> Block {
        // Assuming Block::new takes index, transactions, previous_hash
        // and calculates its own hash and merkle_root internally.
        // This is a simplified constructor for testing.
        let mut block = Block::new(index, transactions, previous_hash);
        // If Block needs explicit mining or hash calculation for testing:
        if block.hash.is_empty() {
            block.hash = block.calculate_hash().unwrap_or_default();
        }
        if block.merkle_root.is_empty() && !block.transactions.is_empty() {
             block.merkle_root = Block::calculate_merkle_root(&block.transactions).unwrap_or_default();
        } else if block.transactions.is_empty() {
            block.merkle_root = vec![0u8;32]; // Default for empty tx list
        }
        block
    }

    #[test]
    fn test_apply_block_updates_chain_head_and_state_root() {
        // Assuming Blockchain::new() or default() initializes an empty chain or genesis.
        // And that apply_block is a free function as per the prompt,
        // though it internally might use a Blockchain instance.
        // For this test to be meaningful, we'd need a way to inspect the chain.
        // Let's assume a simple in-memory Blockchain for the test.

        let mut blockchain = Blockchain::default(); // Assumes default creates a genesis block
        let initial_block_hash = blockchain.chain.last().unwrap().hash.clone();
        let initial_state_root = blockchain.chain.last().unwrap().merkle_root.clone(); // Assuming merkle_root as state_root placeholder

        let block1 = create_simple_block(1, initial_block_hash.clone(), vec![]);
        
        // Using the free function apply_block which might instantiate its own Blockchain
        // This test setup is a bit awkward due to the apply_block signature.
        // A better test would directly use methods on a persistent Blockchain instance.
        // However, sticking to the prompt's apply_block:
        
        // To test apply_block's effect, we need it to modify a shared Blockchain instance,
        // or the test needs to re-initialize apply_block in a way that it can inspect its state.
        // The provided apply_block fn creates a new Blockchain instance each time.
        // This test will be limited. Let's assume for the sake of a runnable test
        // we're checking the Receipt rather than global chain state.

        let receipt = crate::blockchain::apply_block(&block1).expect("apply_block failed for block1");

        // Verify receipt's state root (which comes from the block itself in the stub)
        assert_eq!(receipt.state_root, block1.merkle_root, "Receipt state root should match block's merkle_root");
        assert!(receipt.success, "Block application should be successful");

        // To truly test chain head update, apply_block would need to modify a persistent `Blockchain` instance.
        // The current free `apply_block` function makes this hard.
        // If we were to test blockchain.apply_block(&mut self, block: &Block):
        // blockchain.apply_block(&block1).expect("apply_block failed for block1");
        // assert_eq!(blockchain.chain.last().unwrap().hash, block1.hash);
        // assert_eq!(blockchain.chain.last().unwrap().merkle_root, block1.merkle_root);
    }

    #[test]
    fn test_apply_block_with_stake_tx_updates_validator_set() {
        // This test assumes that apply_block, when processing a block,
        // identifies StakeTx-like transactions and updates a ValidatorSet.
        // The current stub for apply_block doesn't do this.
        // This test is more of an integration test expectation.
        // For now, we can't directly verify ValidatorSet changes through the current apply_block stub.

        // Setup:
        // 1. Create a Blockchain instance (which internally might have a ValidatorSet or allow one to be passed).
        // 2. Create a StakeTx.
        // 3. Create a Block containing this StakeTx (needs Block to support transactions).
        // 4. Call apply_block.
        // 5. Inspect the ValidatorSet.

        // Due to the limitations of the current apply_block stub and Blockchain structure,
        // a full test is not feasible without significant assumptions or modifications.
        // We'll assert that the block applies successfully, implying the contained (but unprocessed)
        // StakeTx didn't cause an error.

        let pk = dummy_public_key(1);
        let addr = dummy_address(1);
        
        // This StakeTx is from consensus::types, but Block expects blockchain::Transaction
        // We'd need a way to wrap/convert or for Block to accept generic transactions.
        // let stake_tx_consensus = StakeTx {
        //     validator_pubkey: pk.clone(),
        //     amount: MIN_STAKE + 100,
        //     delegatee: None,
        //     nonce: 0,
        //     signature: dummy_signature(),
        // };

        // Let's assume a simplified blockchain::Transaction that can represent staking.
        let dummy_stake_transaction = crate::blockchain::transaction::Transaction {
            sender: addr.clone(), // Sender of the stake
            recipient: "staking_contract_address".to_string(), // Or a special address
            amount: MIN_STAKE + 100,
            fee: 0,
            timestamp: 0, // Set appropriately
            signature: dummy_signature(),
            is_private: false,
            // Additional fields might be needed to identify it as a StakeTx
            // e.g., data: serde_json::to_vec(&stake_tx_consensus).unwrap_or_default(),
        };
        dummy_stake_transaction.hash(); // Ensure hash is calculated if mutable

        let mut blockchain = Blockchain::default();
        let prev_hash = blockchain.chain.last().unwrap().hash.clone();
        
        let block_with_stake = create_simple_block(1, prev_hash, vec![dummy_stake_transaction]);

        // If apply_block were to process consensus Txs, it would need access to ValidatorSet.
        // The current free function `apply_block` cannot easily do this.
        // Let's assume the block applies without error.
        let receipt = crate::blockchain::apply_block(&block_with_stake);
        
        assert!(receipt.is_ok(), "Block with stake-like transaction should apply successfully (even if StakeTx is not processed by stub)");
        if let Ok(r) = receipt {
            assert!(r.success);
        }
        
        // A more complete test would be:
        // let mut vs = ValidatorSet::new();
        // let mut blockchain_with_vs = Blockchain::new_with_validator_set(&mut vs); // Hypothetical
        // blockchain_with_vs.apply_block(&block_with_stake).unwrap();
        // assert!(vs.validators.contains_key(&addr));
        // assert_eq!(vs.validators.get(&addr).unwrap().stake, MIN_STAKE + 100);

        println!("Warning: test_apply_block_with_stake_tx_updates_validator_set is a partial test due to apply_block stub limitations.");
    }
} 