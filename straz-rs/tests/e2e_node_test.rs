"""#[cfg(test)]
mod e2e_node_tests {
    use straz_rs::blockchain::block::Block;
    use straz_rs::blockchain::transaction::Transaction;
    use straz_rs::blockchain::state::{State, AccountState};
    use straz_rs::blockchain::Blockchain; // Assuming Blockchain can be instantiated for tests
    use straz_rs::crypto::{PqcKeyPair, QuantumKeyPair, hybrid::HybridKey, PublicKey, Hash};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Gas cost constants from vm/execution.rs (or blockchain/tests/vm_execution_tests.rs)
    const GAS_PUSH: u64 = 1;
    const GAS_STOP: u64 = 0;

    fn mock_hybrid_keypair(seed: u8) -> HybridKey {
        // Simple way to get different keys for tests; real crypto would not use seed like this
        // For now, assuming PqcKeyPair and QuantumKeyPair have a way to be varied or are random enough
        let pqc_kp = PqcKeyPair::generate(); 
        let quantum_kp = QuantumKeyPair::generate();
        // To make them somewhat deterministic for simple test runs if needed, 
        // one might use a seeded RNG if the underlying crypto libs support it.
        // For this test, true randomness is fine.
        HybridKey::new(pqc_kp, quantum_kp)
    }

    fn mock_public_key(kp: &HybridKey) -> PublicKey {
        kp.public_key()
    }

    #[tokio::test]
    async fn test_e2e_proposer_fee_distribution() {
        // 1. Setup: Proposer (Node A) and Sender (Node B)
        let node_a_kp = Arc::new(mock_hybrid_keypair(1));
        let node_a_pk = mock_public_key(&node_a_kp);

        let node_b_kp = Arc::new(mock_hybrid_keypair(2));
        let node_b_pk = mock_public_key(&node_b_kp);
        
        let contract_pk = mock_public_key(&mock_hybrid_keypair(3)); // Dummy contract address

        // 2. Initialize State and Blockchain (or just State for direct testing if Blockchain setup is complex)
        // Using State directly as Blockchain::apply_block_to_state takes &Block and updates its own Arc<RwLock<State>>.
        // For this test, we can simulate the blockchain's state management part.
        let mut state = State::new();

        let initial_balance_a: u128 = 1000;
        let initial_balance_b: u128 = 2000;
        state.balances.insert(node_a_pk.clone(), AccountState::new(initial_balance_a));
        state.balances.insert(node_b_pk.clone(), AccountState::new(initial_balance_b));

        // 3. Node B creates a transaction for a simple contract
        let assembly_source = "PUSH 1; STOP";
        let gas_limit: u64 = 10;
        let gas_price: u128 = 1;
        let tx_fee: u64 = 5; // Explicit transaction fee
        let amount_to_contract: u64 = 0;

        let tx = Transaction::create_and_sign(
            node_b_pk.clone(),           // Sender: Node B
            contract_pk.clone(),       // Recipient: Contract Address
            amount_to_contract,        
            tx_fee,                    
            false,                     // is_private
            Some(assembly_source),     
            &node_b_kp,                // Sender's keypair
            gas_limit,                 
            gas_price,                 
        ).expect("Transaction creation failed");

        // 4. Node A proposes a block with this transaction
        let block_index: u64 = 1;
        // Assuming a previous hash for simplicity; in a real chain, this comes from the blockchain instance
        let previous_hash_str = "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let block = Block::new(
            block_index,
            vec![tx.clone()],
            previous_hash_str, 
            node_a_pk.clone(), // Proposer: Node A
        );

        // 5. Apply the block to the state
        // In a real scenario, this would be blockchain.apply_block_to_state(&block).await
        // Here, we use the test utility on State or directly call apply_transaction for each tx.
        // State::apply_block_for_test is suitable here as it uses the updated apply_transaction.
        state.apply_block_for_test(&block).expect("Applying block failed");

        // 6. Assertions
        // Calculate expected gas used for "PUSH 1; STOP"
        let expected_gas_used = GAS_PUSH + GAS_STOP; // 1 + 0 = 1
        assert_eq!(expected_gas_used, 1, "Mismatch in expected gas for PUSH; STOP");

        let actual_gas_cost_paid_by_sender = expected_gas_used as u128 * gas_price;
        let total_fees_from_tx = tx_fee as u128 + actual_gas_cost_paid_by_sender;

        // Assert Node B's (sender) balance
        let expected_balance_b = initial_balance_b - (amount_to_contract as u128) - total_fees_from_tx;
        assert_eq!(state.get_balance(&node_b_pk), expected_balance_b, "Node B (sender) balance mismatch");
        assert_eq!(state.balances.get(&node_b_pk).unwrap().nonce, 1, "Node B nonce incorrect");

        // Assert Node A's (proposer) balance increased by total_fees_from_tx
        let expected_balance_a = initial_balance_a + total_fees_from_tx;
        assert_eq!(state.get_balance(&node_a_pk), expected_balance_a, "Node A (proposer) balance mismatch after earning fees");

        // Assert contract storage (optional, contract doesn't store anything here)
        // let contract_storage = state.get_account_storage(&contract_pk, "some_key");
        // assert_eq!(contract_storage, None);
    }
}
"" 