#[cfg(test)]
mod vm_execution_tests {
    use crate::blockchain::block::{Block, BlockHeader};
    use crate::blockchain::transaction::{Transaction, TransactionError};
    use crate::blockchain::state::{State, StateError, AccountState};
    use crate::crypto::{hash_data, PqcKeyPair, QuantumKeyPair, hybrid::HybridKey, PublicKey, Hash};
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn mock_hybrid_keypair() -> HybridKey {
        let pqc_kp = PqcKeyPair::generate(); 
        let quantum_kp = QuantumKeyPair::generate();
        HybridKey::new(pqc_kp, quantum_kp)
    }

    fn mock_public_key(kp: &HybridKey) -> PublicKey {
        kp.public_key()
    }

    #[test]
    fn test_vm_store_and_load_execution() {
        let mut state = State::new();

        let contract_creator_kp = mock_hybrid_keypair();
        let contract_creator_pk = mock_public_key(&contract_creator_kp);
        
        // The contract "address" will be the transaction recipient for simplicity in this test
        let contract_kp = mock_hybrid_keypair(); // Not strictly needed if contract has no keys itself
        let contract_pk = mock_public_key(&contract_kp);

        // Fund the contract creator's account so they can pay fees
        let mut creator_account_state = AccountState::new(1000);
        state.balances.insert(contract_creator_pk.clone(), creator_account_state);

        let assembly_source = r#"
            PUSH 42
            STORE x
            LOAD x
            PUSH 1
            ADD     ; Result 43 on stack
            STOP
        "#;

        // Create a transaction that deploys/runs this code
        // Sender is creator, recipient is the contract address
        let tx = Transaction::create_and_sign(
            contract_creator_pk.clone(), // Sender
            contract_pk.clone(),         // Recipient (contract address)
            0,                           // Amount (e.g., for contract deployment, no direct value transfer here)
            10,                          // Fee
            false,                       // Not private
            Some(assembly_source),       // Contract source code
            &contract_creator_kp,        // Signer
        ).expect("Transaction creation failed");

        // Create a block with this transaction
        let prev_hash = Hash([0u8; 32]);
        let block_header = BlockHeader {
            index: 1,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            previous_hash: prev_hash,
            merkle_root: Hash([0u8;32]), // Placeholder for test, real one would be calculated
            difficulty: 0, // Placeholder
            nonce: 0, // Placeholder
        };
        let block = Block {
            header: block_header,
            transactions: vec![tx.clone()],
            // validator_signature: None, // Assuming this might exist
        };
        // Manually set merkle_root if block has a method for it or re-hash
        // For this test, apply_block_for_test might not strictly need it if it only processes txns.

        // Apply the block to the state
        match state.apply_block_for_test(&block) {
            Ok(_) => (),
            Err(e) => panic!("apply_block_for_test failed: {:?}", e),
        }

        // Verify storage
        // The storage is associated with the contract_pk (tx.recipient)
        let stored_value = state.get_account_storage(&contract_pk, "x");
        assert_eq!(stored_value, Some(42), "Value for 'x' should be 42 in contract storage");

        // Optional: Verify the stack of the VM if the VM instance were accessible after run
        // For this test, checking the persisted storage is the main goal.
        // If apply_transaction returned the VM state or similar, we could check stack.
        // For example, after the ADD, the top of stack should be 43.
    }
} 