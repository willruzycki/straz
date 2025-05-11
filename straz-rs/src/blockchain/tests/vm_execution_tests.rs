#[cfg(test)]
mod vm_execution_tests {
    use crate::blockchain::block::{Block, BlockHeader};
    use crate::blockchain::transaction::{Transaction, TransactionError};
    use crate::blockchain::state::{State, StateError, AccountState};
    use crate::crypto::{hash_data, PqcKeyPair, QuantumKeyPair, hybrid::HybridKey, PublicKey, Hash};
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Constants for gas costs (mirroring vm/execution.rs for test calculations)
    const GAS_PUSH: u64 = 1;
    const GAS_POP: u64 = 1;
    const GAS_ADD: u64 = 1;
    const GAS_STORE: u64 = 5;
    const GAS_LOAD: u64 = 5;
    const GAS_STOP: u64 = 0;
    const GAS_GET_BLOCK_NUMBER: u64 = 3;
    const GAS_GET_SENDER: u64 = 3;

    fn mock_hybrid_keypair() -> HybridKey {
        let pqc_kp = PqcKeyPair::generate(); 
        let quantum_kp = QuantumKeyPair::generate();
        HybridKey::new(pqc_kp, quantum_kp)
    }

    fn mock_public_key(kp: &HybridKey) -> PublicKey {
        kp.public_key()
    }

    #[test]
    fn test_vm_store_and_load_execution_updated() {
        let mut state = State::new();

        let contract_creator_kp = mock_hybrid_keypair();
        let contract_creator_pk = mock_public_key(&contract_creator_kp);
        
        let contract_kp = mock_hybrid_keypair(); 
        let contract_pk = mock_public_key(&contract_kp);

        let initial_creator_balance: u128 = 1_000_000;
        state.balances.insert(contract_creator_pk.clone(), AccountState::new(initial_creator_balance));

        let assembly_source = r#"
            PUSH 42
            STORE x
            LOAD x
            PUSH 1
            ADD     ; Result 43 on stack
            STOP
        "#;

        let gas_limit: u64 = 100_000;
        let gas_price: u128 = 1;
        let fee: u64 = 10;

        let tx = Transaction::create_and_sign(
            contract_creator_pk.clone(), 
            contract_pk.clone(),         
            0,                           
            fee,                          
            false,                       
            Some(assembly_source),       
            &contract_creator_kp,
            gas_limit,
            gas_price,       
        ).expect("Transaction creation failed");

        match state.apply_transaction(&tx) {
            Ok(_) => (),
            Err(e) => panic!("apply_transaction failed: {:?}", e),
        }

        let stored_value = state.get_account_storage(&contract_pk, "x");
        assert_eq!(stored_value, Some(42), "Value for 'x' should be 42 in contract storage");
        
        let expected_gas_used = GAS_PUSH + GAS_STORE + GAS_LOAD + GAS_PUSH + GAS_ADD + GAS_STOP;
        let expected_cost = fee as u128 + (expected_gas_used as u128 * gas_price);
        assert_eq!(state.get_balance(&contract_creator_pk), initial_creator_balance - expected_cost);
        assert_eq!(state.balances.get(&contract_creator_pk).unwrap().nonce, 1);
    }

    #[test]
    fn test_vm_success_with_gas() {
        let mut state = State::new();
        let sender_kp = mock_hybrid_keypair();
        let sender_pk = mock_public_key(&sender_kp);
        let contract_pk = mock_public_key(&mock_hybrid_keypair());

        let initial_sender_balance: u128 = 1_000_000;
        state.balances.insert(sender_pk.clone(), AccountState::new(initial_sender_balance));

        let assembly_source = "PUSH 10; PUSH 20; ADD; STORE result; STOP";
        let gas_limit: u64 = 100;
        let gas_price: u128 = 2;
        let fee: u64 = 5;
        let amount: u64 = 0;

        let tx = Transaction::create_and_sign(
            sender_pk.clone(), contract_pk.clone(), amount, fee, false, 
            Some(assembly_source), &sender_kp, gas_limit, gas_price
        ).unwrap();

        assert!(state.apply_transaction(&tx).is_ok());

        let expected_gas_used = GAS_PUSH + GAS_PUSH + GAS_ADD + GAS_STORE + GAS_STOP;
        assert!(expected_gas_used <= gas_limit, "Test setup error: gas_limit too low for ops");

        let total_cost = amount as u128 + fee as u128 + (expected_gas_used as u128 * gas_price);
        assert_eq!(state.get_balance(&sender_pk), initial_sender_balance - total_cost);
        assert_eq!(state.get_account_storage(&contract_pk, "result"), Some(30));
        assert_eq!(state.balances.get(&sender_pk).unwrap().nonce, 1);
    }

    #[test]
    fn test_vm_out_of_gas() {
        let mut state = State::new();
        let sender_kp = mock_hybrid_keypair();
        let sender_pk = mock_public_key(&sender_kp);
        let contract_pk = mock_public_key(&mock_hybrid_keypair());

        let initial_sender_balance: u128 = 1_000_000;
        state.balances.insert(sender_pk.clone(), AccountState::new(initial_sender_balance));
        
        // PUSH + PUSH + ADD + STORE + STOP = 1+1+1+5+0 = 8 gas units
        let assembly_source = "PUSH 10; PUSH 20; ADD; STORE result; STOP"; 
        let gas_limit: u64 = 7; // Set gas_limit just below required
        let gas_price: u128 = 1;
        let fee: u64 = 5;
        let amount: u64 = 0;

        let tx = Transaction::create_and_sign(
            sender_pk.clone(), contract_pk.clone(), amount, fee, false,
            Some(assembly_source), &sender_kp, gas_limit, gas_price
        ).unwrap();

        // apply_transaction should still be Ok, but OutOfGas error is handled internally
        // and full gas_limit is charged.
        assert!(state.apply_transaction(&tx).is_ok());

        let total_cost = amount as u128 + fee as u128 + (gas_limit as u128 * gas_price);
        assert_eq!(state.get_balance(&sender_pk), initial_sender_balance - total_cost);
        // Storage should not be modified due to OutOfGas
        assert_eq!(state.get_account_storage(&contract_pk, "result"), None);
        assert_eq!(state.balances.get(&sender_pk).unwrap().nonce, 1);
    }

    #[test]
    fn test_insufficient_balance_for_max_gas() {
        let mut state = State::new();
        let sender_kp = mock_hybrid_keypair();
        let sender_pk = mock_public_key(&sender_kp);
        let contract_pk = mock_public_key(&mock_hybrid_keypair());

        let assembly_source = "PUSH 1; STOP";
        let gas_limit: u64 = 100;
        let gas_price: u128 = 1;
        let fee: u64 = 5;
        let amount: u64 = 0;
        
        let required_balance = amount as u128 + fee as u128 + (gas_limit as u128 * gas_price);
        let initial_sender_balance = required_balance - 1; // Just not enough

        state.balances.insert(sender_pk.clone(), AccountState::new(initial_sender_balance));

        let tx = Transaction::create_and_sign(
            sender_pk.clone(), contract_pk.clone(), amount, fee, false,
            Some(assembly_source), &sender_kp, gas_limit, gas_price
        ).unwrap();

        match state.apply_transaction(&tx) {
            Err(StateError::InsufficientBalance) => (),
            _ => panic!("Expected InsufficientBalance error"),
        }

        assert_eq!(state.get_balance(&sender_pk), initial_sender_balance); // Balance unchanged
        assert_eq!(state.get_account_storage(&contract_pk, "result"), None); // Storage unchanged
        assert_eq!(state.balances.get(&sender_pk).unwrap().nonce, 0); // Nonce unchanged
    }

    #[test]
    fn test_context_opcodes_get_sender_block_number() {
        let mut state = State::new();
        let sender_kp = mock_hybrid_keypair();
        let sender_pk = mock_public_key(&sender_kp);
        let contract_pk = mock_public_key(&mock_hybrid_keypair());

        let initial_sender_balance: u128 = 1_000_000;
        state.balances.insert(sender_pk.clone(), AccountState::new(initial_sender_balance));

        let assembly_source = "GETSENDER; STORE s_hash; GETBLOCKNUMBER; STORE b_num; STOP";
        let gas_limit: u64 = 100;
        let gas_price: u128 = 1;
        let fee: u64 = 5;

        let tx = Transaction::create_and_sign(
            sender_pk.clone(), contract_pk.clone(), 0, fee, false,
            Some(assembly_source), &sender_kp, gas_limit, gas_price
        ).unwrap();

        assert!(state.apply_transaction(&tx).is_ok());

        // Calculate expected sender hash (first 8 bytes of hash of sender_pk.key)
        // Assuming PublicKey.key holds the bytes for hashing, matching vm/execution.rs GetSender
        let sender_key_bytes = &sender_pk.key; 
        let expected_sender_hash_full = hash_data(sender_key_bytes);
        let mut expected_sender_val_bytes = [0u8; 8];
        expected_sender_val_bytes.copy_from_slice(&expected_sender_hash_full.0[0..8]);
        let expected_sender_val_i64 = i64::from_be_bytes(expected_sender_val_bytes);

        assert_eq!(state.get_account_storage(&contract_pk, "s_hash"), Some(expected_sender_val_i64));
        assert_eq!(state.get_account_storage(&contract_pk, "b_num"), Some(0), "Block number should be 0 (placeholder)");

        let expected_gas_used = GAS_GET_SENDER + GAS_STORE + GAS_GET_BLOCK_NUMBER + GAS_STORE + GAS_STOP;
        let total_cost = fee as u128 + (expected_gas_used as u128 * gas_price);
        assert_eq!(state.get_balance(&sender_pk), initial_sender_balance - total_cost);
        assert_eq!(state.balances.get(&sender_pk).unwrap().nonce, 1);
    }
} 