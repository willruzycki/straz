use crate::Result;
use crate::blockchain::Block;
use std::collections::HashMap;
use crate::blockchain::transaction::{Transaction, TransactionError};
use crate::crypto::{PublicKey, Hash};
use crate::vm::execution::{VirtualMachine, VmExecutionError};

#[derive(Debug, Clone)]
pub struct AccountState {
    pub balance: u128,
    pub nonce: u64,
    pub storage: HashMap<String, i64>,
}

impl AccountState {
    fn new(balance: u128) -> Self {
        AccountState {
            balance,
            nonce: 0,
            storage: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct State {
    balances: HashMap<PublicKey, AccountState>,
    total_supply: u128,
}

#[derive(Debug)]
pub enum StateError {
    InsufficientBalance,
    AccountNotFound(PublicKey),
    InvalidNonce,
    TransactionError(TransactionError),
    VmError(VmExecutionError),
    InvalidStateTransition(String),
}

impl From<TransactionError> for StateError {
    fn from(e: TransactionError) -> Self {
        StateError::TransactionError(e)
    }
}

impl From<VmExecutionError> for StateError {
    fn from(e: VmExecutionError) -> Self {
        StateError::VmError(e)
    }
}

impl State {
    pub fn new() -> Self {
        State {
            balances: HashMap::new(),
            total_supply: 1_000_000_000_000_000_000,
        }
    }
    
    pub fn apply_transaction(&mut self, tx: &Transaction, block_number: u64, proposer_pk: &PublicKey) -> Result<(), StateError> {
        let sender_pk = tx.sender.clone();
        let recipient_pk = tx.recipient.clone();

        let actual_gas_cost: u128;

        if !tx.bytecode.is_empty() {
            let max_payable_gas_cost = tx.gas_limit as u128 * tx.gas_price;
            
            let sender_account_for_check = self.balances.entry(sender_pk.clone()).or_insert_with(|| AccountState::new(0));
            if sender_account_for_check.balance < tx.amount as u128 + tx.fee as u128 + max_payable_gas_cost {
                return Err(StateError::InsufficientBalance);
            }

            let mut vm = VirtualMachine::new(tx.bytecode.clone());
            
            let contract_account_storage_ref = self.balances.entry(recipient_pk.clone()).or_insert_with(|| AccountState::new(0));
            vm.set_storage(contract_account_storage_ref.storage.clone());

            match vm.run(tx.gas_limit, block_number, &tx.sender.key) {
                Ok(gas_used) => {
                    actual_gas_cost = gas_used as u128 * tx.gas_price;
                    let contract_account_storage_mut = self.balances.entry(recipient_pk.clone()).or_insert_with(|| AccountState::new(0));
                    contract_account_storage_mut.storage = vm.consume_storage();
                }
                Err(VmExecutionError::OutOfGas) => {
                    actual_gas_cost = max_payable_gas_cost;
                }
                Err(e) => {
                    actual_gas_cost = max_payable_gas_cost;
                    return Err(StateError::VmError(e));
                }
            }
        } else {
            actual_gas_cost = 0;
            let sender_account_for_check = self.balances.entry(sender_pk.clone()).or_insert_with(|| AccountState::new(0));
            if sender_account_for_check.balance < tx.amount as u128 + tx.fee as u128 {
                return Err(StateError::InsufficientBalance);
            }
        }

        let sender_account = self.balances.entry(sender_pk.clone()).or_insert_with(|| AccountState::new(0));
        
        let total_debit_from_sender = tx.amount as u128 + tx.fee as u128 + actual_gas_cost;
        if sender_account.balance < total_debit_from_sender {
            return Err(StateError::InsufficientBalance); 
        }
        sender_account.balance -= total_debit_from_sender;

        let recipient_account = self.balances.entry(recipient_pk.clone()).or_insert_with(|| AccountState::new(0));
        recipient_account.balance += tx.amount as u128;
        
        sender_account.nonce += 1;

        let fees_to_proposer = tx.fee as u128 + actual_gas_cost;
        if fees_to_proposer > 0 {
            let proposer_account = self.balances.entry(proposer_pk.clone()).or_insert_with(|| AccountState::new(0));
            proposer_account.balance += fees_to_proposer;
        }

        Ok(())
    }

    pub fn apply_block_for_test(&mut self, block: &Block) -> Result<(), StateError> {
        for tx in &block.transactions {
            self.apply_transaction(tx, block.index, &block.proposer)?;
        }
        Ok(())
    }

    pub fn get_balance(&self, pub_key: &PublicKey) -> u128 {
        self.balances.get(pub_key).map_or(0, |acc| acc.balance)
    }
    
    pub fn get_account_storage(&self, account_pk: &PublicKey, key: &str) -> Option<i64> {
        self.balances.get(account_pk).and_then(|acc| acc.storage.get(key).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{PqcKeyPair, QuantumKeyPair, hybrid::HybridKey};
    use crate::blockchain::transaction::Transaction;

    fn mock_hybrid_keypair() -> HybridKey {
        let pqc_kp = PqcKeyPair::generate();
        let quantum_kp = QuantumKeyPair::generate();
        HybridKey::new(pqc_kp, quantum_kp)
    }

    fn mock_public_key(kp: &HybridKey) -> PublicKey {
        kp.public_key()
    }

    fn mock_proposer_pk() -> PublicKey {
        PublicKey { key: vec![1; 32], algorithm: "dummy_proposer".to_string() }
    }

    #[test]
    fn test_apply_simple_transaction() {
        let mut state = State::new();
        let kp1 = mock_hybrid_keypair();
        let pk1 = mock_public_key(&kp1);
        let kp2 = mock_hybrid_keypair();
        let pk2 = mock_public_key(&kp2);
        let proposer_pk_for_test = mock_proposer_pk();

        state.balances.insert(pk1.clone(), AccountState::new(1_000_000));
        state.balances.insert(proposer_pk_for_test.clone(), AccountState::new(0));

        let tx_fee = 10u64;
        let tx = Transaction::create_and_sign(
            pk1.clone(),
            pk2.clone(),
            100,
            tx_fee,
            false,
            None,
            &kp1,
            0,
            0
        ).unwrap();

        let block_number_for_test = 1u64;
        assert!(state.apply_transaction(&tx, block_number_for_test, &proposer_pk_for_test).is_ok());
        
        assert_eq!(state.get_balance(&pk1), 1_000_000 - 100 - tx_fee as u128);
        assert_eq!(state.get_balance(&pk2), 100);
        assert_eq!(state.get_balance(&proposer_pk_for_test), tx_fee as u128);
    }

    #[test]
    fn test_insufficient_balance() {
        let mut state = State::new();
        let kp1 = mock_hybrid_keypair();
        let pk1 = mock_public_key(&kp1);
        let kp2 = mock_hybrid_keypair();
        let pk2 = mock_public_key(&kp2);
        let proposer_pk_for_test = mock_proposer_pk();

        let tx = Transaction::create_and_sign(
            pk1.clone(),
            pk2.clone(),
            100_000,
            10,
            false,
            None,
            &kp1,
            0,
            0
        ).unwrap();
        
        let block_number_for_test = 1u64;
        match state.apply_transaction(&tx, block_number_for_test, &proposer_pk_for_test) {
            Err(StateError::InsufficientBalance) => (),
            _ => panic!("Expected InsufficientBalance error"),
        }
    }
} 