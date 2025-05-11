use crate::Result;
use crate::blockchain::Block;
use std::collections::HashMap;
use crate::blockchain::transaction::{Transaction, TransactionError};
use crate::crypto::{PublicKey, Hash};
use crate::vm::execution::{VirtualMachine, VmExecutionError};

#[derive(Debug, Clone)]
pub struct AccountState {
    pub balance: u64,
    pub nonce: u64,
    pub storage: HashMap<String, i64>,
}

impl AccountState {
    fn new(balance: u64) -> Self {
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
    total_supply: u64,
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
            total_supply: 1_000_000_000,
        }
    }
    
    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), StateError> {
        let sender_account = self.balances.entry(tx.sender.clone()).or_insert_with(|| AccountState::new(0));

        if sender_account.balance < tx.amount + tx.fee {
            return Err(StateError::InsufficientBalance);
        }

        sender_account.balance -= tx.amount + tx.fee;

        let recipient_account = self.balances.entry(tx.recipient.clone()).or_insert_with(|| AccountState::new(0));
        recipient_account.balance += tx.amount;

        if !tx.bytecode.is_empty() {
            let mut vm = VirtualMachine::new(tx.bytecode.clone());
            
            let contract_account_state = self.balances.entry(tx.recipient.clone()).or_insert_with(|| AccountState::new(0));
            vm.set_storage(contract_account_state.storage.clone());

            vm.run(tx).map_err(StateError::VmError)?;
            
            contract_account_state.storage = vm.consume_storage(); 
        }

        Ok(())
    }

    pub fn apply_block_for_test(&mut self, block: &Block) -> Result<(), StateError> {
        for tx in &block.transactions {
            self.apply_transaction(tx)?;
        }
        Ok(())
    }

    pub fn get_balance(&self, pub_key: &PublicKey) -> u64 {
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

    #[test]
    fn test_apply_simple_transaction() {
        let mut state = State::new();
        let kp1 = mock_hybrid_keypair();
        let pk1 = mock_public_key(&kp1);
        let kp2 = mock_hybrid_keypair();
        let pk2 = mock_public_key(&kp2);

        state.balances.insert(pk1.clone(), AccountState::new(1000));

        let tx = Transaction::create_and_sign(
            pk1.clone(),
            pk2.clone(),
            100,
            10,
            false,
            None,
            &kp1,
        ).unwrap();

        assert!(state.apply_transaction(&tx).is_ok());
        assert_eq!(state.get_balance(&pk1), 1000 - 100 - 10);
        assert_eq!(state.get_balance(&pk2), 100);
    }

    #[test]
    fn test_insufficient_balance() {
        let mut state = State::new();
        let kp1 = mock_hybrid_keypair();
        let pk1 = mock_public_key(&kp1);
        let kp2 = mock_hybrid_keypair();
        let pk2 = mock_public_key(&kp2);

        let tx = Transaction::create_and_sign(
            pk1.clone(),
            pk2.clone(),
            100,
            10,
            false,
            None,
            &kp1,
        ).unwrap();

        match state.apply_transaction(&tx) {
            Err(StateError::InsufficientBalance) => (),
            _ => panic!("Expected InsufficientBalance error"),
        }
    }
} 