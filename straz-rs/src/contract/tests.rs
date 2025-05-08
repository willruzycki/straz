use super::*;
use crate::crypto::KeyPair;

#[test]
fn test_vm_arithmetic() {
    let mut vm = QRVM::new();
    
    // Test addition
    vm.stack.push(5u64.to_le_bytes().to_vec());
    vm.stack.push(3u64.to_le_bytes().to_vec());
    vm.execute_op(&OpCode::Add).unwrap();
    assert_eq!(vm.pop_u64().unwrap(), 8);
    
    // Test multiplication
    vm.stack.push(4u64.to_le_bytes().to_vec());
    vm.stack.push(3u64.to_le_bytes().to_vec());
    vm.execute_op(&OpCode::Mul).unwrap();
    assert_eq!(vm.pop_u64().unwrap(), 12);
    
    // Test division
    vm.stack.push(10u64.to_le_bytes().to_vec());
    vm.stack.push(2u64.to_le_bytes().to_vec());
    vm.execute_op(&OpCode::Div).unwrap();
    assert_eq!(vm.pop_u64().unwrap(), 5);
}

#[test]
fn test_vm_storage() {
    let mut vm = QRVM::new();
    
    // Store value
    vm.stack.push(b"key".to_vec());
    vm.stack.push(b"value".to_vec());
    vm.execute_op(&OpCode::SStore).unwrap();
    
    // Load value
    vm.stack.push(b"key".to_vec());
    vm.execute_op(&OpCode::SLoad).unwrap();
    assert_eq!(vm.pop_bytes().unwrap(), b"value");
}

#[test]
fn test_vm_crypto() {
    let mut vm = QRVM::new();
    let keypair = KeyPair::new().unwrap();
    let message = b"test message";
    
    // Test hashing
    vm.stack.push(message.to_vec());
    vm.execute_op(&OpCode::Hash).unwrap();
    let hash = vm.pop_bytes().unwrap();
    assert_eq!(hash.len(), 32); // SHA3-256 hash length
    
    // Test signing and verification
    vm.stack.push(message.to_vec());
    vm.execute_op(&OpCode::Sign).unwrap();
    let signature = vm.pop_bytes().unwrap();
    
    vm.stack.push(message.to_vec());
    vm.stack.push(signature);
    vm.execute_op(&OpCode::Verify).unwrap();
    assert_eq!(vm.pop_u64().unwrap(), 1);
}

#[test]
fn test_vm_control_flow() {
    let mut vm = QRVM::new();
    
    // Test conditional jump
    vm.stack.push(1u64.to_le_bytes().to_vec()); // condition
    vm.stack.push(2u64.to_le_bytes().to_vec()); // target
    vm.execute_op(&OpCode::JumpI).unwrap();
    assert_eq!(vm.pc, 2);
    
    // Test unconditional jump
    vm.stack.push(0u64.to_le_bytes().to_vec()); // target
    vm.execute_op(&OpCode::Jump).unwrap();
    assert_eq!(vm.pc, 0);
}

#[test]
fn test_vm_stack_operations() {
    let mut vm = QRVM::new();
    
    // Test push and pop
    vm.execute_op(&OpCode::Push(vec![1, 2, 3])).unwrap();
    vm.execute_op(&OpCode::Pop).unwrap();
    assert!(vm.stack.is_empty());
    
    // Test dup
    vm.execute_op(&OpCode::Push(vec![1, 2, 3])).unwrap();
    vm.execute_op(&OpCode::Dup(0)).unwrap();
    assert_eq!(vm.stack.len(), 2);
    assert_eq!(vm.stack[0], vm.stack[1]);
    
    // Test swap
    vm.stack.clear();
    vm.execute_op(&OpCode::Push(vec![1])).unwrap();
    vm.execute_op(&OpCode::Push(vec![2])).unwrap();
    vm.execute_op(&OpCode::Swap(1)).unwrap();
    assert_eq!(vm.stack[0], vec![2]);
    assert_eq!(vm.stack[1], vec![1]);
}

#[test]
fn test_vm_error_handling() {
    let mut vm = QRVM::new();
    
    // Test division by zero
    vm.stack.push(1u64.to_le_bytes().to_vec());
    vm.stack.push(0u64.to_le_bytes().to_vec());
    assert!(vm.execute_op(&OpCode::Div).is_err());
    
    // Test stack underflow
    assert!(vm.execute_op(&OpCode::Pop).is_err());
    
    // Test invalid jump target
    vm.stack.push(1000u64.to_le_bytes().to_vec());
    assert!(vm.execute_op(&OpCode::Jump).is_err());
}

#[test]
fn test_vm_contract_execution() {
    let mut vm = QRVM::new();
    let contract = Contract {
        address: vec![1, 2, 3],
        code: vec![
            OpCode::Push(vec![1]),
            OpCode::Push(vec![2]),
            OpCode::Add,
            OpCode::Stop,
        ],
        storage: HashMap::new(),
        owner: vec![4, 5, 6],
        balance: 100,
        nonce: 0,
        is_private: false,
    };
    
    vm.load_contract(&contract);
    let result = vm.execute().unwrap();
    assert!(result.is_empty());
    assert!(!vm.running);
} 