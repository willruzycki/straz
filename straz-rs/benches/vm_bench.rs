use criterion::{black_box, criterion_group, criterion_main, Criterion};
use straz_rs::contract::vm::{QRVM, OpCode};
use straz_rs::contract::Contract;
use std::collections::HashMap;

fn bench_vm_arithmetic(c: &mut Criterion) {
    let mut vm = QRVM::new();
    
    c.bench_function("vm_add", |b| {
        b.iter(|| {
            vm.stack.push(black_box(5u64.to_le_bytes().to_vec()));
            vm.stack.push(black_box(3u64.to_le_bytes().to_vec()));
            vm.execute_op(&OpCode::Add).unwrap();
            vm.stack.clear();
        })
    });
    
    c.bench_function("vm_mul", |b| {
        b.iter(|| {
            vm.stack.push(black_box(4u64.to_le_bytes().to_vec()));
            vm.stack.push(black_box(3u64.to_le_bytes().to_vec()));
            vm.execute_op(&OpCode::Mul).unwrap();
            vm.stack.clear();
        })
    });
}

fn bench_vm_storage(c: &mut Criterion) {
    let mut vm = QRVM::new();
    
    c.bench_function("vm_store", |b| {
        b.iter(|| {
            vm.stack.push(black_box(b"key".to_vec()));
            vm.stack.push(black_box(b"value".to_vec()));
            vm.execute_op(&OpCode::SStore).unwrap();
            vm.storage.clear();
        })
    });
    
    c.bench_function("vm_load", |b| {
        vm.storage.insert(b"key".to_vec(), b"value".to_vec());
        b.iter(|| {
            vm.stack.push(black_box(b"key".to_vec()));
            vm.execute_op(&OpCode::SLoad).unwrap();
            vm.stack.clear();
        })
    });
}

fn bench_vm_crypto(c: &mut Criterion) {
    let mut vm = QRVM::new();
    let message = b"test message";
    
    c.bench_function("vm_hash", |b| {
        b.iter(|| {
            vm.stack.push(black_box(message.to_vec()));
            vm.execute_op(&OpCode::Hash).unwrap();
            vm.stack.clear();
        })
    });
    
    c.bench_function("vm_sign_verify", |b| {
        b.iter(|| {
            vm.stack.push(black_box(message.to_vec()));
            vm.execute_op(&OpCode::Sign).unwrap();
            let signature = vm.pop_bytes().unwrap();
            
            vm.stack.push(black_box(message.to_vec()));
            vm.stack.push(signature);
            vm.execute_op(&OpCode::Verify).unwrap();
            vm.stack.clear();
        })
    });
}

fn bench_vm_control_flow(c: &mut Criterion) {
    let mut vm = QRVM::new();
    
    c.bench_function("vm_jump", |b| {
        b.iter(|| {
            vm.stack.push(black_box(0u64.to_le_bytes().to_vec()));
            vm.execute_op(&OpCode::Jump).unwrap();
            vm.pc = 0;
        })
    });
    
    c.bench_function("vm_jumpi", |b| {
        b.iter(|| {
            vm.stack.push(black_box(1u64.to_le_bytes().to_vec()));
            vm.stack.push(black_box(2u64.to_le_bytes().to_vec()));
            vm.execute_op(&OpCode::JumpI).unwrap();
            vm.pc = 0;
        })
    });
}

fn bench_vm_stack_operations(c: &mut Criterion) {
    let mut vm = QRVM::new();
    
    c.bench_function("vm_push_pop", |b| {
        b.iter(|| {
            vm.execute_op(&OpCode::Push(black_box(vec![1, 2, 3]))).unwrap();
            vm.execute_op(&OpCode::Pop).unwrap();
        })
    });
    
    c.bench_function("vm_dup", |b| {
        b.iter(|| {
            vm.execute_op(&OpCode::Push(black_box(vec![1, 2, 3]))).unwrap();
            vm.execute_op(&OpCode::Dup(0)).unwrap();
            vm.stack.clear();
        })
    });
}

fn bench_vm_contract_execution(c: &mut Criterion) {
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
    
    c.bench_function("vm_contract", |b| {
        b.iter(|| {
            vm.load_contract(&contract);
            vm.execute().unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_vm_arithmetic,
    bench_vm_storage,
    bench_vm_crypto,
    bench_vm_control_flow,
    bench_vm_stack_operations,
    bench_vm_contract_execution,
);
criterion_main!(benches); 