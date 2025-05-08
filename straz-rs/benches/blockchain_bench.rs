use criterion::{black_box, criterion_group, criterion_main, Criterion};
use straz_rs::blockchain::{Blockchain, Transaction};
use straz_rs::crypto::KeyPair;
use tokio::runtime::Runtime;

fn benchmark_blockchain_creation(c: &mut Criterion) {
    c.bench_function("blockchain_creation", |b| {
        b.iter(|| {
            black_box(Blockchain::new(4));
        });
    });
}

fn benchmark_transaction_creation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut blockchain = Blockchain::new(4);
    let keypair = KeyPair::generate();
    
    c.bench_function("transaction_creation", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(blockchain.create_transaction(
                    keypair.public_key(),
                    "recipient".to_string(),
                    100,
                    1,
                ).await)
            });
        });
    });
}

fn benchmark_mining(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut blockchain = Blockchain::new(4);
    
    // Create some transactions
    rt.block_on(async {
        for i in 0..10 {
            blockchain.create_transaction(
                format!("sender{}", i),
                format!("recipient{}", i),
                100,
                1,
            ).await.unwrap();
        }
    });
    
    c.bench_function("mining", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(blockchain.mine_pending_transactions("miner".to_string()).await)
            });
        });
    });
}

fn benchmark_chain_validation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut blockchain = Blockchain::new(4);
    
    // Create and mine some blocks
    rt.block_on(async {
        for i in 0..5 {
            blockchain.create_transaction(
                format!("sender{}", i),
                format!("recipient{}", i),
                100,
                1,
            ).await.unwrap();
            blockchain.mine_pending_transactions("miner".to_string()).await.unwrap();
        }
    });
    
    c.bench_function("chain_validation", |b| {
        b.iter(|| {
            black_box(blockchain.is_chain_valid().unwrap());
        });
    });
}

criterion_group!(
    benches,
    benchmark_blockchain_creation,
    benchmark_transaction_creation,
    benchmark_mining,
    benchmark_chain_validation
);
criterion_main!(benches); 