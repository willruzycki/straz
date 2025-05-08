use criterion::{black_box, criterion_group, criterion_main, Criterion};
use straz_rs::blockchain::{Blockchain, Block};
use straz_rs::consensus::Consensus;
use straz_rs::crypto::KeyPair;
use tokio::runtime::Runtime;

fn benchmark_validator_registration(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let blockchain = Blockchain::new(4);
    let consensus = Consensus::new(blockchain, 1000, 10);
    let keypair = KeyPair::generate();
    
    c.bench_function("validator_registration", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(consensus.register_validator(
                    "validator".to_string(),
                    2000,
                    keypair.clone(),
                ).await)
            });
        });
    });
}

fn benchmark_validator_selection(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let blockchain = Blockchain::new(4);
    let consensus = Consensus::new(blockchain, 1000, 10);
    
    // Register multiple validators
    rt.block_on(async {
        for i in 0..10 {
            let keypair = KeyPair::generate();
            consensus.register_validator(
                format!("validator{}", i),
                1000 + (i * 100) as u64,
                keypair,
            ).await.unwrap();
        }
    });
    
    c.bench_function("validator_selection", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(consensus.select_validator().await)
            });
        });
    });
}

fn benchmark_block_validation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let blockchain = Blockchain::new(4);
    let consensus = Consensus::new(blockchain, 1000, 10);
    let keypair = KeyPair::generate();
    
    // Register validator
    rt.block_on(async {
        consensus.register_validator(
            "validator".to_string(),
            2000,
            keypair.clone(),
        ).await.unwrap();
    });
    
    // Create and sign a block
    let mut block = Block::new(
        1,
        vec![],
        "previous_hash".to_string(),
    );
    block.sign(&keypair).unwrap();
    
    c.bench_function("block_validation", |b| {
        b.iter(|| {
            rt.block_on(async {
                let validator = consensus.select_validator().await.unwrap().unwrap();
                black_box(consensus.validate_block(&block, &validator).await)
            });
        });
    });
}

fn benchmark_block_processing(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let blockchain = Blockchain::new(4);
    let consensus = Consensus::new(blockchain, 1000, 10);
    let keypair = KeyPair::generate();
    
    // Register validator
    rt.block_on(async {
        consensus.register_validator(
            "validator".to_string(),
            2000,
            keypair.clone(),
        ).await.unwrap();
    });
    
    // Create and sign a block
    let mut block = Block::new(
        1,
        vec![],
        "previous_hash".to_string(),
    );
    block.sign(&keypair).unwrap();
    
    c.bench_function("block_processing", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(consensus.process_block(block.clone()).await)
            });
        });
    });
}

criterion_group!(
    benches,
    benchmark_validator_registration,
    benchmark_validator_selection,
    benchmark_block_validation,
    benchmark_block_processing
);
criterion_main!(benches); 