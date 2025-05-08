# Straz

A quantum-resistant blockchain with ZK-rollup support, implemented in Rust.

## Features

- **Quantum-Resistant Cryptography**
  - Post-quantum cryptographic algorithms
  - Hybrid encryption schemes
  - Quantum-resistant signatures

- **Blockchain Core**
  - Proof of Stake consensus
  - Efficient state management
  - Merkle tree-based transaction verification
  - ZK-rollup support for private transactions

- **Consensus**
  - Validator registration and management
  - Performance-based validator selection
  - Stake-based consensus mechanism
  - Quantum-resistant block validation

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Cargo package manager
- Git

### Installation

1. Clone the repository:
```bash
git clone https://github.com/willruzycki/straz.git
cd straz
```

2. Build the project:
```bash
cargo build --release
```

3. Run tests:
```bash
cargo test
```

4. Run benchmarks:
```bash
cargo bench
```

## Project Structure

```
straz/
├── src/
│   ├── blockchain/     # Blockchain core implementation
│   ├── consensus/      # Consensus mechanism
│   ├── crypto/         # Cryptographic primitives
│   └── network/        # P2P networking
├── benches/            # Performance benchmarks
├── tests/             # Integration tests
└── examples/          # Usage examples
```

## Usage

### Creating a Transaction

```rust
use straz_rs::blockchain::{Blockchain, Transaction};
use straz_rs::crypto::KeyPair;

let mut blockchain = Blockchain::new(4);
let keypair = KeyPair::generate();

blockchain.create_transaction(
    keypair.public_key(),
    "recipient".to_string(),
    100,
    1,
).await?;
```

### Running a Validator

```rust
use straz_rs::consensus::Consensus;
use straz_rs::blockchain::Blockchain;

let blockchain = Blockchain::new(4);
let consensus = Consensus::new(blockchain, 1000, 10);

consensus.register_validator(
    "validator_address".to_string(),
    2000,
    keypair,
).await?;
```

## Security

- All cryptographic operations use quantum-resistant algorithms
- Private transactions are protected by ZK-rollup
- Consensus mechanism includes slashing conditions for malicious validators
- Regular security audits and updates

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- NIST PQC Standardization Project
- Zero Knowledge Proof research community
- Rust Cryptography Working Group 