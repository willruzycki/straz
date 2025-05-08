# Straz

A post-quantum and quantum-resistant blockchain with ZK-rollup support, implemented in Rust.

## Features

- Hybrid classical + post-quantum cryptography
- Zero-knowledge rollup for transaction batching
- Quantum-resistant consensus mechanism
- High-performance transaction processing
- Secure key management

## Prerequisites

- Rust 1.70 or later
- liboqs (for post-quantum cryptography)
- OpenSSL development libraries

## Installation

1. Install Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. Install system dependencies:
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y liboqs-dev libssl-dev

# macOS
brew install liboqs openssl
```

3. Clone and build:
```bash
git clone https://github.com/yourusername/straz.git
cd straz
cargo build --release
```

## Usage

```rust
use straz::crypto::{KeyPair, PostQuantumCrypto, ZKRollup};
use straz::blockchain::Blockchain;

// Create a new key pair
let keypair = KeyPair::new()?;

// Sign a message
let message = b"Hello, quantum world!";
let signature = keypair.sign(message)?;

// Verify the signature
assert!(keypair.verify(message, &signature)?);

// Create a blockchain instance
let mut blockchain = Blockchain::new();

// Add a transaction
blockchain.create_transaction(
    "sender_address",
    "recipient_address",
    100,
    0.001
)?;

// Mine pending transactions
blockchain.mine_pending_transactions("miner_address").await?;
```

## Testing

Run the test suite:
```bash
cargo test
```

Run benchmarks:
```bash
cargo bench
```

## Security

This project implements several security measures:
- Hybrid encryption using both classical and post-quantum algorithms
- Zero-knowledge proofs for transaction privacy
- Quantum-resistant signatures
- Secure key management

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [liboqs](https://github.com/open-quantum-safe/liboqs) for post-quantum cryptography
- [ring](https://github.com/briansmith/ring) for cryptographic primitives
- [arkworks](https://github.com/arkworks-rs) for zero-knowledge proofs 