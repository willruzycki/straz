# Straz (STRZ)

Straz is a privacy-focused cryptocurrency based on Bitcoin Core, designed for secure and private transactions.

## Parameters

- **Coin Name:** Straz
- **Ticker:** STRZ
- **Block Reward:** 50 STRZ per block
- **Halving Interval:** 210,000 blocks (≈4 years at 10 min block time)
- **Block Time:** 600 seconds (10 min)
- **Coinbase Maturity:** 100 blocks
- **Max Supply:** 21,000,000 STRZ
- **P2P Port:** 18444
- **RPC Port:** 18443
- **Magic Bytes:** 0xfa, 0xce, 0xb0, 0x0c
- **Address Prefix:** 63 (addresses start with "S")
- **Bech32 Prefix:** stz

## Genesis Block

- **Timestamp:** May 5, 2025 00:00:00 UTC (Unix: 1748736000)
- **Message:** "Straz Genesis Block – Privacy & Payments, 2025-05-05"
- **Initial Difficulty:** 0x1d00ffff

## Building from Source

### Prerequisites

- Git
- Build essentials (gcc, g++, make)
- Berkeley DB 4.8
- Boost libraries
- libevent
- ZeroMQ
- Other Bitcoin Core dependencies

### Build Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/straz.git
   cd straz
   ```

2. Install dependencies (Ubuntu/Debian):
   ```bash
   sudo apt update
   sudo apt install build-essential libtool autotools-dev automake pkg-config bsdmainutils curl git
   sudo apt install libevent-dev libboost-system-dev libboost-filesystem-dev libboost-test-dev libboost-thread-dev
   sudo apt install libminiupnpc-dev libzmq3-dev libprotobuf-dev protobuf-compiler
   ```

3. Build Berkeley DB 4.8:
   ```bash
   ./contrib/install_db4.sh `pwd`
   export BDB_PREFIX="$(pwd)/db4"
   ```

4. Build Straz:
   ```bash
   ./autogen.sh
   ./configure BDB_CFLAGS="-I${BDB_PREFIX}/include" BDB_LIBS="-L${BDB_PREFIX}/lib"
   make -j$(nproc)
   ```

## Running a Node

1. Create a data directory:
   ```bash
   mkdir -p ~/.straz
   ```

2. Create a configuration file:
   ```bash
   echo "rpcuser=your_username
   rpcpassword=your_password
   " > ~/.straz/straz.conf
   ```

3. Start the daemon:
   ```bash
   ./src/strazd -daemon
   ```

## Mining

To mine Straz, you'll need a CPU miner that supports SHA256d. The recommended miner is cpuminer.

1. Install cpuminer:
   ```bash
   git clone https://github.com/pooler/cpuminer.git
   cd cpuminer
   ./autogen.sh
   ./configure CFLAGS="-O3"
   make
   ```

2. Start mining:
   ```bash
   ./minerd --url=http://127.0.0.1:18443/ --user=your_username --pass=your_password --algo=sha256d
   ```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 