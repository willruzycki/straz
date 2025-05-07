#!/bin/bash

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Check if strazd is running
if ! pgrep -x "strazd" > /dev/null; then
    echo -e "${RED}Straz daemon is not running. Please start it first:${NC}"
    echo "./src/strazd -daemon"
    exit 1
fi

# Check if cpuminer exists
if [ ! -f "cpuminer/minerd" ]; then
    echo -e "${RED}CPU miner not found. Building it...${NC}"
    
    # Install dependencies
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install automake libcurl openssl
    else
        sudo apt-get update
        sudo apt-get install -y build-essential libcurl4-openssl-dev
    fi
    
    # Clone and build cpuminer
    git clone https://github.com/pooler/cpuminer.git
    cd cpuminer
    ./autogen.sh
    ./configure CFLAGS="-O3"
    make
    cd ..
fi

# Get RPC credentials from config
RPC_USER=$(grep rpcuser .straz/straz.conf | cut -d= -f2)
RPC_PASS=$(grep rpcpassword .straz/straz.conf | cut -d= -f2)

# Get a new address for mining rewards
echo -e "${GREEN}Getting a new address for mining rewards...${NC}"
ADDRESS=$(./src/straz-cli getnewaddress)

echo -e "${GREEN}Starting miner...${NC}"
echo -e "Mining rewards will be sent to: ${GREEN}$ADDRESS${NC}"
echo -e "Press Ctrl+C to stop mining"

# Start mining
./cpuminer/minerd --url=http://127.0.0.1:18443/ \
    --user=$RPC_USER \
    --pass=$RPC_PASS \
    --coinbase-addr=$ADDRESS \
    --algo=sha256d \
    --threads=$(nproc) 