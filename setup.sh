#!/bin/bash

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo -e "${GREEN}Setting up Straz (STRZ) development environment...${NC}"

# Check if running on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo -e "${GREEN}Detected macOS system${NC}"
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo -e "${RED}Homebrew is not installed. Please install it first:${NC}"
        echo "/bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        exit 1
    fi
    
    # Install dependencies using Homebrew
    echo -e "${GREEN}Installing dependencies...${NC}"
    brew install automake berkeley-db4 libtool boost miniupnpc pkg-config python qt libevent qrencode sqlite
    
    # Set up Berkeley DB
    export BDB_PREFIX="/usr/local/opt/berkeley-db4"
else
    echo -e "${RED}This script currently only supports macOS.${NC}"
    echo "For other operating systems, please follow the manual setup instructions in README.md"
    exit 1
fi

# Create necessary directories
echo -e "${GREEN}Creating project directories...${NC}"
mkdir -p src
mkdir -p contrib
mkdir -p .straz

# Create initial configuration file
echo -e "${GREEN}Creating initial configuration...${NC}"
cat > .straz/straz.conf << EOL
# Straz configuration file
rpcuser=strazrpc
rpcpassword=$(openssl rand -hex 32)
daemon=1
server=1
listen=1
txindex=1
rpcallowip=127.0.0.1
rpcport=18443
port=18444
EOL

echo -e "${GREEN}Setup complete!${NC}"
echo -e "Next steps:"
echo -e "1. Clone Bitcoin Core: git clone https://github.com/bitcoin/bitcoin.git"
echo -e "2. Copy the source files to the src directory"
echo -e "3. Follow the build instructions in README.md"
echo -e "\nYour RPC credentials are in .straz/straz.conf" 