#!/bin/bash

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo -e "${GREEN}Modifying Bitcoin Core source code for Straz...${NC}"

# Check if Bitcoin Core source exists
if [ ! -d "bitcoin" ]; then
    echo -e "${RED}Bitcoin Core source not found. Please clone it first:${NC}"
    echo "git clone https://github.com/bitcoin/bitcoin.git"
    exit 1
fi

# Create backup of original files
echo -e "${GREEN}Creating backups of original files...${NC}"
cp bitcoin/src/chainparams.cpp bitcoin/src/chainparams.cpp.bak
cp bitcoin/src/chainparamsbase.cpp bitcoin/src/chainparamsbase.cpp.bak
cp bitcoin/src/consensus/consensus.h bitcoin/src/consensus/consensus.h.bak

# Modify chainparams.cpp
echo -e "${GREEN}Modifying chainparams.cpp...${NC}"
sed -i '' 's/bitcoin/straz/g' bitcoin/src/chainparams.cpp
sed -i '' 's/Bitcoin/Straz/g' bitcoin/src/chainparams.cpp
sed -i '' 's/BTC/STRZ/g' bitcoin/src/chainparams.cpp
sed -i '' 's/8333/18444/g' bitcoin/src/chainparams.cpp
sed -i '' 's/0xf9, 0xbe, 0xb4, 0xd9/0xfa, 0xce, 0xb0, 0x0c/g' bitcoin/src/chainparams.cpp
sed -i '' 's/0x00/0x3f/g' bitcoin/src/chainparams.cpp  # Address prefix
sed -i '' 's/bc/stz/g' bitcoin/src/chainparams.cpp  # Bech32 prefix

# Modify chainparamsbase.cpp
echo -e "${GREEN}Modifying chainparamsbase.cpp...${NC}"
sed -i '' 's/bitcoin/straz/g' bitcoin/src/chainparamsbase.cpp
sed -i '' 's/Bitcoin/Straz/g' bitcoin/src/chainparamsbase.cpp
sed -i '' 's/8332/18443/g' bitcoin/src/chainparamsbase.cpp

# Modify consensus.h
echo -e "${GREEN}Modifying consensus.h...${NC}"
sed -i '' 's/COINBASE_MATURITY 100/COINBASE_MATURITY 100/g' bitcoin/src/consensus/consensus.h

# Create a patch file for the genesis block
echo -e "${GREEN}Creating genesis block patch...${NC}"
cat > genesis.patch << EOL
--- a/src/chainparams.cpp
+++ b/src/chainparams.cpp
@@ -123,7 +123,7 @@ public:
         consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
         consensus.defaultAssumeValid = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
         pchMessageStart[0] = 0xfa;
-        pchMessageStart[1] = 0xce;
+        pchMessageStart[1] = 0xce;
         pchMessageStart[2] = 0xb0;
         pchMessageStart[3] = 0x0c;
         nDefaultPort = 18444;
@@ -131,7 +131,7 @@ public:
         nPruneAfterHeight = 100000;
         m_assumed_blockchain_size = 0;
         m_assumed_chain_state_size = 0;
-        genesis = CreateGenesisBlock(1748736000, 2083236893, 0x1d00ffff, 1, 50 * COIN);
+        genesis = CreateGenesisBlock(1748736000, 2083236893, 0x1d00ffff, 1, 50 * COIN);
         consensus.hashGenesisBlock = genesis.GetHash();
         assert(consensus.hashGenesisBlock == uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"));
         assert(genesis.hashMerkleRoot == uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"));
EOL

# Apply the patch
echo -e "${GREEN}Applying genesis block patch...${NC}"
cd bitcoin && patch -p1 < ../genesis.patch

echo -e "${GREEN}Modifications complete!${NC}"
echo -e "Next steps:"
echo -e "1. Run ./genesis.py to generate the genesis block parameters"
echo -e "2. Update the genesis block parameters in src/chainparams.cpp"
echo -e "3. Build the modified Bitcoin Core:"
echo -e "   cd bitcoin"
echo -e "   ./autogen.sh"
echo -e "   ./configure"
echo -e "   make -j$(nproc)" 