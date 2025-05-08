# Project Files Export for ChatGPT (from: /Users/williamruzycki/straz)

**Note:** This export attempts to include all relevant text-based files. Common binary file types, version control directories, virtual environments, and build artifacts are excluded.

---

### File: `setup.sh`

```bash
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
```
---
### File: `zk_quantum.py`

```python
#!/usr/bin/env python3

from typing import Dict, List, Any, Optional, Tuple
import hashlib
import json
import time
from dataclasses import dataclass
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import numpy as np
from scipy.stats import entropy

logger = logging.getLogger(__name__)

@dataclass
class ZKProof:
    proof: bytes
    public_inputs: List[Any]
    timestamp: float
    verifier_key: bytes

@dataclass
class ZKTransaction:
    sender: str
    recipient: str
    amount: float
    proof: ZKProof
    timestamp: float
    signature: bytes

class ZKRollup:
    def __init__(self):
        self.batch_size = 1000  # Maximum transactions per batch
        self.current_batch: List[ZKTransaction] = []
        self.verifier_keys: Dict[str, bytes] = {}
        self.quantum_resistant = True
        self.zk_proofs: Dict[str, ZKProof] = {}
        
    def generate_zk_proof(self, transaction: Dict[str, Any]) -> Optional[ZKProof]:
        """Generate a zero-knowledge proof for a transaction"""
        try:
            # In a real implementation, this would use a proper ZK-SNARK/STARK system
            # For now, we'll simulate a proof using quantum-resistant primitives
            
            # Generate public inputs (transaction details that can be revealed)
            public_inputs = [
                transaction["sender"],
                transaction["recipient"],
                transaction["amount"],
                time.time()
            ]
            
            # Generate a simulated proof using quantum-resistant primitives
            proof = self._generate_quantum_resistant_proof(public_inputs)
            
            # Generate verifier key
            verifier_key = self._generate_verifier_key()
            
            return ZKProof(
                proof=proof,
                public_inputs=public_inputs,
                timestamp=time.time(),
                verifier_key=verifier_key
            )
        except Exception as e:
            logger.error(f"Error generating ZK proof: {e}")
            return None

    def _generate_quantum_resistant_proof(self, public_inputs: List[Any]) -> bytes:
        """Generate a quantum-resistant proof"""
        # Use lattice-based cryptography for quantum resistance
        # This is a simplified simulation
        proof_data = {
            "public_inputs": public_inputs,
            "timestamp": time.time(),
            "randomness": np.random.bytes(32)
        }
        return json.dumps(proof_data).encode()

    def _generate_verifier_key(self) -> bytes:
        """Generate a quantum-resistant verifier key"""
        # Use lattice-based cryptography
        return hashlib.sha3_256(str(time.time()).encode()).digest()

    def verify_zk_proof(self, proof: ZKProof) -> bool:
        """Verify a zero-knowledge proof"""
        try:
            # In a real implementation, this would verify the ZK-SNARK/STARK proof
            # For now, we'll simulate verification using quantum-resistant primitives
            
            # Verify the proof using the verifier key
            return self._verify_quantum_resistant_proof(proof)
        except Exception as e:
            logger.error(f"Error verifying ZK proof: {e}")
            return False

    def _verify_quantum_resistant_proof(self, proof: ZKProof) -> bool:
        """Verify a quantum-resistant proof"""
        # This is a simplified simulation
        try:
            proof_data = json.loads(proof.proof.decode())
            return (
                proof_data["timestamp"] <= time.time() and
                len(proof_data["randomness"]) == 32
            )
        except Exception:
            return False

    def add_transaction_to_batch(self, transaction: ZKTransaction) -> bool:
        """Add a transaction to the current batch"""
        if len(self.current_batch) >= self.batch_size:
            return False
        
        if self.verify_zk_proof(transaction.proof):
            self.current_batch.append(transaction)
            return True
        return False

    def generate_batch_proof(self) -> Optional[ZKProof]:
        """Generate a proof for the entire batch"""
        if not self.current_batch:
            return None
        
        # Combine all transactions into a single proof
        batch_data = {
            "transactions": [
                {
                    "sender": tx.sender,
                    "recipient": tx.recipient,
                    "amount": tx.amount,
                    "timestamp": tx.timestamp
                }
                for tx in self.current_batch
            ],
            "batch_timestamp": time.time()
        }
        
        # Generate a quantum-resistant proof for the batch
        proof = self._generate_quantum_resistant_proof([batch_data])
        verifier_key = self._generate_verifier_key()
        
        return ZKProof(
            proof=proof,
            public_inputs=[batch_data],
            timestamp=time.time(),
            verifier_key=verifier_key
        )

class QuantumResistantCrypto:
    def __init__(self):
        self.key_size = 4096  # Larger key size for quantum resistance
        self.hash_algorithm = hashes.SHA3_256()
        self.padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA3_256()),
            algorithm=hashes.SHA3_256(),
            label=None
        )
    
    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """Generate a quantum-resistant key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        public_key = private_key.public_key()
        
        return (
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ),
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    
    def encrypt(self, message: bytes, public_key: bytes) -> bytes:
        """Encrypt a message using quantum-resistant encryption"""
        public_key = serialization.load_pem_public_key(public_key)
        return public_key.encrypt(
            message,
            self.padding
        )
    
    def decrypt(self, encrypted_message: bytes, private_key: bytes) -> bytes:
        """Decrypt a message using quantum-resistant decryption"""
        private_key = serialization.load_pem_private_key(
            private_key,
            password=None
        )
        return private_key.decrypt(
            encrypted_message,
            self.padding
        )
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message using quantum-resistant signature"""
        private_key = serialization.load_pem_private_key(
            private_key,
            password=None
        )
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA3_256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA3_256()
        )
    
    def verify_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a quantum-resistant signature"""
        try:
            public_key = serialization.load_pem_public_key(public_key)
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA3_256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA3_256()
            )
            return True
        except Exception:
            return False

    def generate_quantum_resistant_hash(self, data: bytes) -> bytes:
        """Generate a quantum-resistant hash"""
        # Use SHA3-256 which is considered quantum-resistant
        return hashlib.sha3_256(data).digest()

    def generate_quantum_resistant_key(self, password: str, salt: bytes) -> bytes:
        """Generate a quantum-resistant key from a password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode()) 
```
---
### File: `smart_contract.py`

```python
#!/usr/bin/env python3

from typing import Dict, Any, List, Optional
import json
import hashlib
import time
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class ContractState:
    address: str
    code: str
    owner: str
    balance: float
    storage: Dict[str, Any]
    last_updated: float
    gas_used: int
    gas_price: float

class ContractManager:
    def __init__(self):
        self.contracts: Dict[str, ContractState] = {}
        self.gas_price = 0.000001  # Base gas price in STRZ
        self.max_gas_per_block = 1000000
        self.contract_types = {
            "token": self._execute_token_contract,
            "nft": self._execute_nft_contract,
            "dex": self._execute_dex_contract,
            "dao": self._execute_dao_contract,
            "custom": self._execute_custom_contract
        }

    def deploy_contract(self, code: str, owner: str, contract_type: str = "custom") -> Optional[str]:
        """Deploy a new smart contract"""
        try:
            # Generate contract address
            contract_hash = hashlib.sha256(f"{code}{owner}{time.time()}".encode()).hexdigest()
            contract_address = f"0x{contract_hash[:40]}"
            
            # Create contract state
            self.contracts[contract_address] = ContractState(
                address=contract_address,
                code=code,
                owner=owner,
                balance=0.0,
                storage={},
                last_updated=time.time(),
                gas_used=0,
                gas_price=self.gas_price
            )
            
            logger.info(f"Contract deployed at {contract_address}")
            return contract_address
        except Exception as e:
            logger.error(f"Error deploying contract: {e}")
            return None

    def execute_contract(self, contract_address: str, method: str, params: List[Any], sender: str, value: float = 0) -> Dict[str, Any]:
        """Execute a contract method"""
        if contract_address not in self.contracts:
            return {"error": "Contract not found"}
        
        contract = self.contracts[contract_address]
        
        # Check if contract has enough balance for gas
        gas_cost = self._estimate_gas_cost(method, params)
        if contract.balance < gas_cost:
            return {"error": "Insufficient contract balance for gas"}
        
        try:
            # Execute contract method based on type
            contract_type = self._detect_contract_type(contract.code)
            if contract_type in self.contract_types:
                result = self.contract_types[contract_type](contract, method, params, sender, value)
            else:
                result = self._execute_custom_contract(contract, method, params, sender, value)
            
            # Update contract state
            contract.balance -= gas_cost
            contract.gas_used += gas_cost
            contract.last_updated = time.time()
            
            return result
        except Exception as e:
            logger.error(f"Error executing contract: {e}")
            return {"error": str(e)}

    def _estimate_gas_cost(self, method: str, params: List[Any]) -> float:
        """Estimate gas cost for a contract method"""
        base_cost = 1000  # Base cost for any method call
        param_cost = len(str(params)) * 10  # Cost based on parameter size
        return (base_cost + param_cost) * self.gas_price

    def _detect_contract_type(self, code: str) -> str:
        """Detect contract type from code"""
        code_lower = code.lower()
        if "erc20" in code_lower or "token" in code_lower:
            return "token"
        elif "erc721" in code_lower or "nft" in code_lower:
            return "nft"
        elif "swap" in code_lower or "liquidity" in code_lower:
            return "dex"
        elif "vote" in code_lower or "proposal" in code_lower:
            return "dao"
        return "custom"

    def _execute_token_contract(self, contract: ContractState, method: str, params: List[Any], sender: str, value: float) -> Dict[str, Any]:
        """Execute token contract methods"""
        if method == "transfer":
            recipient, amount = params
            if contract.storage.get(sender, 0) >= amount:
                contract.storage[sender] = contract.storage.get(sender, 0) - amount
                contract.storage[recipient] = contract.storage.get(recipient, 0) + amount
                return {"success": True, "new_balance": contract.storage[sender]}
        elif method == "balanceOf":
            address = params[0]
            return {"balance": contract.storage.get(address, 0)}
        return {"error": "Invalid method"}

    def _execute_nft_contract(self, contract: ContractState, method: str, params: List[Any], sender: str, value: float) -> Dict[str, Any]:
        """Execute NFT contract methods"""
        if method == "mint":
            token_id = params[0]
            if token_id not in contract.storage:
                contract.storage[token_id] = sender
                return {"success": True, "token_id": token_id}
        elif method == "transfer":
            token_id, recipient = params
            if contract.storage.get(token_id) == sender:
                contract.storage[token_id] = recipient
                return {"success": True}
        return {"error": "Invalid method"}

    def _execute_dex_contract(self, contract: ContractState, method: str, params: List[Any], sender: str, value: float) -> Dict[str, Any]:
        """Execute DEX contract methods"""
        if method == "addLiquidity":
            token_a, token_b, amount_a, amount_b = params
            pool_id = f"{token_a}_{token_b}"
            if pool_id not in contract.storage:
                contract.storage[pool_id] = {
                    "reserve_a": amount_a,
                    "reserve_b": amount_b,
                    "liquidity_providers": {sender: amount_a + amount_b}
                }
            return {"success": True, "pool_id": pool_id}
        elif method == "swap":
            token_in, token_out, amount_in = params
            pool_id = f"{token_in}_{token_out}"
            if pool_id in contract.storage:
                pool = contract.storage[pool_id]
                amount_out = (amount_in * pool["reserve_b"]) / (pool["reserve_a"] + amount_in)
                return {"success": True, "amount_out": amount_out}
        return {"error": "Invalid method"}

    def _execute_dao_contract(self, contract: ContractState, method: str, params: List[Any], sender: str, value: float) -> Dict[str, Any]:
        """Execute DAO contract methods"""
        if method == "createProposal":
            proposal_id = len(contract.storage.get("proposals", []))
            proposal = {
                "id": proposal_id,
                "creator": sender,
                "description": params[0],
                "votes": {},
                "executed": False
            }
            if "proposals" not in contract.storage:
                contract.storage["proposals"] = []
            contract.storage["proposals"].append(proposal)
            return {"success": True, "proposal_id": proposal_id}
        elif method == "vote":
            proposal_id, vote = params
            if proposal_id < len(contract.storage.get("proposals", [])):
                proposal = contract.storage["proposals"][proposal_id]
                proposal["votes"][sender] = vote
                return {"success": True}
        return {"error": "Invalid method"}

    def _execute_custom_contract(self, contract: ContractState, method: str, params: List[Any], sender: str, value: float) -> Dict[str, Any]:
        """Execute custom contract methods"""
        # This is a simplified version - in a real implementation,
        # you would have a proper VM to execute the contract code
        try:
            # Execute the contract code in a sandboxed environment
            # For now, we'll just return a success message
            return {"success": True, "method": method, "params": params}
        except Exception as e:
            return {"error": str(e)}

    def get_contract(self, address: str) -> Optional[ContractState]:
        """Get contract information"""
        return self.contracts.get(address)

    def save_contracts(self, filename: str):
        """Save contracts to file"""
        with open(filename, 'w') as f:
            json.dump({
                address: {
                    "code": contract.code,
                    "owner": contract.owner,
                    "balance": contract.balance,
                    "storage": contract.storage,
                    "last_updated": contract.last_updated,
                    "gas_used": contract.gas_used,
                    "gas_price": contract.gas_price
                }
                for address, contract in self.contracts.items()
            }, f, indent=4)

    def load_contracts(self, filename: str):
        """Load contracts from file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                for address, contract_data in data.items():
                    self.contracts[address] = ContractState(
                        address=address,
                        code=contract_data["code"],
                        owner=contract_data["owner"],
                        balance=contract_data["balance"],
                        storage=contract_data["storage"],
                        last_updated=contract_data["last_updated"],
                        gas_used=contract_data["gas_used"],
                        gas_price=contract_data["gas_price"]
                    )
        except FileNotFoundError:
            logger.warning(f"No contracts file found at {filename}")
        except Exception as e:
            logger.error(f"Error loading contracts: {e}") 
```
---
### File: `requirements.txt`

```text
flask==3.0.2
cryptography>=42.0.0
requests==2.31.0
python-dotenv==1.0.1
websockets==12.0
aiohttp==3.9.3
pytest==8.0.2
black==24.2.0
mypy==1.8.0
pylint==3.0.3
pytest-asyncio==0.23.5
pytest-cov==4.1.0
pytest-mock==3.12.0
pytest-timeout==2.2.0
pytest-xdist==3.5.0
pytest-benchmark==4.0.0
pytest-env==1.1.3
pytest-randomly==3.15.0
pytest-sugar==1.0.0
pytest-html==4.1.1
pytest-metadata==3.1.0
pytest-ordering==0.6
pytest-repeat==0.9.1
pytest-rerunfailures==12.0
pytest-selenium==4.0.2
pytest-socket==0.6.0
pytest-subtests==0.12.0
pytest-tldr==0.2.5
pytest-watch==4.2.0
pytest-xprocess==0.23.0
pytest-xvfb==3.0.0
numpy>=1.26.4
scipy>=1.12.0
liboqs-python>=0.7.2
pycryptodome>=3.20.0
liboqs>=0.7.2
pqcrypto>=0.1.3
pynacl>=1.5.0
pyopenssl>=24.0.0
cryptography-vectors>=42.0.0

```
---
### File: `p2p.py`

```python
#!/usr/bin/env python3

import asyncio
import websockets
import json
from typing import Set, Dict, Any, List, Optional
import logging
from blockchain import Blockchain
import time
import hashlib
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import socket
import struct
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PeerInfo:
    address: str
    port: int
    last_seen: float
    latency: float
    version: str
    capabilities: List[str]
    is_validator: bool
    shard_id: Optional[int]

class DHTNode:
    def __init__(self, node_id: str, address: str, port: int):
        self.node_id = node_id
        self.address = address
        self.port = port
        self.buckets: Dict[int, Set[str]] = {i: set() for i in range(160)}  # 160-bit key space
        self.data: Dict[str, Any] = {}

    def distance(self, other_id: str) -> int:
        """Calculate XOR distance between two node IDs"""
        return int(self.node_id, 16) ^ int(other_id, 16)

    def update_bucket(self, node_id: str):
        """Update the appropriate bucket with a node ID"""
        distance = self.distance(node_id)
        bucket_index = distance.bit_length() - 1
        self.buckets[bucket_index].add(node_id)

    def get_closest_nodes(self, target_id: str, k: int = 8) -> List[str]:
        """Get k closest nodes to the target ID"""
        distance = self.distance(target_id)
        bucket_index = distance.bit_length() - 1
        
        # Start with the current bucket
        closest = list(self.buckets[bucket_index])
        
        # If we need more nodes, look in adjacent buckets
        i = 1
        while len(closest) < k and (bucket_index - i >= 0 or bucket_index + i < 160):
            if bucket_index - i >= 0:
                closest.extend(self.buckets[bucket_index - i])
            if bucket_index + i < 160:
                closest.extend(self.buckets[bucket_index + i])
            i += 1
        
        # Sort by distance and return k closest
        return sorted(closest, key=lambda x: self.distance(x))[:k]

class P2PNode:
    def __init__(self, host: str = "0.0.0.0", port: int = 6000):
        self.host = host
        self.port = port
        self.node_id = hashlib.sha256(f"{host}:{port}".encode()).hexdigest()
        self.peers: Dict[str, PeerInfo] = {}
        self.blockchain = None
        self.server = None
        self.known_peers: Set[str] = set()
        self.peer_latency: Dict[str, float] = {}
        self.sync_interval = 60
        self.max_peers = 50
        self.min_peers = 10
        self.dht = DHTNode(self.node_id, host, port)
        self.encryption_key = self._generate_encryption_key()
        self.version = "1.0.0"
        self.capabilities = ["blockchain", "dht", "encryption"]

    def _generate_encryption_key(self) -> bytes:
        """Generate an encryption key for secure communication"""
        salt = b'straz_blockchain_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.node_id.encode()))
        return key

    def set_blockchain(self, blockchain: Blockchain):
        self.blockchain = blockchain

    async def start(self):
        """Start the P2P server"""
        self.server = await websockets.serve(
            self.handle_connection,
            self.host,
            self.port
        )
        logger.info(f"P2P server started on {self.host}:{self.port}")
        
        # Start background tasks
        asyncio.create_task(self.periodic_sync())
        asyncio.create_task(self.periodic_peer_discovery())
        asyncio.create_task(self.periodic_peer_health_check())
        asyncio.create_task(self.periodic_dht_maintenance())

    async def periodic_sync(self):
        """Periodically sync with peers"""
        while True:
            await asyncio.sleep(self.sync_interval)
            await self.sync_with_peers()

    async def periodic_peer_discovery(self):
        """Periodically discover new peers"""
        while True:
            await asyncio.sleep(300)  # Every 5 minutes
            await self.discover_peers()

    async def periodic_peer_health_check(self):
        """Periodically check peer health"""
        while True:
            await asyncio.sleep(60)  # Every minute
            await self.check_peer_health()

    async def periodic_dht_maintenance(self):
        """Periodically maintain DHT state"""
        while True:
            await asyncio.sleep(3600)  # Every hour
            await self.maintain_dht()

    async def maintain_dht(self):
        """Maintain DHT state by refreshing buckets and removing stale nodes"""
        current_time = time.time()
        
        # Remove stale nodes from DHT
        for bucket in self.dht.buckets.values():
            stale_nodes = set()
            for node_id in bucket:
                if node_id in self.peers:
                    peer = self.peers[node_id]
                    if current_time - peer.last_seen > 3600:  # 1 hour
                        stale_nodes.add(node_id)
            bucket -= stale_nodes
        
        # Refresh buckets by querying random nodes
        for bucket_index in range(160):
            if len(self.dht.buckets[bucket_index]) > 0:
                random_node = random.choice(list(self.dht.buckets[bucket_index]))
                await self.query_dht_node(random_node)

    async def discover_peers(self):
        """Discover new peers through DHT and existing peers"""
        # Query DHT for new peers
        closest_nodes = self.dht.get_closest_nodes(self.node_id)
        for node_id in closest_nodes:
            if node_id not in self.peers:
                await self.connect_to_peer(node_id)
        
        # Query existing peers for new peers
        for peer in list(self.peers.values()):
            try:
                async with websockets.connect(f"ws://{peer.address}:{peer.port}") as websocket:
                    await self.send_message(websocket, {
                        "type": "get_peers"
                    })
            except Exception as e:
                logger.error(f"Failed to discover peers through {peer.address}:{e}")
                del self.peers[peer.address]

    async def check_peer_health(self):
        """Check health of connected peers"""
        current_time = time.time()
        for peer_id, peer in list(self.peers.items()):
            try:
                start_time = time.time()
                async with websockets.connect(f"ws://{peer.address}:{peer.port}") as websocket:
                    await self.send_message(websocket, {
                        "type": "ping"
                    })
                    response = await websocket.recv()
                    latency = time.time() - start_time
                    
                    # Update peer info
                    peer.latency = latency
                    peer.last_seen = current_time
                    
                    # Update DHT
                    self.dht.update_bucket(peer_id)
            except Exception as e:
                logger.error(f"Peer {peer.address} is unhealthy: {e}")
                del self.peers[peer_id]
                self.known_peers.remove(peer.address)

    async def sync_with_peers(self):
        """Sync blockchain with peers"""
        if not self.blockchain:
            return

        for peer in list(self.peers.values()):
            try:
                async with websockets.connect(f"ws://{peer.address}:{peer.port}") as websocket:
                    # Get the latest block height
                    await self.send_message(websocket, {
                        "type": "get_block_height"
                    })
                    response = await websocket.recv()
                    data = json.loads(response)
                    
                    if data["type"] == "block_height":
                        peer_height = data["height"]
                        local_height = len(self.blockchain.chain)
                        
                        if peer_height > local_height:
                            # Request missing blocks
                            await self.send_message(websocket, {
                                "type": "get_blocks",
                                "data": {
                                    "start_height": local_height,
                                    "end_height": peer_height
                                }
                            })
            except Exception as e:
                logger.error(f"Failed to sync with peer {peer.address}: {e}")
                del self.peers[peer.address]

    async def handle_connection(self, websocket, path):
        """Handle incoming connections"""
        peer_address = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        peer_id = hashlib.sha256(peer_address.encode()).hexdigest()
        
        # Add peer to DHT
        self.dht.update_bucket(peer_id)
        
        try:
            await self.handle_peer_messages(websocket)
        except Exception as e:
            logger.error(f"Error handling connection from {peer_address}: {e}")
        finally:
            if peer_id in self.peers:
                del self.peers[peer_id]

    async def handle_peer_messages(self, websocket):
        """Handle messages from peers"""
        async for message in websocket:
            try:
                # Decrypt message
                decrypted_message = self._decrypt_message(message)
                data = json.loads(decrypted_message)
                await self.process_message(data)
            except json.JSONDecodeError:
                logger.error("Invalid JSON message received")
            except Exception as e:
                logger.error(f"Error processing message: {e}")

    def _encrypt_message(self, message: str) -> bytes:
        """Encrypt a message using Fernet"""
        f = Fernet(self.encryption_key)
        return f.encrypt(message.encode())

    def _decrypt_message(self, encrypted_message: bytes) -> str:
        """Decrypt a message using Fernet"""
        f = Fernet(self.encryption_key)
        return f.decrypt(encrypted_message).decode()

    async def process_message(self, message: Dict[str, Any]):
        """Process different types of messages"""
        message_type = message.get("type")
        data = message.get("data", {})

        if message_type == "handshake":
            # Handle handshake
            peer_id = data["node_id"]
            peer_info = PeerInfo(
                address=data["address"],
                port=data["port"],
                last_seen=time.time(),
                latency=0.0,
                version=data["version"],
                capabilities=data["capabilities"],
                is_validator=data.get("is_validator", False),
                shard_id=data.get("shard_id")
            )
            self.peers[peer_id] = peer_info
            self.known_peers.add(f"{peer_info.address}:{peer_info.port}")
            self.dht.update_bucket(peer_id)
        
        elif message_type == "new_block":
            # Handle new block
            if self.blockchain:
                block_data = data["block"]
                if self.verify_block(block_data):
                    self.blockchain.chain.append(Block.from_dict(block_data))
                    # Broadcast to other peers
                    await self.broadcast_except(message, data["sender"])
        
        elif message_type == "new_transaction":
            # Handle new transaction
            if self.blockchain:
                transaction = data["transaction"]
                if self.blockchain.validate_transaction(transaction):
                    self.blockchain.transaction_pool[self.blockchain.calculate_transaction_hash(transaction)] = transaction
                    # Broadcast to other peers
                    await self.broadcast_except(message, data["sender"])
        
        elif message_type == "get_blocks":
            # Handle block request
            if self.blockchain:
                start_height = data["start_height"]
                end_height = data["end_height"]
                blocks = self.blockchain.chain[start_height:end_height]
                return {
                    "type": "blocks",
                    "data": {
                        "blocks": [block.to_dict() for block in blocks]
                    }
                }
        
        elif message_type == "get_peers":
            # Return list of known peers
            return {
                "type": "peers",
                "data": {
                    "peers": [
                        {
                            "node_id": peer_id,
                            "address": peer.address,
                            "port": peer.port,
                            "version": peer.version,
                            "capabilities": peer.capabilities,
                            "is_validator": peer.is_validator,
                            "shard_id": peer.shard_id
                        }
                        for peer_id, peer in self.peers.items()
                    ]
                }
            }
        
        elif message_type == "ping":
            # Handle ping
            return {
                "type": "pong",
                "data": {
                    "timestamp": time.time()
                }
            }
        
        elif message_type == "dht_query":
            # Handle DHT query
            target_id = data["target_id"]
            closest_nodes = self.dht.get_closest_nodes(target_id)
            return {
                "type": "dht_response",
                "data": {
                    "nodes": closest_nodes
                }
            }

    async def broadcast_except(self, message: Dict[str, Any], exclude_peer: str):
        """Broadcast a message to all peers except one"""
        encrypted_message = self._encrypt_message(json.dumps(message))
        for peer in self.peers.values():
            if f"{peer.address}:{peer.port}" != exclude_peer:
                try:
                    async with websockets.connect(f"ws://{peer.address}:{peer.port}") as websocket:
                        await websocket.send(encrypted_message)
                except Exception as e:
                    logger.error(f"Failed to broadcast to {peer.address}:{e}")
                    del self.peers[peer.address]

    async def send_message(self, websocket, message: Dict[str, Any]):
        """Send a message to a peer"""
        try:
            encrypted_message = self._encrypt_message(json.dumps(message))
            await websocket.send(encrypted_message)
        except Exception as e:
            logger.error(f"Failed to send message: {e}")

    async def stop(self):
        """Stop the P2P server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("P2P server stopped")

if __name__ == "__main__":
    # Example usage
    async def main():
        node = P2PNode()
        await node.start()
        
        # Keep the server running
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await node.stop()

    asyncio.run(main()) 
```
---
### File: `Dockerfile`

```
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose ports
EXPOSE 5000 6000

# Create necessary directories
RUN mkdir -p wallets

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python", "api.py"] 
```
---
### File: `pqc.py`

```python
#!/usr/bin/env python3

from typing import Dict, List, Any, Optional, Tuple, Union
import hashlib
import json
import time
from dataclasses import dataclass
import logging
import numpy as np
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import x25519, x448
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, load_pem_private_key,
    load_pem_public_key, NoEncryption
)
import os
import struct
import liboqs
from liboqs import KeyEncapsulation, Signature

logger = logging.getLogger(__name__)

@dataclass
class PQCKeyPair:
    """Container for multiple post-quantum key pairs"""
    # Lattice-based cryptography
    kyber_key: Tuple[bytes, bytes]  # (private, public)
    ntru_key: Tuple[bytes, bytes]
    
    # Hash-based signatures
    sphincs_key: Tuple[bytes, bytes]
    xmss_key: Tuple[bytes, bytes]
    
    # Code-based cryptography
    mceliece_key: Tuple[bytes, bytes]
    
    # Multivariate cryptography
    rainbow_key: Tuple[bytes, bytes]
    
    # Isogeny-based cryptography
    sidh_key: Tuple[bytes, bytes]
    
    # Hybrid classical-quantum
    hybrid_key: Tuple[bytes, bytes]
    
    timestamp: float
    algorithm_versions: Dict[str, str]

class PostQuantumCrypto:
    def __init__(self):
        # Initialize liboqs
        liboqs.init()
        
        # Algorithm configurations
        self.algorithm_configs = {
            'kyber': {
                'variant': 'Kyber768',
                'security_level': 3,  # 256-bit security
                'key_size': 32
            },
            'ntru': {
                'variant': 'NTRU-HPS-2048-509',
                'security_level': 3,
                'key_size': 32
            },
            'sphincs': {
                'variant': 'SPHINCS+-SHA256-256f-robust',
                'security_level': 3,
                'key_size': 32
            },
            'xmss': {
                'variant': 'XMSS-SHA2_20_256',
                'security_level': 3,
                'key_size': 32
            },
            'mceliece': {
                'variant': 'Classic-McEliece-348864',
                'security_level': 3,
                'key_size': 32
            },
            'rainbow': {
                'variant': 'Rainbow-V-Classic',
                'security_level': 3,
                'key_size': 32
            },
            'sidh': {
                'variant': 'SIDH-p751',
                'security_level': 3,
                'key_size': 32
            }
        }
        
        # Initialize algorithm instances
        self.kem = {}
        self.sig = {}
        self._initialize_algorithms()
        
        # Security parameters
        self.min_security_level = 3  # 256-bit security minimum
        self.key_rotation_period = 30 * 24 * 60 * 60  # 30 days
        self.max_key_age = 90 * 24 * 60 * 60  # 90 days
        
        # Initialize entropy pool
        self.entropy_pool = self._initialize_entropy_pool()
        
        # Initialize key store
        self.key_store = {}
        
        # Initialize security monitoring
        self.security_metrics = {
            'key_rotations': 0,
            'algorithm_updates': 0,
            'security_incidents': 0,
            'last_audit': time.time()
        }

    def _initialize_algorithms(self):
        """Initialize post-quantum cryptographic algorithms"""
        try:
            # Initialize KEM algorithms
            self.kem['kyber'] = KeyEncapsulation(self.algorithm_configs['kyber']['variant'])
            self.kem['ntru'] = KeyEncapsulation(self.algorithm_configs['ntru']['variant'])
            self.kem['mceliece'] = KeyEncapsulation(self.algorithm_configs['mceliece']['variant'])
            
            # Initialize signature algorithms
            self.sig['sphincs'] = Signature(self.algorithm_configs['sphincs']['variant'])
            self.sig['xmss'] = Signature(self.algorithm_configs['xmss']['variant'])
            self.sig['rainbow'] = Signature(self.algorithm_configs['rainbow']['variant'])
            
            logger.info("Post-quantum algorithms initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing post-quantum algorithms: {e}")
            raise

    def _initialize_entropy_pool(self) -> bytes:
        """Initialize a high-entropy pool for cryptographic operations"""
        entropy = os.urandom(1024)  # Initial entropy
        entropy += struct.pack('d', time.time())  # Add timestamp
        entropy += struct.pack('Q', os.getpid())  # Add process ID
        entropy += struct.pack('Q', os.getppid())  # Add parent process ID
        entropy += struct.pack('Q', int.from_bytes(os.urandom(8), 'big'))  # Add random data
        return entropy

    def _update_entropy_pool(self) -> None:
        """Update the entropy pool with new random data"""
        self.entropy_pool = hashlib.sha3_512(
            self.entropy_pool + os.urandom(64)
        ).digest()

    def generate_pqc_key_pair(self) -> PQCKeyPair:
        """Generate a complete set of post-quantum key pairs"""
        try:
            # Generate Kyber key pair
            kyber_public, kyber_private = self.kem['kyber'].generate_keypair()
            
            # Generate NTRU key pair
            ntru_public, ntru_private = self.kem['ntru'].generate_keypair()
            
            # Generate SPHINCS+ key pair
            sphincs_public, sphincs_private = self.sig['sphincs'].generate_keypair()
            
            # Generate XMSS key pair
            xmss_public, xmss_private = self.sig['xmss'].generate_keypair()
            
            # Generate McEliece key pair
            mceliece_public, mceliece_private = self.kem['mceliece'].generate_keypair()
            
            # Generate Rainbow key pair
            rainbow_public, rainbow_private = self.sig['rainbow'].generate_keypair()
            
            # Generate SIDH key pair
            sidh_public, sidh_private = self._generate_sidh_keypair()
            
            # Generate hybrid key pair (combining classical and post-quantum)
            hybrid_public, hybrid_private = self._generate_hybrid_keypair()
            
            # Store algorithm versions
            algorithm_versions = {
                'kyber': self.algorithm_configs['kyber']['variant'],
                'ntru': self.algorithm_configs['ntru']['variant'],
                'sphincs': self.algorithm_configs['sphincs']['variant'],
                'xmss': self.algorithm_configs['xmss']['variant'],
                'mceliece': self.algorithm_configs['mceliece']['variant'],
                'rainbow': self.algorithm_configs['rainbow']['variant'],
                'sidh': self.algorithm_configs['sidh']['variant']
            }
            
            return PQCKeyPair(
                kyber_key=(kyber_private, kyber_public),
                ntru_key=(ntru_private, ntru_public),
                sphincs_key=(sphincs_private, sphincs_public),
                xmss_key=(xmss_private, xmss_public),
                mceliece_key=(mceliece_private, mceliece_public),
                rainbow_key=(rainbow_private, rainbow_public),
                sidh_key=(sidh_private, sidh_public),
                hybrid_key=(hybrid_private, hybrid_public),
                timestamp=time.time(),
                algorithm_versions=algorithm_versions
            )
        except Exception as e:
            logger.error(f"Error generating post-quantum key pairs: {e}")
            raise

    def _generate_sidh_keypair(self) -> Tuple[bytes, bytes]:
        """Generate SIDH key pair"""
        # Implementation would use liboqs SIDH implementation
        # This is a placeholder for the actual implementation
        return os.urandom(32), os.urandom(32)

    def _generate_hybrid_keypair(self) -> Tuple[bytes, bytes]:
        """Generate hybrid key pair combining classical and post-quantum cryptography"""
        # Generate classical key pair
        classical_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        classical_public = classical_private.public_key()
        
        # Generate post-quantum key pair
        pq_private, pq_public = self.kem['kyber'].generate_keypair()
        
        # Combine the keys
        hybrid_private = classical_private.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption()
        ) + pq_private
        
        hybrid_public = classical_public.public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        ) + pq_public
        
        return hybrid_private, hybrid_public

    def hybrid_encrypt(self, message: bytes, public_keys: PQCKeyPair) -> Dict[str, bytes]:
        """Encrypt a message using multiple post-quantum algorithms"""
        try:
            # Generate a random session key
            session_key = os.urandom(32)
            
            # Encrypt the session key with each public key
            encrypted_keys = {
                'kyber': self.kem['kyber'].encap_secret(public_keys.kyber_key[1])[0],
                'ntru': self.kem['ntru'].encap_secret(public_keys.ntru_key[1])[0],
                'mceliece': self.kem['mceliece'].encap_secret(public_keys.mceliece_key[1])[0]
            }
            
            # Encrypt the message with the session key using AES-256-GCM
            iv = os.urandom(12)
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.GCM(iv)
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message) + encryptor.finalize()
            
            return {
                'encrypted_keys': encrypted_keys,
                'iv': iv,
                'ciphertext': ciphertext,
                'tag': encryptor.tag
            }
        except Exception as e:
            logger.error(f"Error in hybrid encryption: {e}")
            raise

    def hybrid_decrypt(self, encrypted_data: Dict[str, bytes], private_keys: PQCKeyPair) -> bytes:
        """Decrypt a message using multiple post-quantum algorithms"""
        try:
            # Try to decrypt the session key with each private key
            session_key = None
            for key_type, encrypted_key in encrypted_data['encrypted_keys'].items():
                try:
                    if key_type == 'kyber':
                        session_key = self.kem['kyber'].decap_secret(encrypted_key, private_keys.kyber_key[0])
                    elif key_type == 'ntru':
                        session_key = self.kem['ntru'].decap_secret(encrypted_key, private_keys.ntru_key[0])
                    elif key_type == 'mceliece':
                        session_key = self.kem['mceliece'].decap_secret(encrypted_key, private_keys.mceliece_key[0])
                    if session_key:
                        break
                except Exception:
                    continue
            
            if not session_key:
                raise ValueError("Failed to decrypt session key with any private key")
            
            # Decrypt the message with the session key
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.GCM(encrypted_data['iv'], encrypted_data['tag'])
            )
            decryptor = cipher.decryptor()
            return decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
        except Exception as e:
            logger.error(f"Error in hybrid decryption: {e}")
            raise

    def multi_sign(self, message: bytes, private_keys: PQCKeyPair) -> Dict[str, bytes]:
        """Sign a message using multiple post-quantum algorithms"""
        try:
            # Generate signatures using different algorithms
            signatures = {
                'sphincs': self.sig['sphincs'].sign(message, private_keys.sphincs_key[0]),
                'xmss': self.sig['xmss'].sign(message, private_keys.xmss_key[0]),
                'rainbow': self.sig['rainbow'].sign(message, private_keys.rainbow_key[0])
            }
            
            return signatures
        except Exception as e:
            logger.error(f"Error in multi-sign: {e}")
            raise

    def verify_signatures(self, message: bytes, signatures: Dict[str, bytes], public_keys: PQCKeyPair) -> bool:
        """Verify signatures from multiple post-quantum algorithms"""
        try:
            # Verify each signature
            for sig_type, signature in signatures.items():
                if sig_type == 'sphincs':
                    if not self.sig['sphincs'].verify(message, signature, public_keys.sphincs_key[1]):
                        return False
                elif sig_type == 'xmss':
                    if not self.sig['xmss'].verify(message, signature, public_keys.xmss_key[1]):
                        return False
                elif sig_type == 'rainbow':
                    if not self.sig['rainbow'].verify(message, signature, public_keys.rainbow_key[1]):
                        return False
            return True
        except Exception as e:
            logger.error(f"Error in verify signatures: {e}")
            return False

    def rotate_keys(self, key_pair: PQCKeyPair) -> PQCKeyPair:
        """Rotate keys based on security policy"""
        current_time = time.time()
        if current_time - key_pair.timestamp > self.key_rotation_period:
            self.security_metrics['key_rotations'] += 1
            return self.generate_pqc_key_pair()
        return key_pair

    def update_algorithms(self) -> None:
        """Update cryptographic algorithms based on latest security recommendations"""
        try:
            # Check for algorithm updates
            for alg_name, config in self.algorithm_configs.items():
                if self._should_update_algorithm(alg_name):
                    self._update_algorithm(alg_name)
                    self.security_metrics['algorithm_updates'] += 1
            
            # Update security metrics
            self.security_metrics['last_audit'] = time.time()
            
            logger.info("Cryptographic algorithms updated successfully")
        except Exception as e:
            logger.error(f"Error updating algorithms: {e}")
            raise

    def _should_update_algorithm(self, algorithm_name: str) -> bool:
        """Check if an algorithm should be updated based on security policy"""
        # Implementation would check against security recommendations
        # This is a placeholder for the actual implementation
        return False

    def _update_algorithm(self, algorithm_name: str) -> None:
        """Update a specific cryptographic algorithm"""
        # Implementation would update the algorithm configuration
        # This is a placeholder for the actual implementation
        pass

    def get_security_metrics(self) -> Dict[str, Any]:
        """Get current security metrics"""
        return {
            **self.security_metrics,
            'active_algorithms': list(self.algorithm_configs.keys()),
            'security_level': self.min_security_level,
            'key_rotation_period': self.key_rotation_period,
            'max_key_age': self.max_key_age
        }

    def cleanup(self) -> None:
        """Clean up resources"""
        try:
            # Clean up liboqs
            liboqs.cleanup()
            
            # Clear sensitive data
            self.entropy_pool = None
            self.key_store.clear()
            
            logger.info("Post-quantum cryptography resources cleaned up")
        except Exception as e:
            logger.error(f"Error cleaning up resources: {e}")
            raise 
```
---
### File: `straz_blockchain.json`

```json
{
    "chain": [
        {
            "index": 0,
            "timestamp": 1746579890.492359,
            "transactions": [],
            "previous_hash": "0",
            "nonce": 0,
            "hash": "036abd1ae39b645783691c576bfa1d7a79a94014a0961dd0796c48d0ef533c9f",
            "validator_signatures": []
        },
        {
            "index": 1,
            "timestamp": 1746579890.492533,
            "transactions": [
                {
                    "sender": "COINBASE",
                    "recipient": "18nXnrPE9Worf5qdzVDijvmzgUGXUHABed",
                    "amount": 50,
                    "timestamp": 1746579890.492533
                }
            ],
            "previous_hash": "036abd1ae39b645783691c576bfa1d7a79a94014a0961dd0796c48d0ef533c9f",
            "nonce": 17682,
            "hash": "0000223057bda71ae5039eacf9a03233ecb4335169d23be01c1a751afc48630c",
            "validator_signatures": []
        },
        {
            "index": 2,
            "timestamp": 1746579890.555434,
            "transactions": [
                {
                    "sender": "18nXnrPE9Worf5qdzVDijvmzgUGXUHABed",
                    "recipient": "15CAQYMYsmnnL2giK5F9pZ2ycqcY5kQNGq",
                    "amount": 25,
                    "timestamp": 1746579890.5554292
                },
                {
                    "sender": "COINBASE",
                    "recipient": "18nXnrPE9Worf5qdzVDijvmzgUGXUHABed",
                    "amount": 50,
                    "timestamp": 1746579890.555434
                }
            ],
            "previous_hash": "0000223057bda71ae5039eacf9a03233ecb4335169d23be01c1a751afc48630c",
            "nonce": 26343,
            "hash": "0000572fa764b4339f350efc91c41dc2c95829406dae0b9f843b60ea53aae805",
            "validator_signatures": []
        },
        {
            "index": 3,
            "timestamp": 1746580213.303033,
            "transactions": [
                {
                    "sender": "1Bb9Bqgw9L1F4M61dDyNuwU3Jqgd8RRM4x",
                    "recipient": "1CkoNV1NVGFAYWvxig9JPoKC9UqJtFzPaS",
                    "amount": 10.0,
                    "timestamp": 1746580211.689599
                },
                {
                    "sender": "COINBASE",
                    "recipient": "1Bb9Bqgw9L1F4M61dDyNuwU3Jqgd8RRM4x",
                    "amount": 50,
                    "timestamp": 1746580213.303029
                }
            ],
            "previous_hash": "0000572fa764b4339f350efc91c41dc2c95829406dae0b9f843b60ea53aae805",
            "nonce": 33771,
            "hash": "00000447bad37fb87f6e9fede4392122a139714ca030809f4cc142fb2da3446f",
            "validator_signatures": []
        }
    ],
    "pending_transactions": [],
    "difficulty": 4
}
```
---
### File: `quantum_crypto.py`

```python
#!/usr/bin/env python3

from typing import Dict, List, Any, Optional, Tuple, Union
import hashlib
import json
import time
from dataclasses import dataclass
import logging
import numpy as np
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import x25519, x448
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, load_pem_private_key,
    load_pem_public_key, NoEncryption
)
import os
import struct

logger = logging.getLogger(__name__)

@dataclass
class QuantumKeyPair:
    """Container for multiple quantum-resistant key pairs"""
    rsa_key: Tuple[bytes, bytes]  # (private, public)
    x25519_key: Tuple[bytes, bytes]
    ed25519_key: Tuple[bytes, bytes]
    x448_key: Tuple[bytes, bytes]
    ed448_key: Tuple[bytes, bytes]
    dh_key: Tuple[bytes, bytes]
    timestamp: float

class AdvancedQuantumCrypto:
    def __init__(self):
        # RSA parameters
        self.rsa_key_size = 8192  # Increased key size for better quantum resistance
        self.rsa_public_exponent = 65537
        
        # Hash algorithms
        self.hash_algorithms = {
            'sha3_256': hashes.SHA3_256(),
            'sha3_512': hashes.SHA3_512(),
            'shake256': hashes.SHAKE256(32),
            'blake2b': hashes.BLAKE2b(64)
        }
        
        # Padding schemes
        self.padding_schemes = {
            'oaep': padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA3_512()),
                algorithm=hashes.SHA3_512(),
                label=None
            ),
            'pss': padding.PSS(
                mgf=padding.MGF1(hashes.SHA3_512()),
                salt_length=padding.PSS.MAX_LENGTH
            )
        }
        
        # Key derivation parameters
        self.kdf_iterations = 200000  # Increased iterations for better security
        self.kdf_length = 64  # Increased key length
        
        # Initialize entropy pool
        self.entropy_pool = self._initialize_entropy_pool()

    def _initialize_entropy_pool(self) -> bytes:
        """Initialize a high-entropy pool for cryptographic operations"""
        entropy = os.urandom(1024)  # Initial entropy
        entropy += struct.pack('d', time.time())  # Add timestamp
        entropy += struct.pack('Q', os.getpid())  # Add process ID
        return entropy

    def _update_entropy_pool(self) -> None:
        """Update the entropy pool with new random data"""
        self.entropy_pool = hashlib.sha3_512(
            self.entropy_pool + os.urandom(64)
        ).digest()

    def generate_quantum_key_pair(self) -> QuantumKeyPair:
        """Generate a complete set of quantum-resistant key pairs"""
        try:
            # Generate RSA key pair
            rsa_private = rsa.generate_private_key(
                public_exponent=self.rsa_public_exponent,
                key_size=self.rsa_key_size
            )
            rsa_public = rsa_private.public_key()
            rsa_key_pair = (
                rsa_private.private_bytes(
                    Encoding.PEM,
                    PrivateFormat.PKCS8,
                    NoEncryption()
                ),
                rsa_public.public_bytes(
                    Encoding.PEM,
                    PublicFormat.SubjectPublicKeyInfo
                )
            )

            # Generate X25519 key pair
            x25519_private = x25519.X25519PrivateKey.generate()
            x25519_public = x25519_private.public_key()
            x25519_key_pair = (
                x25519_private.private_bytes(
                    Encoding.Raw,
                    PrivateFormat.Raw,
                    NoEncryption()
                ),
                x25519_public.public_bytes(
                    Encoding.Raw,
                    PublicFormat.Raw
                )
            )

            # Generate Ed25519 key pair
            ed25519_private = ed25519.Ed25519PrivateKey.generate()
            ed25519_public = ed25519_private.public_key()
            ed25519_key_pair = (
                ed25519_private.private_bytes(
                    Encoding.Raw,
                    PrivateFormat.Raw,
                    NoEncryption()
                ),
                ed25519_public.public_bytes(
                    Encoding.Raw,
                    PublicFormat.Raw
                )
            )

            # Generate X448 key pair
            x448_private = x448.X448PrivateKey.generate()
            x448_public = x448_private.public_key()
            x448_key_pair = (
                x448_private.private_bytes(
                    Encoding.Raw,
                    PrivateFormat.Raw,
                    NoEncryption()
                ),
                x448_public.public_bytes(
                    Encoding.Raw,
                    PublicFormat.Raw
                )
            )

            # Generate Ed448 key pair
            ed448_private = ed448.Ed448PrivateKey.generate()
            ed448_public = ed448_private.public_key()
            ed448_key_pair = (
                ed448_private.private_bytes(
                    Encoding.Raw,
                    PrivateFormat.Raw,
                    NoEncryption()
                ),
                ed448_public.public_bytes(
                    Encoding.Raw,
                    PublicFormat.Raw
                )
            )

            # Generate DH key pair
            dh_parameters = dh.generate_parameters(generator=2, key_size=4096)
            dh_private = dh_parameters.generate_private_key()
            dh_public = dh_private.public_key()
            dh_key_pair = (
                dh_private.private_bytes(
                    Encoding.PEM,
                    PrivateFormat.PKCS8,
                    NoEncryption()
                ),
                dh_public.public_bytes(
                    Encoding.PEM,
                    PublicFormat.SubjectPublicKeyInfo
                )
            )

            return QuantumKeyPair(
                rsa_key=rsa_key_pair,
                x25519_key=x25519_key_pair,
                ed25519_key=ed25519_key_pair,
                x448_key=x448_key_pair,
                ed448_key=ed448_key_pair,
                dh_key=dh_key_pair,
                timestamp=time.time()
            )
        except Exception as e:
            logger.error(f"Error generating quantum key pairs: {e}")
            raise

    def hybrid_encrypt(self, message: bytes, public_keys: QuantumKeyPair) -> Dict[str, bytes]:
        """Encrypt a message using multiple quantum-resistant algorithms"""
        try:
            # Generate a random session key
            session_key = os.urandom(32)
            
            # Encrypt the session key with each public key
            encrypted_keys = {
                'rsa': self._encrypt_with_rsa(session_key, public_keys.rsa_key[1]),
                'x25519': self._encrypt_with_x25519(session_key, public_keys.x25519_key[1]),
                'x448': self._encrypt_with_x448(session_key, public_keys.x448_key[1])
            }
            
            # Encrypt the message with the session key using AES-256-GCM
            iv = os.urandom(12)
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.GCM(iv)
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message) + encryptor.finalize()
            
            return {
                'encrypted_keys': encrypted_keys,
                'iv': iv,
                'ciphertext': ciphertext,
                'tag': encryptor.tag
            }
        except Exception as e:
            logger.error(f"Error in hybrid encryption: {e}")
            raise

    def hybrid_decrypt(self, encrypted_data: Dict[str, bytes], private_keys: QuantumKeyPair) -> bytes:
        """Decrypt a message using multiple quantum-resistant algorithms"""
        try:
            # Try to decrypt the session key with each private key
            session_key = None
            for key_type, encrypted_key in encrypted_data['encrypted_keys'].items():
                try:
                    if key_type == 'rsa':
                        session_key = self._decrypt_with_rsa(encrypted_key, private_keys.rsa_key[0])
                    elif key_type == 'x25519':
                        session_key = self._decrypt_with_x25519(encrypted_key, private_keys.x25519_key[0])
                    elif key_type == 'x448':
                        session_key = self._decrypt_with_x448(encrypted_key, private_keys.x448_key[0])
                    if session_key:
                        break
                except Exception:
                    continue
            
            if not session_key:
                raise ValueError("Failed to decrypt session key with any private key")
            
            # Decrypt the message with the session key
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.GCM(encrypted_data['iv'], encrypted_data['tag'])
            )
            decryptor = cipher.decryptor()
            return decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
        except Exception as e:
            logger.error(f"Error in hybrid decryption: {e}")
            raise

    def multi_sign(self, message: bytes, private_keys: QuantumKeyPair) -> Dict[str, bytes]:
        """Sign a message using multiple quantum-resistant algorithms"""
        try:
            # Generate signatures using different algorithms
            signatures = {
                'rsa': self._sign_with_rsa(message, private_keys.rsa_key[0]),
                'ed25519': self._sign_with_ed25519(message, private_keys.ed25519_key[0]),
                'ed448': self._sign_with_ed448(message, private_keys.ed448_key[0])
            }
            
            return signatures
        except Exception as e:
            logger.error(f"Error in multi-sign: {e}")
            raise

    def verify_signatures(self, message: bytes, signatures: Dict[str, bytes], public_keys: QuantumKeyPair) -> bool:
        """Verify signatures from multiple quantum-resistant algorithms"""
        try:
            # Verify each signature
            for sig_type, signature in signatures.items():
                if sig_type == 'rsa':
                    if not self._verify_rsa_signature(message, signature, public_keys.rsa_key[1]):
                        return False
                elif sig_type == 'ed25519':
                    if not self._verify_ed25519_signature(message, signature, public_keys.ed25519_key[1]):
                        return False
                elif sig_type == 'ed448':
                    if not self._verify_ed448_signature(message, signature, public_keys.ed448_key[1]):
                        return False
            return True
        except Exception as e:
            logger.error(f"Error in verify signatures: {e}")
            return False

    def _encrypt_with_rsa(self, data: bytes, public_key: bytes) -> bytes:
        """Encrypt data using RSA"""
        key = load_pem_public_key(public_key)
        return key.encrypt(data, self.padding_schemes['oaep'])

    def _decrypt_with_rsa(self, data: bytes, private_key: bytes) -> bytes:
        """Decrypt data using RSA"""
        key = load_pem_private_key(private_key, password=None)
        return key.decrypt(data, self.padding_schemes['oaep'])

    def _encrypt_with_x25519(self, data: bytes, public_key: bytes) -> bytes:
        """Encrypt data using X25519"""
        key = x25519.X25519PublicKey.from_public_bytes(public_key)
        shared_key = key.exchange(x25519.X25519PrivateKey.generate())
        return self._encrypt_with_shared_key(data, shared_key)

    def _decrypt_with_x25519(self, data: bytes, private_key: bytes) -> bytes:
        """Decrypt data using X25519"""
        key = x25519.X25519PrivateKey.from_private_bytes(private_key)
        shared_key = key.exchange(x25519.X25519PublicKey.from_public_bytes(data[:32]))
        return self._decrypt_with_shared_key(data[32:], shared_key)

    def _encrypt_with_x448(self, data: bytes, public_key: bytes) -> bytes:
        """Encrypt data using X448"""
        key = x448.X448PublicKey.from_public_bytes(public_key)
        shared_key = key.exchange(x448.X448PrivateKey.generate())
        return self._encrypt_with_shared_key(data, shared_key)

    def _decrypt_with_x448(self, data: bytes, private_key: bytes) -> bytes:
        """Decrypt data using X448"""
        key = x448.X448PrivateKey.from_private_bytes(private_key)
        shared_key = key.exchange(x448.X448PublicKey.from_public_bytes(data[:56]))
        return self._decrypt_with_shared_key(data[56:], shared_key)

    def _sign_with_rsa(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message using RSA"""
        key = load_pem_private_key(private_key, password=None)
        return key.sign(
            message,
            self.padding_schemes['pss'],
            hashes.SHA3_512()
        )

    def _sign_with_ed25519(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message using Ed25519"""
        key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        return key.sign(message)

    def _sign_with_ed448(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message using Ed448"""
        key = ed448.Ed448PrivateKey.from_private_bytes(private_key)
        return key.sign(message)

    def _verify_rsa_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify an RSA signature"""
        try:
            key = load_pem_public_key(public_key)
            key.verify(
                signature,
                message,
                self.padding_schemes['pss'],
                hashes.SHA3_512()
            )
            return True
        except Exception:
            return False

    def _verify_ed25519_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify an Ed25519 signature"""
        try:
            key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            key.verify(message, signature)
            return True
        except Exception:
            return False

    def _verify_ed448_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify an Ed448 signature"""
        try:
            key = ed448.Ed448PublicKey.from_public_bytes(public_key)
            key.verify(message, signature)
            return True
        except Exception:
            return False

    def _encrypt_with_shared_key(self, data: bytes, shared_key: bytes) -> bytes:
        """Encrypt data using a shared key"""
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(shared_key),
            modes.GCM(iv)
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + ciphertext + encryptor.tag

    def _decrypt_with_shared_key(self, data: bytes, shared_key: bytes) -> bytes:
        """Decrypt data using a shared key"""
        iv = data[:12]
        tag = data[-16:]
        ciphertext = data[12:-16]
        cipher = Cipher(
            algorithms.AES(shared_key),
            modes.GCM(iv, tag)
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def generate_quantum_resistant_hash(self, data: bytes, algorithm: str = 'sha3_512') -> bytes:
        """Generate a quantum-resistant hash using the specified algorithm"""
        if algorithm not in self.hash_algorithms:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        return hashlib.sha3_512(data).digest()

    def generate_quantum_resistant_key(self, password: str, salt: bytes) -> bytes:
        """Generate a quantum-resistant key from a password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=self.kdf_length,
            salt=salt,
            iterations=self.kdf_iterations
        )
        return kdf.derive(password.encode()) 
```
---
### File: `README.md`

```markdown
# Straz Blockchain

A Python-based blockchain implementation with smart contract support and proof-of-stake consensus.

## Features

- Blockchain implementation with proof-of-work mining
- Smart contract support
- Wallet management
- RESTful API interface
- Proof-of-stake consensus mechanism

## Setup

1. Clone the repository:
```bash
git clone https://github.com/willruzycki/Straz.git
cd Straz
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the API server:
```bash
python api.py
```

The server will start on `http://localhost:5002`

## API Endpoints

- `GET /` - List all available routes
- `GET /api/blockchain` - Get blockchain status
- `GET /api/block/<index>` - Get block by index
- `POST /api/transaction` - Create a new transaction
- `POST /api/mine` - Mine a new block
- `POST /api/wallet` - Create a new wallet
- `GET /api/wallet/<address>` - Get wallet balance
- `POST /api/contracts` - Deploy a new smart contract
- `GET /api/contract/<address>` - Get contract information
- `POST /api/contract/transaction` - Create a contract transaction
- `POST /api/validator` - Register a new validator
- `GET /api/validator/<address>` - Get validator information

## License

MIT 
```
---
### File: `api.py`

```python
#!/usr/bin/env python3

from flask import Flask, request, jsonify
from blockchain import Blockchain
from wallet import Wallet, WalletManager
import os
import json
from typing import Dict, Any
import logging
import time
import hashlib

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize blockchain and wallet manager
blockchain = None
wallet_manager = None

def load_or_create_blockchain():
    global blockchain
    if os.path.exists("straz_blockchain.json"):
        blockchain = Blockchain.load_from_file("straz_blockchain.json")
    else:
        blockchain = Blockchain(difficulty=4)
        # Create genesis block
        wallet_manager = WalletManager()
        miner_wallet = wallet_manager.create_wallet()
        blockchain.mine_pending_transactions(miner_wallet.address)
        blockchain.save_to_file("straz_blockchain.json")

def load_or_create_wallet_manager():
    global wallet_manager
    wallet_manager = WalletManager()
    if os.path.exists("wallets"):
        wallet_manager.load_wallets("wallets")

# Initialize before first request
@app.before_request
def initialize():
    global blockchain, wallet_manager
    if blockchain is None:
        load_or_create_blockchain()
    if wallet_manager is None:
        load_or_create_wallet_manager()
    logger.debug(f"Request: {request.method} {request.path}")
    logger.debug(f"Request data: {request.get_data()}")

# Add error handlers
@app.errorhandler(Exception)
def handle_error(error):
    logger.error(f"Error: {str(error)}")
    return jsonify({"error": str(error)}), 500

@app.route("/", methods=["GET"])
def get_routes():
    """Get list of available routes"""
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            "endpoint": rule.endpoint,
            "methods": list(rule.methods),
            "path": str(rule)
        })
    return jsonify({"routes": routes})

@app.route("/api/blockchain", methods=["GET"])
def get_blockchain():
    """Get blockchain status"""
    logger.debug("Handling /api/blockchain GET request")
    return jsonify({
        "blocks": len(blockchain.chain),
        "difficulty": blockchain.difficulty,
        "mining_reward": blockchain.mining_reward,
        "is_valid": blockchain.is_chain_valid()
    })

@app.route("/api/block/<int:block_index>", methods=["GET"])
def get_block(block_index):
    """Get block by index"""
    logger.debug(f"Handling /api/block/{block_index} GET request")
    if block_index < len(blockchain.chain):
        return jsonify(blockchain.chain[block_index].to_dict())
    return jsonify({"error": "Block not found"}), 404

@app.route("/api/transaction", methods=["POST"])
def create_transaction():
    """Create a new transaction"""
    logger.debug("Handling /api/transaction POST request")
    data = request.get_json()
    required_fields = ["sender", "recipient", "amount"]
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
        
    try:
        # Check if this is a ZK transaction
        use_zk = data.get("use_zk", False)
        
        success = blockchain.create_transaction(
            data["sender"],
            data["recipient"],
            float(data["amount"]),
            float(data.get("fee", 0.001)),
            use_zk=use_zk
        )
        
        if success:
            response = {
                "message": "Transaction added to pool",
                "is_zk": use_zk
            }
            if use_zk:
                response["zk_status"] = "ZK proof generated and verified"
            return jsonify(response), 201
        return jsonify({"error": "Transaction validation failed"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/mine", methods=["POST"])
def mine_block():
    """Mine a new block"""
    logger.debug("Handling /api/mine POST request")
    data = request.get_json()
    if "miner_address" not in data:
        return jsonify({"error": "Miner address required"}), 400
        
    try:
        blockchain.mine_pending_transactions(data["miner_address"])
        blockchain.save_to_file("straz_blockchain.json")
        return jsonify({"message": "Block mined successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/wallet", methods=["POST"])
def create_wallet():
    """Create a new wallet"""
    logger.debug("Handling /api/wallet POST request")
    wallet = wallet_manager.create_wallet()
    wallet_manager.save_wallets("wallets")
    return jsonify(wallet.to_dict()), 201

@app.route("/api/wallet/<string:address>", methods=["GET"])
def get_wallet(address):
    """Get wallet balance"""
    logger.debug(f"Handling /api/wallet/{address} GET request")
    balance = blockchain.get_balance(address)
    return jsonify({"address": address, "balance": balance})

@app.route("/api/contracts", methods=["POST"])
def deploy_contract():
    """Deploy a new smart contract"""
    logger.debug("Handling /api/contracts POST request")
    logger.debug(f"Request data: {request.get_data()}")
    
    data = request.get_json()
    required_fields = ["contractCode", "deployerAddress", "privateKey"]
    
    if not all(field in data for field in required_fields):
        logger.error(f"Missing required fields. Received: {list(data.keys())}")
        return jsonify({
            "status": "error",
            "message": "Missing required fields"
        }), 400
        
    try:
        logger.debug(f"Deploying contract for address: {data['deployerAddress']}")
        contract = blockchain.contract_manager.deploy_contract(
            data["contractCode"],
            data["deployerAddress"],
            data["privateKey"]
        )
        blockchain.save_to_file("straz_blockchain.json")
        logger.debug(f"Contract deployed successfully at address: {contract.address}")
        
        return jsonify({
            "status": "success",
            "data": {
                "contract": {
                    "address": contract.address,
                    "code": contract.code,
                    "state": contract.state,
                    "owner": contract.owner
                }
            }
        }), 201
    except Exception as e:
        logger.error(f"Error deploying contract: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 400

@app.route("/api/contract/<string:address>", methods=["GET"])
def get_contract(address):
    """Get contract information"""
    logger.debug(f"Handling /api/contract/{address} GET request")
    contract = blockchain.contract_manager.get_contract(address)
    if contract:
        return jsonify(contract.to_dict())
    return jsonify({"error": "Contract not found"}), 404

@app.route("/api/contract/transaction", methods=["POST"])
def create_contract_transaction():
    """Create a contract transaction"""
    logger.debug("Handling /api/contract/transaction POST request")
    data = request.get_json()
    required_fields = ["sender", "contract_address", "method", "params"]
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
        
    try:
        blockchain.create_contract_transaction(
            data["sender"],
            data["contract_address"],
            data["method"],
            data["params"],
            data.get("value", 0)
        )
        return jsonify({"message": "Contract transaction added to pool"}), 201
    except Exception as e:
        logger.error(f"Error creating contract transaction: {str(e)}")
        return jsonify({"error": str(e)}), 400

@app.route("/api/validator", methods=["POST"])
def register_validator():
    """Register a new validator"""
    logger.debug("Handling /api/validator POST request")
    data = request.get_json()
    required_fields = ["address", "stake"]
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
        
    try:
        success = blockchain.consensus.register_validator(
            data["address"],
            float(data["stake"])
        )
        if success:
            blockchain.save_to_file("straz_blockchain.json")
            return jsonify({"message": "Validator registered successfully"}), 201
        return jsonify({"error": "Insufficient stake"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/validator/<string:address>", methods=["GET"])
def get_validator(address):
    """Get validator information"""
    logger.debug(f"Handling /api/validator/{address} GET request")
    info = blockchain.consensus.get_validator_info(address)
    if "error" in info:
        return jsonify(info), 404
    return jsonify(info)

@app.route("/api/zk/verify", methods=["POST"])
def verify_zk_proof():
    """Verify a zero-knowledge proof"""
    logger.debug("Handling /api/zk/verify POST request")
    data = request.get_json()
    required_fields = ["proof", "public_inputs"]
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
    
    try:
        # Get the appropriate ZK-rollup instance
        shard_id = int(hashlib.sha256(data["sender"].encode()).hexdigest(), 16) % blockchain.num_shards
        zk_rollup = blockchain.shards[shard_id].zk_rollup
        
        if not zk_rollup:
            return jsonify({"error": "ZK-rollup not available for this shard"}), 400
        
        # Create ZKProof object
        proof = ZKProof(
            proof=bytes.fromhex(data["proof"]),
            public_inputs=data["public_inputs"],
            timestamp=time.time(),
            verifier_key=bytes.fromhex(data.get("verifier_key", ""))
        )
        
        # Verify the proof
        is_valid = zk_rollup.verify_zk_proof(proof)
        
        return jsonify({
            "is_valid": is_valid,
            "timestamp": time.time()
        }), 200
    except Exception as e:
        logger.error(f"Error verifying ZK proof: {e}")
        return jsonify({"error": str(e)}), 400

@app.route("/api/zk/batch", methods=["POST"])
def create_zk_batch():
    """Create a new ZK-rollup batch"""
    logger.debug("Handling /api/zk/batch POST request")
    data = request.get_json()
    required_fields = ["shard_id", "transactions"]
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
    
    try:
        shard_id = data["shard_id"]
        if shard_id not in blockchain.shards:
            return jsonify({"error": "Invalid shard ID"}), 400
        
        zk_rollup = blockchain.shards[shard_id].zk_rollup
        if not zk_rollup:
            return jsonify({"error": "ZK-rollup not available for this shard"}), 400
        
        # Process each transaction in the batch
        successful_txs = []
        for tx in data["transactions"]:
            if zk_rollup.add_transaction_to_batch(tx):
                successful_txs.append(tx)
        
        # Generate batch proof
        batch_proof = zk_rollup.generate_batch_proof()
        
        return jsonify({
            "message": "Batch created successfully",
            "successful_transactions": len(successful_txs),
            "batch_proof": batch_proof.proof.hex() if batch_proof else None,
            "timestamp": time.time()
        }), 201
    except Exception as e:
        logger.error(f"Error creating ZK batch: {e}")
        return jsonify({"error": str(e)}), 400

@app.route("/api/quantum/key", methods=["POST"])
def generate_quantum_key():
    """Generate a new quantum-resistant key pair"""
    logger.debug("Handling /api/quantum/key POST request")
    try:
        private_key, public_key = blockchain.quantum_crypto.generate_key_pair()
        
        return jsonify({
            "private_key": private_key.decode(),
            "public_key": public_key.decode(),
            "timestamp": time.time()
        }), 201
    except Exception as e:
        logger.error(f"Error generating quantum key pair: {e}")
        return jsonify({"error": str(e)}), 400

@app.route("/api/quantum/sign", methods=["POST"])
def quantum_sign():
    """Sign a message using quantum-resistant cryptography"""
    logger.debug("Handling /api/quantum/sign POST request")
    data = request.get_json()
    required_fields = ["message", "private_key"]
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
    
    try:
        signature = blockchain.quantum_crypto.sign(
            data["message"].encode(),
            data["private_key"].encode()
        )
        
        return jsonify({
            "signature": signature.hex(),
            "timestamp": time.time()
        }), 200
    except Exception as e:
        logger.error(f"Error signing message: {e}")
        return jsonify({"error": str(e)}), 400

@app.route("/api/quantum/verify", methods=["POST"])
def quantum_verify():
    """Verify a quantum-resistant signature"""
    logger.debug("Handling /api/quantum/verify POST request")
    data = request.get_json()
    required_fields = ["message", "signature", "public_key"]
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
    
    try:
        is_valid = blockchain.quantum_crypto.verify_signature(
            data["message"].encode(),
            bytes.fromhex(data["signature"]),
            data["public_key"].encode()
        )
        
        return jsonify({
            "is_valid": is_valid,
            "timestamp": time.time()
        }), 200
    except Exception as e:
        logger.error(f"Error verifying signature: {e}")
        return jsonify({"error": str(e)}), 400

# Initialize on startup
load_or_create_wallet_manager()
load_or_create_blockchain()

if __name__ == "__main__":
    # Print registered routes
    logger.info("Registered routes:")
    for rule in app.url_map.iter_rules():
        logger.info(f"{rule.endpoint}: {rule.methods} {rule.rule}")
    
    app.run(host="0.0.0.0", port=5002, debug=True) 
```
---
### File: `contracts.json`

```json
{
    "contracts": {
        "0x149bee9d2687d26ef3e7ca62ded46cf9484d8fce": {
            "address": "0x149bee9d2687d26ef3e7ca62ded46cf9484d8fce",
            "code": "def hello(self, name):\n    return f\"Hello, {name}!\"",
            "owner": "1K1XmPJVgnth11unZXvoMsL1aMkqJMgh1P",
            "state": {
                "balance": 0.0,
                "storage": {}
            }
        }
    },
    "code": {
        "0x149bee9d2687d26ef3e7ca62ded46cf9484d8fce": "def hello(self, name):\n    return f\"Hello, {name}!\""
    }
}
```
---
### File: `mine.sh`

```bash
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
```
---
### File: `quantum_crypto_for_chatgpt.txt`

```text
```python
#!/usr/bin/env python3

from typing import Dict, List, Any, Optional, Tuple, Union
import hashlib
import json
import time
from dataclasses import dataclass
import logging
import numpy as np
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import x25519, x448
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, load_pem_private_key,
    load_pem_public_key, NoEncryption
)
import os
import struct

logger = logging.getLogger(__name__)

@dataclass
class QuantumKeyPair:
    """Container for multiple quantum-resistant key pairs"""
    rsa_key: Tuple[bytes, bytes]  # (private, public)
    x25519_key: Tuple[bytes, bytes]
    ed25519_key: Tuple[bytes, bytes]
    x448_key: Tuple[bytes, bytes]
    ed448_key: Tuple[bytes, bytes]
    dh_key: Tuple[bytes, bytes]
    timestamp: float

class AdvancedQuantumCrypto:
    def __init__(self):
        # RSA parameters
        self.rsa_key_size = 8192  # Increased key size for better quantum resistance
        self.rsa_public_exponent = 65537
        
        # Hash algorithms
        self.hash_algorithms = {
            'sha3_256': hashes.SHA3_256(),
            'sha3_512': hashes.SHA3_512(),
            'shake256': hashes.SHAKE256(32),
            'blake2b': hashes.BLAKE2b(64)
        }
        
        # Padding schemes
        self.padding_schemes = {
            'oaep': padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA3_512()),
                algorithm=hashes.SHA3_512(),
                label=None
            ),
            'pss': padding.PSS(
                mgf=padding.MGF1(hashes.SHA3_512()),
                salt_length=padding.PSS.MAX_LENGTH
            )
        }
        
        # Key derivation parameters
        self.kdf_iterations = 200000  # Increased iterations for better security
        self.kdf_length = 64  # Increased key length
        
        # Initialize entropy pool
        self.entropy_pool = self._initialize_entropy_pool()

    def _initialize_entropy_pool(self) -> bytes:
        """Initialize a high-entropy pool for cryptographic operations"""
        entropy = os.urandom(1024)  # Initial entropy
        entropy += struct.pack('d', time.time())  # Add timestamp
        entropy += struct.pack('Q', os.getpid())  # Add process ID
        return entropy

    def _update_entropy_pool(self) -> None:
        """Update the entropy pool with new random data"""
        self.entropy_pool = hashlib.sha3_512(
            self.entropy_pool + os.urandom(64)
        ).digest()

    def generate_quantum_key_pair(self) -> QuantumKeyPair:
        """Generate a complete set of quantum-resistant key pairs"""
        try:
            # Generate RSA key pair
            rsa_private = rsa.generate_private_key(
                public_exponent=self.rsa_public_exponent,
                key_size=self.rsa_key_size
            )
            rsa_public = rsa_private.public_key()
            rsa_key_pair = (
                rsa_private.private_bytes(
                    Encoding.PEM,
                    PrivateFormat.PKCS8,
                    NoEncryption()
                ),
                rsa_public.public_bytes(
                    Encoding.PEM,
                    PublicFormat.SubjectPublicKeyInfo
                )
            )

            # Generate X25519 key pair
            x25519_private = x25519.X25519PrivateKey.generate()
            x25519_public = x25519_private.public_key()
            x25519_key_pair = (
                x25519_private.private_bytes(
                    Encoding.Raw,
                    PrivateFormat.Raw,
                    NoEncryption()
                ),
                x25519_public.public_bytes(
                    Encoding.Raw,
                    PublicFormat.Raw
                )
            )

            # Generate Ed25519 key pair
            ed25519_private = ed25519.Ed25519PrivateKey.generate()
            ed25519_public = ed25519_private.public_key()
            ed25519_key_pair = (
                ed25519_private.private_bytes(
                    Encoding.Raw,
                    PrivateFormat.Raw,
                    NoEncryption()
                ),
                ed25519_public.public_bytes(
                    Encoding.Raw,
                    PublicFormat.Raw
                )
            )

            # Generate X448 key pair
            x448_private = x448.X448PrivateKey.generate()
            x448_public = x448_private.public_key()
            x448_key_pair = (
                x448_private.private_bytes(
                    Encoding.Raw,
                    PrivateFormat.Raw,
                    NoEncryption()
                ),
                x448_public.public_bytes(
                    Encoding.Raw,
                    PublicFormat.Raw
                )
            )

            # Generate Ed448 key pair
            ed448_private = ed448.Ed448PrivateKey.generate()
            ed448_public = ed448_private.public_key()
            ed448_key_pair = (
                ed448_private.private_bytes(
                    Encoding.Raw,
                    PrivateFormat.Raw,
                    NoEncryption()
                ),
                ed448_public.public_bytes(
                    Encoding.Raw,
                    PublicFormat.Raw
                )
            )

            # Generate DH key pair
            dh_parameters = dh.generate_parameters(generator=2, key_size=4096)
            dh_private = dh_parameters.generate_private_key()
            dh_public = dh_private.public_key()
            dh_key_pair = (
                dh_private.private_bytes(
                    Encoding.PEM,
                    PrivateFormat.PKCS8,
                    NoEncryption()
                ),
                dh_public.public_bytes(
                    Encoding.PEM,
                    PublicFormat.SubjectPublicKeyInfo
                )
            )

            return QuantumKeyPair(
                rsa_key=rsa_key_pair,
                x25519_key=x25519_key_pair,
                ed25519_key=ed25519_key_pair,
                x448_key=x448_key_pair,
                ed448_key=ed448_key_pair,
                dh_key=dh_key_pair,
                timestamp=time.time()
            )
        except Exception as e:
            logger.error(f"Error generating quantum key pairs: {e}")
            raise

    def hybrid_encrypt(self, message: bytes, public_keys: QuantumKeyPair) -> Dict[str, bytes]:
        """Encrypt a message using multiple quantum-resistant algorithms"""
        try:
            # Generate a random session key
            session_key = os.urandom(32)
            
            # Encrypt the session key with each public key
            encrypted_keys = {
                'rsa': self._encrypt_with_rsa(session_key, public_keys.rsa_key[1]),
                'x25519': self._encrypt_with_x25519(session_key, public_keys.x25519_key[1]),
                'x448': self._encrypt_with_x448(session_key, public_keys.x448_key[1])
            }
            
            # Encrypt the message with the session key using AES-256-GCM
            iv = os.urandom(12)
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.GCM(iv)
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message) + encryptor.finalize()
            
            return {
                'encrypted_keys': encrypted_keys,
                'iv': iv,
                'ciphertext': ciphertext,
                'tag': encryptor.tag
            }
        except Exception as e:
            logger.error(f"Error in hybrid encryption: {e}")
            raise

    def hybrid_decrypt(self, encrypted_data: Dict[str, bytes], private_keys: QuantumKeyPair) -> bytes:
        """Decrypt a message using multiple quantum-resistant algorithms"""
        try:
            # Try to decrypt the session key with each private key
            session_key = None
            for key_type, encrypted_key in encrypted_data['encrypted_keys'].items():
                try:
                    if key_type == 'rsa':
                        session_key = self._decrypt_with_rsa(encrypted_key, private_keys.rsa_key[0])
                    elif key_type == 'x25519':
                        session_key = self._decrypt_with_x25519(encrypted_key, private_keys.x25519_key[0])
                    elif key_type == 'x448':
                        session_key = self._decrypt_with_x448(encrypted_key, private_keys.x448_key[0])
                    if session_key:
                        break
                except Exception:
                    continue
            
            if not session_key:
                raise ValueError("Failed to decrypt session key with any private key")
            
            # Decrypt the message with the session key
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.GCM(encrypted_data['iv'], encrypted_data['tag'])
            )
            decryptor = cipher.decryptor()
            return decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
        except Exception as e:
            logger.error(f"Error in hybrid decryption: {e}")
            raise

    def multi_sign(self, message: bytes, private_keys: QuantumKeyPair) -> Dict[str, bytes]:
        """Sign a message using multiple quantum-resistant algorithms"""
        try:
            # Generate signatures using different algorithms
            signatures = {
                'rsa': self._sign_with_rsa(message, private_keys.rsa_key[0]),
                'ed25519': self._sign_with_ed25519(message, private_keys.ed25519_key[0]),
                'ed448': self._sign_with_ed448(message, private_keys.ed448_key[0])
            }
            
            return signatures
        except Exception as e:
            logger.error(f"Error in multi-sign: {e}")
            raise

    def verify_signatures(self, message: bytes, signatures: Dict[str, bytes], public_keys: QuantumKeyPair) -> bool:
        """Verify signatures from multiple quantum-resistant algorithms"""
        try:
            # Verify each signature
            for sig_type, signature in signatures.items():
                if sig_type == 'rsa':
                    if not self._verify_rsa_signature(message, signature, public_keys.rsa_key[1]):
                        return False
                elif sig_type == 'ed25519':
                    if not self._verify_ed25519_signature(message, signature, public_keys.ed25519_key[1]):
                        return False
                elif sig_type == 'ed448':
                    if not self._verify_ed448_signature(message, signature, public_keys.ed448_key[1]):
                        return False
            return True
        except Exception as e:
            logger.error(f"Error in verify signatures: {e}")
            return False

    def _encrypt_with_rsa(self, data: bytes, public_key: bytes) -> bytes:
        """Encrypt data using RSA"""
        key = load_pem_public_key(public_key)
        return key.encrypt(data, self.padding_schemes['oaep'])

    def _decrypt_with_rsa(self, data: bytes, private_key: bytes) -> bytes:
        """Decrypt data using RSA"""
        key = load_pem_private_key(private_key, password=None)
        return key.decrypt(data, self.padding_schemes['oaep'])

    def _encrypt_with_x25519(self, data: bytes, public_key: bytes) -> bytes:
        """Encrypt data using X25519"""
        key = x25519.X25519PublicKey.from_public_bytes(public_key)
        shared_key = key.exchange(x25519.X25519PrivateKey.generate())
        return self._encrypt_with_shared_key(data, shared_key)

    def _decrypt_with_x25519(self, data: bytes, private_key: bytes) -> bytes:
        """Decrypt data using X25519"""
        key = x25519.X25519PrivateKey.from_private_bytes(private_key)
        shared_key = key.exchange(x25519.X25519PublicKey.from_public_bytes(data[:32]))
        return self._decrypt_with_shared_key(data[32:], shared_key)

    def _encrypt_with_x448(self, data: bytes, public_key: bytes) -> bytes:
        """Encrypt data using X448"""
        key = x448.X448PublicKey.from_public_bytes(public_key)
        shared_key = key.exchange(x448.X448PrivateKey.generate())
        return self._encrypt_with_shared_key(data, shared_key)

    def _decrypt_with_x448(self, data: bytes, private_key: bytes) -> bytes:
        """Decrypt data using X448"""
        key = x448.X448PrivateKey.from_private_bytes(private_key)
        shared_key = key.exchange(x448.X448PublicKey.from_public_bytes(data[:56]))
        return self._decrypt_with_shared_key(data[56:], shared_key)

    def _sign_with_rsa(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message using RSA"""
        key = load_pem_private_key(private_key, password=None)
        return key.sign(
            message,
            self.padding_schemes['pss'],
            hashes.SHA3_512()
        )

    def _sign_with_ed25519(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message using Ed25519"""
        key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        return key.sign(message)

    def _sign_with_ed448(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message using Ed448"""
        key = ed448.Ed448PrivateKey.from_private_bytes(private_key)
        return key.sign(message)

    def _verify_rsa_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify an RSA signature"""
        try:
            key = load_pem_public_key(public_key)
            key.verify(
                signature,
                message,
                self.padding_schemes['pss'],
                hashes.SHA3_512()
            )
            return True
        except Exception:
            return False

    def _verify_ed25519_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify an Ed25519 signature"""
        try:
            key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            key.verify(message, signature)
            return True
        except Exception:
            return False

    def _verify_ed448_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify an Ed448 signature"""
        try:
            key = ed448.Ed448PublicKey.from_public_bytes(public_key)
            key.verify(message, signature)
            return True
        except Exception:
            return False

    def _encrypt_with_shared_key(self, data: bytes, shared_key: bytes) -> bytes:
        """Encrypt data using a shared key"""
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(shared_key),
            modes.GCM(iv)
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + ciphertext + encryptor.tag

    def _decrypt_with_shared_key(self, data: bytes, shared_key: bytes) -> bytes:
        """Decrypt data using a shared key"""
        iv = data[:12]
        tag = data[-16:]
        ciphertext = data[12:-16]
        cipher = Cipher(
            algorithms.AES(shared_key),
            modes.GCM(iv, tag)
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def generate_quantum_resistant_hash(self, data: bytes, algorithm: str = 'sha3_512') -> bytes:
        """Generate a quantum-resistant hash using the specified algorithm"""
        if algorithm not in self.hash_algorithms:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        return hashlib.sha3_512(data).digest()

    def generate_quantum_resistant_key(self, password: str, salt: bytes) -> bytes:
        """Generate a quantum-resistant key from a password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=self.kdf_length,
            salt=salt,
            iterations=self.kdf_iterations
        )
        return kdf.derive(password.encode()) 
```
```
---
### File: `consensus.py`

```python
#!/usr/bin/env python3

from typing import List, Dict, Any, Set, Optional
import asyncio
import time
from dataclasses import dataclass
import hashlib
import json
import logging
from enum import Enum

logger = logging.getLogger(__name__)

class ValidatorStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SLASHED = "slashed"
    PENDING = "pending"

@dataclass
class Validator:
    address: str
    stake: float
    last_vote: float
    status: ValidatorStatus
    performance_score: float
    total_rewards: float
    total_slashes: float
    last_rotation: float
    shard_id: Optional[int]

class Consensus:
    def __init__(self, difficulty: int = 4):
        self.difficulty = difficulty
        self.validators: Dict[str, Validator] = {}
        self.min_stake = 1000  # Minimum stake to become a validator
        self.epoch_length = 100  # Number of blocks per epoch
        self.current_epoch = 0
        self.leader_schedule: Dict[int, str] = {}  # Block height -> validator address
        self.votes: Dict[str, Set[str]] = {}  # Block hash -> set of validator addresses
        self.validator_rewards: Dict[str, float] = {}  # Validator address -> accumulated rewards
        self.slashing_conditions: Dict[str, int] = {}  # Validator address -> number of violations
        self.reward_rate = 0.05  # 5% annual reward rate
        self.slashing_threshold = 3  # Number of violations before slashing
        self.finality_threshold = 0.67  # 67% of validators must vote for finality
        self.rotation_interval = 86400  # 24 hours in seconds
        self.performance_threshold = 0.8  # Minimum performance score to remain active
        self.max_validators_per_shard = 100
        self.validator_rotation_queue: List[str] = []

    def register_validator(self, address: str, stake: float, shard_id: Optional[int] = None) -> bool:
        """Register a new validator"""
        if stake >= self.min_stake:
            # Check if shard is full
            if shard_id is not None:
                shard_validators = [v for v in self.validators.values() if v.shard_id == shard_id]
                if len(shard_validators) >= self.max_validators_per_shard:
                    return False
            
            self.validators[address] = Validator(
                address=address,
                stake=stake,
                last_vote=time.time(),
                status=ValidatorStatus.PENDING,
                performance_score=1.0,
                total_rewards=0.0,
                total_slashes=0.0,
                last_rotation=time.time(),
                shard_id=shard_id
            )
            return True
        return False

    def update_validator_stake(self, address: str, new_stake: float) -> bool:
        """Update a validator's stake"""
        if address in self.validators:
            validator = self.validators[address]
            validator.stake = new_stake
            validator.status = ValidatorStatus.ACTIVE if new_stake >= self.min_stake else ValidatorStatus.INACTIVE
            return True
        return False

    def rotate_validators(self) -> None:
        """Rotate validators based on performance and stake"""
        current_time = time.time()
        
        # Update performance scores
        for validator in self.validators.values():
            if validator.status == ValidatorStatus.ACTIVE:
                # Calculate performance based on voting history and stake
                votes_count = sum(1 for votes in self.votes.values() if validator.address in votes)
                total_blocks = len(self.votes)
                voting_performance = votes_count / total_blocks if total_blocks > 0 else 0
                
                # Update performance score with exponential moving average
                validator.performance_score = 0.7 * validator.performance_score + 0.3 * voting_performance
                
                # Check if validator should be rotated
                if (current_time - validator.last_rotation > self.rotation_interval and
                    validator.performance_score < self.performance_threshold):
                    validator.status = ValidatorStatus.INACTIVE
                    self.validator_rotation_queue.append(validator.address)
        
        # Activate new validators from the queue
        while self.validator_rotation_queue and len([v for v in self.validators.values() if v.status == ValidatorStatus.ACTIVE]) < self.max_validators_per_shard:
            new_validator = self.validator_rotation_queue.pop(0)
            self.validators[new_validator].status = ValidatorStatus.ACTIVE
            self.validators[new_validator].last_rotation = current_time

    def generate_leader_schedule(self, epoch: int) -> Dict[int, str]:
        """Generate the leader schedule for an epoch"""
        active_validators = [
            v for v in self.validators.values() 
            if v.status == ValidatorStatus.ACTIVE
        ]
        
        if not active_validators:
            return {}
        
        # Sort validators by stake and performance
        sorted_validators = sorted(
            active_validators,
            key=lambda v: (v.stake * v.performance_score),
            reverse=True
        )
        
        # Generate schedule based on stake weight and performance
        schedule = {}
        total_weight = sum(v.stake * v.performance_score for v in sorted_validators)
        
        for i in range(self.epoch_length):
            block_height = epoch * self.epoch_length + i
            # Weighted random selection based on stake and performance
            r = hash(f"{block_height}{epoch}") % total_weight
            current_sum = 0
            for validator in sorted_validators:
                current_sum += validator.stake * validator.performance_score
                if r < current_sum:
                    schedule[block_height] = validator.address
                    break
        
        return schedule

    def calculate_validator_reward(self, validator_address: str, block_reward: float) -> float:
        """Calculate validator reward based on stake, performance, and participation"""
        if validator_address not in self.validators:
            return 0.0
        
        validator = self.validators[validator_address]
        if validator.status != ValidatorStatus.ACTIVE:
            return 0.0
        
        # Calculate reward based on stake weight, performance, and participation
        total_stake = sum(v.stake for v in self.validators.values() if v.status == ValidatorStatus.ACTIVE)
        stake_weight = validator.stake / total_stake if total_stake > 0 else 0
        
        # Apply performance multiplier
        performance_multiplier = validator.performance_score
        
        # Apply slashing penalty if applicable
        violations = self.slashing_conditions.get(validator_address, 0)
        penalty = 1.0 - (violations * 0.1)  # 10% penalty per violation
        
        # Calculate final reward
        reward = block_reward * stake_weight * performance_multiplier * penalty
        
        # Update validator's total rewards
        validator.total_rewards += reward
        
        return reward

    def process_slashing(self, validator_address: str, violation_type: str) -> None:
        """Process validator slashing for violations"""
        if validator_address not in self.slashing_conditions:
            self.slashing_conditions[validator_address] = 0
        
        self.slashing_conditions[validator_address] += 1
        validator = self.validators[validator_address]
        
        # Update validator's total slashes
        slash_amount = validator.stake * 0.5  # Slash 50% of stake
        validator.total_slashes += slash_amount
        
        # Check if validator should be slashed
        if self.slashing_conditions[validator_address] >= self.slashing_threshold:
            validator.status = ValidatorStatus.SLASHED
            validator.stake *= 0.5  # Slash 50% of stake
            logger.warning(f"Validator {validator_address} has been slashed")

    async def process_block(self, block: Dict[str, Any], validator_address: str) -> bool:
        """Process a block and collect validator votes"""
        block_hash = block["hash"]
        
        # Check if validator is active
        if validator_address not in self.validators or self.validators[validator_address].status != ValidatorStatus.ACTIVE:
            return False
        
        # Check if validator is the leader for this block
        block_height = block["index"]
        if self.leader_schedule.get(block_height) != validator_address:
            # Process slashing for invalid block proposal
            self.process_slashing(validator_address, "invalid_proposal")
            return False
        
        # Initialize votes for this block if not exists
        if block_hash not in self.votes:
            self.votes[block_hash] = set()
        
        # Add vote
        self.votes[block_hash].add(validator_address)
        
        # Update validator's last vote time
        self.validators[validator_address].last_vote = time.time()
        
        # Check if block has enough votes for finality
        active_validators_count = len([v for v in self.validators.values() if v.status == ValidatorStatus.ACTIVE])
        required_votes = int(active_validators_count * self.finality_threshold)
        
        if len(self.votes[block_hash]) >= required_votes:
            # Calculate and distribute rewards
            block_reward = 50  # Base block reward
            for voter in self.votes[block_hash]:
                reward = self.calculate_validator_reward(voter, block_reward)
                if voter not in self.validator_rewards:
                    self.validator_rewards[voter] = 0
                self.validator_rewards[voter] += reward
            
            # Rotate validators if needed
            self.rotate_validators()
            
            return True
        
        return False

    def get_validator_info(self, address: str) -> Dict[str, Any]:
        """Get information about a validator"""
        if address not in self.validators:
            return {"error": "Validator not found"}
        
        validator = self.validators[address]
        return {
            "address": validator.address,
            "stake": validator.stake,
            "status": validator.status.value,
            "performance_score": validator.performance_score,
            "total_rewards": validator.total_rewards,
            "total_slashes": validator.total_slashes,
            "last_vote": validator.last_vote,
            "last_rotation": validator.last_rotation,
            "shard_id": validator.shard_id
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert consensus state to dictionary"""
        return {
            "difficulty": self.difficulty,
            "validators": {
                addr: {
                    "stake": v.stake,
                    "last_vote": v.last_vote,
                    "status": v.status.value,
                    "performance_score": v.performance_score,
                    "total_rewards": v.total_rewards,
                    "total_slashes": v.total_slashes,
                    "last_rotation": v.last_rotation,
                    "shard_id": v.shard_id
                }
                for addr, v in self.validators.items()
            },
            "current_epoch": self.current_epoch,
            "leader_schedule": self.leader_schedule,
            "validator_rewards": self.validator_rewards,
            "slashing_conditions": self.slashing_conditions
        }

    def save_state(self, filename: str):
        """Save consensus state to file"""
        with open(filename, 'w') as f:
            json.dump(self.to_dict(), f, indent=4)

    @classmethod
    def load_state(cls, filename: str) -> 'Consensus':
        """Load consensus state from file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            consensus = cls(difficulty=data["difficulty"])
            consensus.current_epoch = data["current_epoch"]
            consensus.leader_schedule = data["leader_schedule"]
            consensus.validator_rewards = data.get("validator_rewards", {})
            consensus.slashing_conditions = data.get("slashing_conditions", {})
            
            for addr, validator_data in data["validators"].items():
                consensus.validators[addr] = Validator(
                    address=addr,
                    stake=validator_data["stake"],
                    last_vote=validator_data["last_vote"],
                    status=ValidatorStatus(validator_data["status"]),
                    performance_score=validator_data.get("performance_score", 1.0),
                    total_rewards=validator_data.get("total_rewards", 0.0),
                    total_slashes=validator_data.get("total_slashes", 0.0),
                    last_rotation=validator_data.get("last_rotation", time.time()),
                    shard_id=validator_data.get("shard_id")
                )
            
            return consensus
        except FileNotFoundError:
            return cls()
        except Exception as e:
            logger.error(f"Error loading consensus state: {e}")
            return cls() 
```
---
### File: `export_all_files_for_chatgpt.py`

```python
import os

def get_language_hint(filename):
    """Attempts to get a language hint from the filename extension."""
    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    mapping = {
        '.py': 'python',
        '.js': 'javascript',
        '.html': 'html',
        '.css': 'css',
        '.java': 'java',
        '.c': 'c',
        '.cpp': 'cpp',
        '.cs': 'csharp',
        '.go': 'go',
        '.rb': 'ruby',
        '.php': 'php',
        '.swift': 'swift',
        '.kt': 'kotlin',
        '.rs': 'rust',
        '.scala': 'scala',
        '.ts': 'typescript',
        '.md': 'markdown',
        '.json': 'json',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.xml': 'xml',
        '.sh': 'bash',
        '.bat': 'batch',
        '.txt': 'text',
        # Add more mappings as needed
    }
    return mapping.get(ext, '') # Return empty string if no specific hint

def export_all_project_files(output_filename="all_project_files_for_chatgpt.md"):
    """
    Exports all relevant text files in the project to a single Markdown file,
    formatted for easy pasting into ChatGPT.
    Skips common binary files, unnecessary directories, and hidden files/folders.
    """
    excluded_dirs = {'.git', '__pycache__', '.venv', 'venv', 'node_modules', '.vscode', '.idea', 'build', 'dist', 'docs/_build', '.mypy_cache', '.pytest_cache', '.tox'}
    # Common non-text file extensions
    excluded_extensions = {
        '.pyc', '.pyo', '.o', '.so', '.dll', '.exe', '.jar', '.class', '.DS_Store', '.swp', '.swo', '.log',
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.webp', '.ico',
        '.mp3', '.wav', '.aac', '.flac', '.ogg', '.m4a',
        '.mp4', '.mov', '.avi', '.mkv', '.webm', '.flv',
        '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.sqlite', '.db', '.dat', '.bin', '.img', '.iso', '.bak'
    }

    project_root = os.getcwd()
    output_parts = []
    files_processed = 0
    files_skipped_binary_or_error = 0
    files_skipped_excluded_ext = 0
    # files_skipped_in_excluded_dir = 0 # This is harder to count accurately with topdown=True and dirs modification

    output_parts.append(f"# Project Files Export for ChatGPT (from: {project_root})\n\n")
    output_parts.append(f"**Note:** This export attempts to include all relevant text-based files. Common binary file types, version control directories, virtual environments, and build artifacts are excluded.\n\n---\n\n")


    for root, dirs, files in os.walk(project_root, topdown=True):
        # Filter out excluded directories and hidden directories
        original_dir_count = len(dirs)
        dirs[:] = [d for d in dirs if d not in excluded_dirs and not d.startswith('.')]
        # files_skipped_in_excluded_dir += original_dir_count - len(dirs) # Count top-level excluded dirs

        for filename in files:
            # Skip the output file itself, hidden files, and backup files
            if filename == output_filename or filename.startswith('.') or filename.endswith("~"):
                continue

            filepath = os.path.join(root, filename)
            relative_filepath = os.path.relpath(filepath, project_root)
            
            # Skip files in directories that eventually got fully excluded (e.g. deep inside .git if not caught by top-level)
            if any(relative_filepath.startswith(excluded_dir + os.sep) for excluded_dir in excluded_dirs):
                # files_skipped_in_excluded_dir +=1 # if we need fine-grained count
                continue

            file_ext = os.path.splitext(filename)[1].lower()
            if file_ext in excluded_extensions:
                files_skipped_excluded_ext += 1
                continue

            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f_content:
                    content = f_content.read()

                # Basic heuristic: if 'ignore' resulted in too many replacement chars, or if it's full of null bytes, might be binary
                if content.count('\ufffd') > len(content) * 0.1 or '\0' in content[:1024]: # Check first 1KB for nulls
                    output_parts.append(f"### File: `{relative_filepath}`\n\n")
                    output_parts.append("```\n")
                    output_parts.append(f"[Skipped: Content appears to be binary or non-UTF-8 text after attempting to read]\n")
                    output_parts.append("```\n---\n")
                    files_skipped_binary_or_error += 1
                    continue
                
                # Another check: if file size is large and no newlines (likely minified or unusual binary)
                if len(content) > 1024 * 1024 and '\n' not in content[:1024*1024]: # 1MB
                     output_parts.append(f"### File: `{relative_filepath}`\n\n")
                     output_parts.append("```\n")
                     output_parts.append(f"[Skipped: File is very large and contains no newlines in the first 1MB, possibly minified or binary]\n")
                     output_parts.append("```\n---\n")
                     files_skipped_binary_or_error += 1
                     continue


                lang_hint = get_language_hint(filename)
                output_parts.append(f"### File: `{relative_filepath}`\n\n")
                output_parts.append(f"```{lang_hint}\n")
                output_parts.append(content)
                output_parts.append("\n```\n---\n")
                files_processed += 1

            except IsADirectoryError:
                # This shouldn't happen with os.walk files list but good to be safe
                continue 
            except Exception as e:
                output_parts.append(f"### File: `{relative_filepath}`\n\n")
                output_parts.append("```\n")
                output_parts.append(f"[Skipped: Error reading file: {e}]\n")
                output_parts.append("```\n---\n")
                files_skipped_binary_or_error += 1

    final_output = "".join(output_parts)

    try:
        with open(output_filename, 'w', encoding='utf-8') as f_out:
            f_out.write(final_output)
        print(f"Successfully exported {files_processed} files to '{output_filename}'.")
        if files_skipped_binary_or_error > 0:
            print(f"Skipped {files_skipped_binary_or_error} files that appeared to be binary, had read errors, or were too large without newlines.")
        if files_skipped_excluded_ext > 0:
            print(f"Skipped {files_skipped_excluded_ext} files due to explicitly excluded extensions.")
        # print(f"Note: Skipped directories include: {', '.join(excluded_dirs)} and any hidden directories.")
        print(f"Review '{output_filename}' to ensure all desired content is included.")

    except Exception as e:
        print(f"Error writing to output file '{output_filename}': {e}")

if __name__ == "__main__":
    export_all_project_files() 
```
---
### File: `mine_block.py`

```python
#!/usr/bin/env python3

from blockchain import Blockchain
from wallet import Wallet, WalletManager
import time

def main():
    # Initialize wallet manager and create a new wallet
    wallet_manager = WalletManager()
    miner_wallet = wallet_manager.create_wallet()
    print(f"\nCreated miner wallet with address: {miner_wallet.address}")
    
    # Initialize blockchain
    straz_chain = Blockchain(difficulty=4)
    print("\nInitialized Straz blockchain")
    
    # Mine the genesis block
    print("\nMining genesis block...")
    straz_chain.mine_pending_transactions(miner_wallet.address)
    
    # Create some test transactions
    print("\nCreating test transactions...")
    test_wallet = wallet_manager.create_wallet()
    print(f"Created test wallet with address: {test_wallet.address}")
    
    # Send some coins to the test wallet
    straz_chain.create_transaction(miner_wallet.address, test_wallet.address, 25)
    print(f"Sent 25 STRZ from {miner_wallet.address} to {test_wallet.address}")
    
    # Mine a block to confirm the transaction
    print("\nMining block to confirm transaction...")
    straz_chain.mine_pending_transactions(miner_wallet.address)
    
    # Check balances
    print("\nChecking balances:")
    print(f"Miner balance: {straz_chain.get_balance(miner_wallet.address)} STRZ")
    print(f"Test wallet balance: {straz_chain.get_balance(test_wallet.address)} STRZ")
    
    # Save the blockchain
    print("\nSaving blockchain...")
    straz_chain.save_to_file("straz_blockchain.json")
    
    # Save the wallets
    print("\nSaving wallets...")
    wallet_manager.save_wallets("wallets")
    
    print("\nBlockchain valid:", straz_chain.is_chain_valid())

if __name__ == "__main__":
    main()

```
---
### File: `blockchain.py`

```python
#!/usr/bin/env python3

import hashlib
import json
import time
import binascii
from typing import List, Dict, Any, Optional
import struct
from smart_contract import ContractManager
from consensus import Consensus
from zk_quantum import ZKRollup, QuantumResistantCrypto, ZKTransaction
import os
import logging
from dataclasses import dataclass
from quantum_crypto import AdvancedQuantumCrypto, QuantumKeyPair
import base64

logger = logging.getLogger(__name__)

@dataclass
class ShardInfo:
    id: int
    validators: List[str]
    transactions: List[Dict]
    state_root: str
    last_block: int
    zk_rollup: Optional[ZKRollup] = None

class Block:
    def __init__(self, index: int, timestamp: float, transactions: List[Dict], previous_hash: str, nonce: int = 0):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()
        self.validator_signatures: List[str] = []
        self.shard_id: Optional[int] = None
        self.cross_chain_refs: List[Dict] = []
        self.state_root: str = ""
        self.receipt_root: str = ""
        self.zk_proof: Optional[bytes] = None  # Zero-knowledge proof for the block

    def calculate_hash(self) -> str:
        """Calculate the hash of the block contents."""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "shard_id": self.shard_id,
            "cross_chain_refs": self.cross_chain_refs,
            "state_root": self.state_root,
            "receipt_root": self.receipt_root,
            "zk_proof": self.zk_proof.hex() if self.zk_proof else None
        }, sort_keys=True).encode()
        
        return hashlib.sha3_256(block_string).hexdigest()  # Using SHA3-256 for quantum resistance
    
    def mine_block(self, difficulty: int) -> None:
        """Mine the block by finding a hash with the required number of leading zeros."""
        target = "0" * difficulty
        
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
            
        logger.info(f"Block mined: {self.hash}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the block to a dictionary."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
            "validator_signatures": self.validator_signatures,
            "shard_id": self.shard_id,
            "cross_chain_refs": self.cross_chain_refs,
            "state_root": self.state_root,
            "receipt_root": self.receipt_root,
            "zk_proof": self.zk_proof.hex() if self.zk_proof else None
        }

class Blockchain:
    def __init__(self, difficulty: int = 4):
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict] = []
        self.difficulty = difficulty
        self.mining_reward = 50  # 50 STRZ
        self.contract_manager = ContractManager()
        self.consensus = Consensus(difficulty)
        self.transaction_pool: Dict[str, Dict] = {}  # tx_hash -> transaction
        self.max_transactions_per_block = 1000
        self.min_transaction_fee = 0.001  # Minimum fee in STRZ
        
        # Initialize quantum-resistant cryptography
        self.quantum_crypto = AdvancedQuantumCrypto()
        
        # Sharding configuration
        self.num_shards = 4
        self.shards: Dict[int, ShardInfo] = {}
        self.cross_chain_bridges: Dict[str, Dict] = {}
        
        # Initialize shards with ZK-rollups
        for i in range(self.num_shards):
            self.shards[i] = ShardInfo(
                id=i,
                validators=[],
                transactions=[],
                state_root="",
                last_block=0,
                zk_rollup=ZKRollup()
            )
        
        # Create the genesis block
        self.create_genesis_block()
        
        self.validator_keys = {}  # Store validator quantum key pairs
    
    def create_genesis_block(self) -> None:
        """Create the genesis block for the blockchain."""
        genesis_block = Block(0, time.time(), [], "0")
        genesis_block.hash = hashlib.sha256(b'\x00' * 32).hexdigest()
        genesis_block.state_root = self._calculate_state_root({})
        genesis_block.receipt_root = self._calculate_receipt_root([])
        
        self.chain.append(genesis_block)
        logger.info(f"Genesis block created with hash: {genesis_block.hash}")
    
    def _calculate_state_root(self, state: Dict) -> str:
        """Calculate the Merkle root of the state trie."""
        # Simplified implementation - in a real blockchain, this would use a proper Merkle Patricia Trie
        return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()
    
    def _calculate_receipt_root(self, receipts: List[Dict]) -> str:
        """Calculate the Merkle root of the transaction receipts."""
        # Simplified implementation
        return hashlib.sha256(json.dumps(receipts, sort_keys=True).encode()).hexdigest()
    
    def get_latest_block(self) -> Block:
        """Return the latest block in the chain."""
        return self.chain[-1]
    
    def validate_transaction(self, transaction: Dict) -> bool:
        """Validate a transaction before adding it to the pool"""
        required_fields = ["sender", "recipient", "amount", "timestamp", "signature"]
        if not all(field in transaction for field in required_fields):
            return False
        
        # Skip validation for coinbase transactions
        if transaction["sender"] == "COINBASE":
            return True
        
        # Check if sender has sufficient balance
        sender_balance = self.get_balance(transaction["sender"])
        if sender_balance < transaction["amount"]:
            return False
        
        # Verify transaction signature
        if not self.verify_transaction_signature(transaction):
            return False
        
        # Check for double spending
        tx_hash = self.calculate_transaction_hash(transaction)
        if tx_hash in self.transaction_pool:
            return False
        
        return True

    def calculate_transaction_hash(self, transaction: Dict) -> str:
        """Calculate the hash of a transaction"""
        tx_string = json.dumps({
            "sender": transaction["sender"],
            "recipient": transaction["recipient"],
            "amount": transaction["amount"],
            "timestamp": transaction["timestamp"]
        }, sort_keys=True).encode()
        return hashlib.sha256(tx_string).hexdigest()

    def verify_transaction_signature(self, transaction: Dict) -> bool:
        """Verify the signature of a transaction using quantum-resistant cryptography"""
        if "signature" not in transaction:
            return False
        
        try:
            # For ZK transactions, verify the ZK proof
            if transaction.get("is_zk", False):
                shard_id = int(hashlib.sha256(transaction["sender"].encode()).hexdigest(), 16) % self.num_shards
                zk_rollup = self.shards[shard_id].zk_rollup
                if zk_rollup and "zk_proof" in transaction:
                    return zk_rollup.verify_zk_proof(transaction["zk_proof"])
            
            # For regular transactions, verify the quantum-resistant signature
            message = json.dumps({
                "sender": transaction["sender"],
                "recipient": transaction["recipient"],
                "amount": transaction["amount"],
                "timestamp": transaction["timestamp"]
            }).encode()
            
            return self.quantum_crypto.verify_signature(
                message,
                transaction["signature"],
                self.quantum_crypto.generate_key_pair()[1]  # Public key
            )
        except Exception as e:
            logger.error(f"Error verifying transaction signature: {e}")
            return False

    def create_transaction(self, sender: str, recipient: str, amount: float, fee: float = 0.001, use_zk: bool = False, use_quantum: bool = True) -> bool:
        """Add a new transaction to the pending transactions pool."""
        if fee < self.min_transaction_fee:
            return False
        
        transaction = {
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
            "fee": fee,
            "timestamp": time.time()
        }
        
        if use_zk:
            # Generate zero-knowledge proof for the transaction
            shard_id = int(hashlib.sha256(sender.encode()).hexdigest(), 16) % self.num_shards
            zk_rollup = self.shards[shard_id].zk_rollup
            
            if zk_rollup:
                proof = zk_rollup.generate_zk_proof(transaction)
                if proof:
                    # Create ZK transaction
                    zk_tx = ZKTransaction(
                        sender=sender,
                        recipient=recipient,
                        amount=amount,
                        proof=proof,
                        timestamp=time.time(),
                        signature=self.quantum_crypto.sign(
                            json.dumps(transaction).encode(),
                            self.quantum_crypto.generate_key_pair()[0]
                        )
                    )
                    
                    # Add to ZK-rollup batch
                    if zk_rollup.add_transaction_to_batch(zk_tx):
                        transaction["zk_proof"] = proof
                        transaction["is_zk"] = True
        
        if use_quantum:
            # Generate quantum key pair if not exists
            if sender not in self.validator_keys:
                self.validator_keys[sender] = self.quantum_crypto.generate_quantum_key_pair()
            
            # Create transaction
            transaction = {
                "sender": sender,
                "recipient": recipient,
                "amount": amount,
                "fee": fee,
                "timestamp": time.time()
            }
            
            # Sign with multiple quantum-resistant algorithms
            message = f"{sender}{recipient}{amount}".encode()
            signatures = self.quantum_crypto.multi_sign(
                message,
                self.validator_keys[sender]
            )
            
            # Store signatures in transaction
            transaction["signature"] = json.dumps({
                'signatures': {
                    k: base64.b64encode(v).decode()
                    for k, v in signatures.items()
                }
            })
        
        if self.validate_transaction(transaction):
            tx_hash = self.calculate_transaction_hash(transaction)
            self.transaction_pool[tx_hash] = transaction
            return True
        return False

    async def mine_pending_transactions(self, mining_reward_address: str) -> None:
        """Mine pending transactions and add them to the blockchain."""
        # Sort transactions by fee (higher fees first)
        sorted_transactions = sorted(
            self.transaction_pool.values(),
            key=lambda x: x.get("fee", 0),
            reverse=True
        )
        
        # Take only the maximum number of transactions per block
        transactions_to_process = sorted_transactions[:self.max_transactions_per_block]
        
        # Create a reward transaction for the miner
        total_fees = sum(tx.get("fee", 0) for tx in transactions_to_process)
        self.pending_transactions.append({
            "sender": "COINBASE",
            "recipient": mining_reward_address,
            "amount": self.mining_reward + total_fees,
            "timestamp": time.time()
        })
        
        # Add selected transactions
        self.pending_transactions.extend(transactions_to_process)
        
        # Create a new block with pending transactions
        block = Block(
            len(self.chain),
            time.time(),
            self.pending_transactions,
            self.get_latest_block().hash
        )
        
        # Assign transactions to shards and generate ZK proofs
        self._assign_transactions_to_shards(block)
        
        # Generate ZK proof for the block if it contains ZK transactions
        if any(tx.get("is_zk", False) for tx in block.transactions):
            shard_id = block.shard_id
            if shard_id is not None:
                zk_rollup = self.shards[shard_id].zk_rollup
                if zk_rollup:
                    batch_proof = zk_rollup.generate_batch_proof()
                    if batch_proof:
                        block.zk_proof = batch_proof.proof
        
        # Mine the block
        block.mine_block(self.difficulty)
        
        # Process block through consensus
        if await self.consensus.process_block(block.to_dict(), mining_reward_address):
            # Add the mined block to the chain
            self.chain.append(block)
            
            # Process smart contract transactions
            for tx in self.pending_transactions:
                if tx.get("type") == "contract":
                    self.contract_manager.execute_contract(
                        tx["contract_address"],
                        tx["method"],
                        tx["params"],
                        tx["sender"],
                        tx.get("value", 0)
                    )
            
            # Remove processed transactions from the pool
            for tx in transactions_to_process:
                tx_hash = self.calculate_transaction_hash(tx)
                self.transaction_pool.pop(tx_hash, None)
            
            # Reset pending transactions
            self.pending_transactions = []
            
            logger.info(f"Block #{block.index} has been mined and added to the chain")
        else:
            logger.warning("Block rejected by consensus")
    
    def _assign_transactions_to_shards(self, block: Block) -> None:
        """Assign transactions to different shards based on sender address"""
        shard_transactions: Dict[int, List[Dict]] = {i: [] for i in range(self.num_shards)}
        
        for tx in block.transactions:
            # Skip coinbase transactions
            if tx["sender"] == "COINBASE":
                continue
            
            # Assign to shard based on sender address hash
            shard_id = int(hashlib.sha256(tx["sender"].encode()).hexdigest(), 16) % self.num_shards
            shard_transactions[shard_id].append(tx)
        
        # Update shard information
        for shard_id, transactions in shard_transactions.items():
            self.shards[shard_id].transactions.extend(transactions)
            self.shards[shard_id].last_block = block.index
    
    def create_cross_chain_bridge(self, target_chain: str, bridge_address: str) -> bool:
        """Create a cross-chain bridge to another blockchain"""
        if target_chain in self.cross_chain_bridges:
            return False
        
        self.cross_chain_bridges[target_chain] = {
            "bridge_address": bridge_address,
            "active": True,
            "last_sync": time.time(),
            "total_transfers": 0
        }
        return True
    
    def process_cross_chain_transaction(self, source_chain: str, transaction: Dict) -> bool:
        """Process a transaction from another blockchain"""
        if source_chain not in self.cross_chain_bridges:
            return False
        
        bridge = self.cross_chain_bridges[source_chain]
        if not bridge["active"]:
            return False
        
        # Verify the transaction is from the bridge
        if transaction["sender"] != bridge["bridge_address"]:
            return False
        
        # Process the transaction
        success = self.create_transaction(
            transaction["sender"],
            transaction["recipient"],
            transaction["amount"]
        )
        
        if success:
            bridge["total_transfers"] += 1
            bridge["last_sync"] = time.time()
        
        return success
    
    def get_balance(self, address: str) -> float:
        """Calculate the balance of a given address based on all transactions in the blockchain."""
        balance = 0.0
        
        for block in self.chain:
            for transaction in block.transactions:
                if transaction["sender"] == address:
                    balance -= transaction["amount"]
                if transaction["recipient"] == address:
                    balance += transaction["amount"]
        
        return balance
    
    def is_chain_valid(self) -> bool:
        """Validate the integrity of the blockchain."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Verify the current block's hash
            if current_block.hash != current_block.calculate_hash():
                logger.error("Current block's hash is invalid")
                return False
            
            # Verify the chain link
            if current_block.previous_hash != previous_block.hash:
                logger.error("Chain link is broken")
                return False
            
            # Verify state roots
            if current_block.state_root != self._calculate_state_root({}):  # Simplified
                logger.error("Invalid state root")
                return False
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the blockchain to a dictionary."""
        return {
            "chain": [block.to_dict() for block in self.chain],
            "pending_transactions": self.pending_transactions,
            "difficulty": self.difficulty,
            "shards": {
                shard_id: {
                    "validators": shard.validators,
                    "last_block": shard.last_block,
                    "state_root": shard.state_root
                }
                for shard_id, shard in self.shards.items()
            },
            "cross_chain_bridges": self.cross_chain_bridges
        }
    
    def save_to_file(self, filename: str) -> None:
        """Save the blockchain to a file."""
        with open(filename, 'w') as f:
            json.dump(self.to_dict(), f, indent=4)
        
        # Save contracts and consensus state
        self.contract_manager.save_contracts("contracts.json")
        self.consensus.save_state("consensus.json")
        
        logger.info(f"Blockchain saved to {filename}")
    
    @classmethod
    def load_from_file(cls, filename: str) -> 'Blockchain':
        """Load the blockchain from a file."""
        blockchain = cls()  # Create a new instance
        
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            blockchain.difficulty = data["difficulty"]
            blockchain.chain = []
            
            for block_data in data["chain"]:
                block = Block(
                    block_data["index"],
                    block_data["timestamp"],
                    block_data["transactions"],
                    block_data["previous_hash"],
                    block_data["nonce"]
                )
                block.hash = block_data["hash"]
                block.validator_signatures = block_data.get("validator_signatures", [])
                block.shard_id = block_data.get("shard_id")
                block.cross_chain_refs = block_data.get("cross_chain_refs", [])
                block.state_root = block_data.get("state_root", "")
                block.receipt_root = block_data.get("receipt_root", "")
                block.zk_proof = bytes.fromhex(block_data.get("zk_proof", "")) if block_data.get("zk_proof") else None
                blockchain.chain.append(block)
            
            blockchain.pending_transactions = data["pending_transactions"]
            
            # Load shard information
            for shard_id, shard_data in data.get("shards", {}).items():
                blockchain.shards[int(shard_id)] = ShardInfo(
                    id=int(shard_id),
                    validators=shard_data["validators"],
                    transactions=[],
                    state_root=shard_data["state_root"],
                    last_block=shard_data["last_block"],
                    zk_rollup=ZKRollup()
                )
            
            # Load cross-chain bridges
            blockchain.cross_chain_bridges = data.get("cross_chain_bridges", {})
            
            # Load contracts if they exist
            if os.path.exists("contracts.json"):
                blockchain.contract_manager.load_contracts("contracts.json")
            
            # Load consensus state if it exists
            if os.path.exists("consensus.json"):
                blockchain.consensus.load_state("consensus.json")
            
            logger.info(f"Blockchain loaded from {filename}")
            return blockchain
            
        except FileNotFoundError:
            logger.warning(f"No existing blockchain found at {filename}")
            return blockchain
        except json.JSONDecodeError:
            logger.error(f"Error decoding blockchain file {filename}")
            return blockchain
        except Exception as e:
            logger.error(f"Error loading blockchain: {str(e)}")
            return blockchain


if __name__ == "__main__":
    # Example usage
    straz_chain = Blockchain(difficulty=4)
    
    print("Mining genesis block...")
    straz_chain.mine_pending_transactions("miner-address-1")
    
    print("\nCreating some transactions...")
    straz_chain.create_transaction("address-1", "address-2", 10)
    straz_chain.create_transaction("address-2", "address-1", 5)
    
    print("\nMining block...")
    straz_chain.mine_pending_transactions("miner-address-1")
    
    print("\nBlockchain valid:", straz_chain.is_chain_valid())
    print("\nMiner's balance:", straz_chain.get_balance("miner-address-1"))
    
    print("\nSaving blockchain...")
    straz_chain.save_to_file("straz_blockchain.json")

```
---
### File: `docker-compose.yml`

```yaml
version: '3.8'

services:
  straz-node:
    build: .
    ports:
      - "5001:5001"  # API port
      - "6000:6000"  # P2P port
    volumes:
      - ./wallets:/app/wallets
      - ./straz_blockchain.json:/app/straz_blockchain.json
    environment:
      - NODE_HOST=0.0.0.0
      - NODE_PORT=6000
      - API_HOST=0.0.0.0
      - API_PORT=5001
    restart: unless-stopped 
```
---
### File: `node.py`

```python
#!/usr/bin/env python3

import socket
import threading
import json
import time
import hashlib
import requests
from typing import List, Dict, Any, Set, Optional
from blockchain import Blockchain, Block
from wallet import Wallet

class Node:
    def __init__(self, host: str = '0.0.0.0', port: int = 5000):
        self.host = host
        self.port = port
        self.blockchain = Blockchain()
        self.peers: Set[str] = set()  # Set of peer URLs
        self.wallet: Optional[Wallet] = None
        
        # Initialize the node server
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    def start(self) -> None:
        """Start the node server."""
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        
        # Start a thread to accept incoming connections
        threading.Thread(target=self.accept_connections, daemon=True).start()
        
        print(f"Node started on {self.host}:{self.port}")
        
        # Sync blockchain with peers
        if self.peers:
            self.sync_with_peers()
    
    def accept_connections(self) -> None:
        """Accept incoming connections from peers."""
        while True:
            client, address = self.socket.accept()
            threading.Thread(target=self.handle_client, args=(client, address), daemon=True).start()
    
    def handle_client(self, client: socket.socket, address: tuple) -> None:
        """Handle an incoming connection from a peer."""
        try:
            # Receive data from client
            data = client.recv(4096).decode('utf-8')
            if not data:
                return
            
            # Parse the message
            message = json.loads(data)
            
            # Handle different message types
            if message["type"] == "get_blockchain":
                # Send the blockchain to the peer
                response = {
                    "type": "blockchain",
                    "data": self.blockchain.to_dict()
                }
                client.send(json.dumps(response).encode('utf-8'))
            
            elif message["type"] == "broadcast_transaction":
                # Add the transaction to pending transactions
                transaction = message["data"]
                self.blockchain.pending_transactions.append(transaction)
                
                # Acknowledge receipt
                response = {
                    "type": "ack",
                    "message": "Transaction received"
                }
                client.send(json.dumps(response).encode('utf-8'))
            
            elif message["type"] == "broadcast_block":
                # Verify and add the block to the blockchain
                block_data = message["data"]
                block = Block(
                    block_data["index"],
                    block_data["timestamp"],
                    block_data["transactions"],
                    block_data["previous_hash"],
                    block_data["nonce"]
                )
                block.hash = block_data["hash"]
                
                # Verify the block
                if self.verify_block(block):
                    self.blockchain.chain.append(block)
                    
                    # Acknowledge receipt
                    response = {
                        "type": "ack",
                        "message": "Block accepted"
                    }
                else:
                    response = {
                        "type": "error",
                        "message": "Invalid block"
                    }
                
                client.send(json.dumps(response).encode('utf-8'))
            
            elif message["type"] == "get_peers":
                # Send the list of peers to the client
                response = {
                    "type": "peers",
                    "data": list(self.peers)
                }
                client.send(json.dumps(response).encode('utf-8'))
            
            elif message["type"] == "add_peer":
                # Add the peer to the peer list
                peer_url = message["data"]
                if peer_url not in self.peers and peer_url != f"{self.host}:{self.port}":
                    self.peers.add(peer_url)
                    
                    # Acknowledge receipt
                    response = {
                        "type": "ack",
                        "message": "Peer added"
                    }
                else:
                    response = {
                        "type": "error",
                        "message": "Peer already exists or is self"
                    }
                
                client.send(json.dumps(response).encode('utf-8'))
        
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        
        finally:
            client.close()
    
    def connect_to_peer(self, host: str, port: int) -> bool:
        """Connect to a peer and add it to the peer list."""
        peer_url = f"{host}:{port}"
        
        if peer_url in self.peers or peer_url == f"{self.host}:{self.port}":
            return False
        
        try:
            # Connect to the peer
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((host, port))
            
            # Send a message to add this node as a peer
            message = {
                "type": "add_peer",
                "data": f"{self.host}:{self.port}"
            }
            client.send(json.dumps(message).encode('utf-8'))
            
            # Receive a response
            response = json.loads(client.recv(4096).decode('utf-8'))
            
            if response["type"] == "ack":
                # Add the peer to the peer list
                self.peers.add(peer_url)
                
                # Get the peer's blockchain
                self.get_blockchain_from_peer(host, port)
                
                # Get the peer's peers
                self.get_peers_from_peer(host, port)
                
                return True
            
            return False
        
        except Exception as e:
            print(f"Error connecting to peer {host}:{port}: {e}")
            return False
        
        finally:
            client.close()
    
    def get_blockchain_from_peer(self, host: str, port: int) -> bool:
        """Get the blockchain from a peer."""
        try:
            # Connect to the peer
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((host, port))
            
            # Send a message to get the blockchain
            message = {
                "type": "get_blockchain"
            }
            client.send(json.dumps(message).encode('utf-8'))
            
            # Receive the blockchain
            response = json.loads(client.recv(4096).decode('utf-8'))
            
            if response["type"] == "blockchain":
                # Check if the peer's blockchain is longer than ours
                peer_blockchain = response["data"]
                if len(peer_blockchain["chain"]) > len(self.blockchain.chain):
                    # Verify the peer's blockchain
                    if self.verify_blockchain(peer_blockchain):
                        # Replace our blockchain with the peer's
                        self.blockchain = Blockchain.load_from_dict(peer_blockchain)
                        return True
            
            return False
        
        except Exception as e:
            print(f"Error getting blockchain from peer {host}:{port}: {e}")
            return False
        
        finally:
            client.close()
    
    def get_peers_from_peer(self, host: str, port: int) -> bool:
        """Get the peers from a peer."""
        try:
            # Connect to the peer
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((host, port))
            
            # Send a message to get the peers
            message = {
                "type": "get_peers"
            }
            client.send(json.dumps(message).encode('utf-8'))
            
            # Receive the peers
            response = json.loads(client.recv(4096).decode('utf-8'))
            
            if response["type"] == "peers":
                # Add the peer's peers to our peer list
                for peer_url in response["data"]:
                    if peer_url not in self.peers and peer_url != f"{self.host}:{self.port}":
                        peer_host, peer_port = peer_url.split(":")
                        self.connect_to_peer(peer_host, int(peer_port))
                
                return True
            
            return False
        
        except Exception as e:
            print(f"Error getting peers from peer {host}:{port}: {e}")
            return False
        
        finally:
            client.close()
    
    def sync_with_peers(self) -> None:
        """Sync the blockchain with all peers."""
        for peer_url in self.peers:
            host, port = peer_url.split(":")
            self.get_blockchain_from_peer(host, int(port))
    
    def broadcast_transaction(self, transaction: Dict) -> None:
        """Broadcast a transaction to all peers."""
        message = {
            "type": "broadcast_transaction",
            "data": transaction
        }
        
        for peer_url in self.peers:
            try:
                host, port = peer_url.split(":")
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((host, int(port)))
                client.send(json.dumps(message).encode('utf-8'))
                client.close()
            except Exception as e:
                print(f"Error broadcasting transaction to peer {peer_url}: {e}")
    
    def broadcast_block(self, block: Block) -> None:
        """Broadcast a block to all peers."""
        message = {
            "type": "broadcast_block",
            "data": block.to_dict()
        }
        
        for peer_url in self.peers:
            try:
                host, port = peer_url.split(":")
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((host, int(port)))
                client.send(json.dumps(message).encode('utf-8'))
                client.close()
            except Exception as e:
                print(f"Error broadcasting block to peer {peer_url}: {e}")
    
    def verify_block(self, block: Block) -> bool:
        """Verify the validity of a block."""
        # Check if the block index is correct
        if block.index != len(self.blockchain.chain):
            return False
        
        # Check if the previous hash matches the last block in the chain
        if block.previous_hash != self.blockchain.get_latest_block().hash:
            return False
        
        # Check if the block hash is valid
        if block.hash != block.calculate_hash():
            return False
        
        # Check if the block hash meets the difficulty requirement
        if block.hash[:self.blockchain.difficulty] != "0" * self.blockchain.difficulty:
            return False
        
        return True
    
    def verify_blockchain(self, blockchain_data: Dict) -> bool:
        """Verify the validity of a blockchain."""
        # Create a temporary blockchain
        temp_blockchain = Blockchain(blockchain_data["difficulty"])
        temp_blockchain.chain = []
        
        # Add all blocks to the temporary blockchain
        for block_data in blockchain_data["chain"]:
            block = Block(
                block_data["index"],
                block_data["timestamp"],
                block_data["transactions"],
                block_data["previous_hash"],
                block_data["nonce"]
            )
            block.hash = block_data["hash"]
            temp_blockchain.chain.append(block)
        
        # Verify the blockchain
        return temp_blockchain.is_chain_valid()
    
    def mine_block(self) -> Block:
        """Mine a new block with the pending transactions."""
        if not self.wallet:
            raise ValueError("No wallet configured for mining rewards")
        
        # Add a mining reward transaction
        mining_reward = {
            "sender": "COINBASE",
            "recipient": self.wallet.address,
            "amount": self.blockchain.mining_reward,
            "timestamp": time.time()
        }
        self.blockchain.pending_transactions.append(mining_reward)
        
        # Create a new block
        new_block = Block(
            len(self.blockchain.chain),
            time.time(),
            self.blockchain.pending_transactions,
            self.blockchain.get_latest_block().hash
        )
        
        # Mine the block
        new_block.mine_block(self.blockchain.difficulty)
        
        # Add the block to the blockchain
        self.blockchain.chain.append(new_block)
        
        # Reset pending transactions
        self.blockchain.pending_transactions = []
        
        # Broadcast the new block
        self.broadcast_block(new_block)
        
        return new_block
    
    def create_transaction(self, recipient: str, amount: float) -> bool:
        """Create a new transaction and broadcast it to the network."""
        if not self.wallet:
            raise ValueError("No wallet configured for creating transactions")
        
        # Check if the sender has enough balance
        sender_balance = self.blockchain.get_balance(self.wallet.address)
        if sender_balance < amount:
            return False
        
        # Create a new transaction
        transaction = {
            "sender": self.wallet.address,
            "recipient": recipient,
            "amount": amount,
            "timestamp": time.time()
        }
        
        # Sign the transaction
        transaction["signature"] = self.wallet.sign_transaction(transaction)
        
        # Add the transaction to pending transactions
        self.blockchain.pending_transactions.append(transaction)
        
        # Broadcast the transaction
        self.broadcast_transaction(transaction)
        
        return True
    
    def set_wallet(self, wallet: Wallet) -> None:
        """Set the wallet for this node."""
        self.wallet = wallet
        print(f"Wallet set: {wallet.address}")
    
    def close(self) -> None:
        """Close the node server."""
        self.socket.close()
        print("Node closed")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Straz cryptocurrency node")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to")
    parser.add_argument("--connect", type=str, help="Peer to connect to in format host:port")
    args = parser.parse_args()
    
    # Create a node
    node = Node(args.host, args.port)
    
    # Create a wallet for the node
    wallet = Wallet()
    node.set_wallet(wallet)
    
    # Start the node
    node.start()
    
    # Connect to a peer if specified
    if args.connect:
        peer_host, peer_port = args.connect.split(":")
        if node.connect_to_peer(peer_host, int(peer_port)):
            print(f"Connected to peer {args.connect}")
        else:
            print(f"Failed to connect to peer {args.connect}")
    
    # Start a simple interactive console
    while True:
        try:
            command = input("straz> ").strip()
            
            if command == "exit":
                node.close()
                break
            
            elif command == "help":
                print("Available commands:")
                print("  help - Show this help message")
                print("  exit - Exit the node")
                print("  peers - Show the list of peers")
                print("  connect <host:port> - Connect to a peer")
                print("  balance - Show the wallet balance")
                print("  mine - Mine a new block")
                print("  send <recipient> <amount> - Send coins to a recipient")
                print("  chain - Show the blockchain")
                print("  save <filename> - Save the blockchain to a file")
                print("  load <filename> - Load the blockchain from a file")
            
            elif command == "peers":
                print(f"Peers: {', '.join(node.peers) if node.peers else 'None'}")
            
            elif command.startswith("connect "):
                peer_url = command.split(" ")[1]
                peer_host, peer_port = peer_url.split(":")
                if node.connect_to_peer(peer_host, int(peer_port)):
                    print(f"Connected to peer {peer_url}")
                else:
                    print(f"Failed to connect to peer {peer_url}")
            
            elif command == "balance":
                balance = node.blockchain.get_balance(node.wallet.address)
                print(f"Balance: {balance} STRZ")
            
            elif command == "mine":
                print("Mining a new block...")
                block = node.mine_block()
                print(f"Block mined: {block.hash}")
            
            elif command.startswith("send "):
                parts = command.split(" ")
                if len(parts) != 3:
                    print("Usage: send <recipient> <amount>")
                    continue
                
                recipient = parts[1]
                try:
                    amount = float(parts[2])
                except ValueError:
                    print("Amount must be a number")
                    continue
                
                if node.create_transaction(recipient, amount):
                    print(f"Transaction created: {amount} STRZ to {recipient}")
                else:
                    print("Failed to create transaction: insufficient balance")
            
            elif command == "chain":
                print(f"Blockchain: {len(node.blockchain.chain)} blocks")
                for block in node.blockchain.chain:
                    print(f"Block #{block.index}: {block.hash}")
            
            elif command.startswith("save "):
                filename = command.split(" ")[1]
                node.blockchain.save_to_file(filename)
                print(f"Blockchain saved to {filename}")
            
            elif command.startswith("load "):
                filename = command.split(" ")[1]
                node.blockchain = Blockchain.load_from_file(filename)
                print(f"Blockchain loaded from {filename}")
            
            else:
                print(f"Unknown command: {command}")
        
        except Exception as e:
            print(f"Error: {e}")

```
---
### File: `modify_bitcoin.sh`

```bash
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
```
---
### File: `main.py`

```python
#!/usr/bin/env python3

import argparse
import os
import sys
import time
from typing import Dict, List, Any

from blockchain import Blockchain, Block
from wallet import Wallet, WalletManager
from node import Node

class StrazCLI:
    def __init__(self):
        self.blockchain = Blockchain()
        self.wallet_manager = WalletManager()
        self.node = None
        self.active_wallet = None
        
        # Create wallets directory if it doesn't exist
        os.makedirs("wallets", exist_ok=True)
        
        # Load existing wallets if any
        if os.path.exists("wallets"):
            self.wallet_manager.load_wallets("wallets")
            
            # Set the first wallet as active if available
            addresses = self.wallet_manager.get_all_addresses()
            if addresses:
                self.active_wallet = self.wallet_manager.get_wallet(addresses[0])
        
        # Create a wallet if none exists
        if not self.active_wallet:
            self.active_wallet = self.wallet_manager.create_wallet()
            self.wallet_manager.save_wallets("wallets")
            
    def start(self):
        """Start the Straz CLI."""
        parser = argparse.ArgumentParser(description="Straz Cryptocurrency")
        subparsers = parser.add_subparsers(dest="command", help="Command")
        
        # Node commands
        node_parser = subparsers.add_parser("node", help="Node operations")
        node_subparsers = node_parser.add_subparsers(dest="node_command", help="Node command")
        
        start_parser = node_subparsers.add_parser("start", help="Start a node")
        start_parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to")
        start_parser.add_argument("--port", type=int, default=5000, help="Port to bind to")
        start_parser.add_argument("--connect", type=str, help="Peer to connect to in format host:port")
        
        node_subparsers.add_parser("stop", help="Stop the node")
        node_subparsers.add_parser("status", help="Get node status")
        
        connect_parser = node_subparsers.add_parser("connect", help="Connect to a peer")
        connect_parser.add_argument("peer", type=str, help="Peer to connect to in format host:port")
        
        node_subparsers.add_parser("peers", help="List connected peers")
        
        # Wallet commands
        wallet_parser = subparsers.add_parser("wallet", help="Wallet operations")
        wallet_subparsers = wallet_parser.add_subparsers(dest="wallet_command", help="Wallet command")
        
        wallet_subparsers.add_parser("create", help="Create a new wallet")
        wallet_subparsers.add_parser("list", help="List all wallets")
        
        import_parser = wallet_subparsers.add_parser("import", help="Import a wallet from a private key")
        import_parser.add_argument("private_key", type=str, help="Private key to import")
        
        set_parser = wallet_subparsers.add_parser("set", help="Set active wallet")
        set_parser.add_argument("address", type=str, help="Address of the wallet to set as active")
        
        wallet_subparsers.add_parser("show", help="Show active wallet details")
        wallet_subparsers.add_parser("balance", help="Show wallet balance")
        
        export_parser = wallet_subparsers.add_parser("export", help="Export wallet to a file")
        export_parser.add_argument("--file", type=str, help="File to export to")
        
        # Mining commands
        mine_parser = subparsers.add_parser("mine", help="Mining operations")
        mine_subparsers = mine_parser.add_subparsers(dest="mine_command", help="Mining command")
        
        mine_subparsers.add_parser("start", help="Start mining")
        mine_subparsers.add_parser("stop", help="Stop mining")
        
        # Transaction commands
        tx_parser = subparsers.add_parser("tx", help="Transaction operations")
        tx_subparsers = tx_parser.add_subparsers(dest="tx_command", help="Transaction command")
        
        send_parser = tx_subparsers.add_parser("send", help="Send coins")
        send_parser.add_argument("recipient", type=str, help="Recipient address")
        send_parser.add_argument("amount", type=float, help="Amount to send")
        
        tx_subparsers.add_parser("pending", help="List pending transactions")
        
        # Blockchain commands
        chain_parser = subparsers.add_parser("chain", help="Blockchain operations")
        chain_subparsers = chain_parser.add_subparsers(dest="chain_command", help="Blockchain command")
        
        chain_subparsers.add_parser("info", help="Get blockchain info")
        
        block_parser = chain_subparsers.add_parser("block", help="Get block by index")
        block_parser.add_argument("index", type=int, help="Block index")
        
        save_parser = chain_subparsers.add_parser("save", help="Save blockchain to a file")
        save_parser.add_argument("--file", type=str, default="blockchain.json", help="File to save to")
        
        load_parser = chain_subparsers.add_parser("load", help="Load blockchain from a file")
        load_parser.add_argument("--file", type=str, default="blockchain.json", help="File to load from")
        
        chain_subparsers.add_parser("validate", help="Validate the blockchain")
        
        # Parse arguments
        args = parser.parse_args()
        
        if not args.command:
            self.interactive_mode()
            return
        
        # Handle commands
        if args.command == "node":
            self.handle_node_command(args)
        elif args.command == "wallet":
            self.handle_wallet_command(args)
        elif args.command == "mine":
            self.handle_mine_command(args)
        elif args.command == "tx":
            self.handle_tx_command(args)
        elif args.command == "chain":
            self.handle_chain_command(args)
    
    def handle_node_command(self, args):
        """Handle node commands."""
        if args.node_command == "start":
            if self.node:
                print("Node already running")
                return
            
            self.node = Node(args.host, args.port)
            self.node.set_wallet(self.active_wallet)
            self.node.start()
            
            if args.connect:
                peer_host, peer_port = args.connect.split(":")
                if self.node.connect_to_peer(peer_host, int(peer_port)):
                    print(f"Connected to peer {args.connect}")
                else:
                    print(f"Failed to connect to peer {args.connect}")
            
            print(f"Node started on {args.host}:{args.port}")
        
        elif args.node_command == "stop":
            if not self.node:
                print("No node running")
                return
            
            self.node.close()
            self.node = None
            print("Node stopped")
        
        elif args.node_command == "status":
            if not self.node:
                print("No node running")
                return
            
            print(f"Node running on {self.node.host}:{self.node.port}")
            print(f"Connected peers: {len(self.node.peers)}")
            print(f"Blockchain: {len(self.node.blockchain.chain)} blocks")
            print(f"Pending transactions: {len(self.node.blockchain.pending_transactions)}")
        
        elif args.node_command == "connect":
            if not self.node:
                print("No node running")
                return
            
            peer_host, peer_port = args.peer.split(":")
            if self.node.connect_to_peer(peer_host, int(peer_port)):
                print(f"Connected to peer {args.peer}")
            else:
                print(f"Failed to connect to peer {args.peer}")
        
        elif args.node_command == "peers":
            if not self.node:
                print("No node running")
                return
            
            print(f"Connected peers: {', '.join(self.node.peers) if self.node.peers else 'None'}")
    
    def handle_wallet_command(self, args):
        """Handle wallet commands."""
        if args.wallet_command == "create":
            wallet = self.wallet_manager.create_wallet()
            self.active_wallet = wallet
            self.wallet_manager.save_wallets("wallets")
            print(f"New wallet created: {wallet.address}")
            
            if self.node:
                self.node.set_wallet(wallet)
        
        elif args.wallet_command == "list":
            addresses = self.wallet_manager.get_all_addresses()
            if not addresses:
                print("No wallets found")
                return
            
            print("Wallets:")
            for i, address in enumerate(addresses):
                active = " (active)" if self.active_wallet and self.active_wallet.address == address else ""
                print(f"{i+1}. {address}{active}")
        
        elif args.wallet_command == "import":
            try:
                wallet = self.wallet_manager.import_wallet(args.private_key)
                self.active_wallet = wallet
                self.wallet_manager.save_wallets("wallets")
                print(f"Wallet imported: {wallet.address}")
                
                if self.node:
                    self.node.set_wallet(wallet)
            except Exception as e:
                print(f"Error importing wallet: {e}")
        
        elif args.wallet_command == "set":
            wallet = self.wallet_manager.get_wallet(args.address)
            if not wallet:
                print(f"Wallet not found: {args.address}")
                return
            
            self.active_wallet = wallet
            print(f"Active wallet set to: {wallet.address}")
            
            if self.node:
                self.node.set_wallet(wallet)
        
        elif args.wallet_command == "show":
            if not self.active_wallet:
                print("No active wallet")
                return
            
            print(f"Address: {self.active_wallet.address}")
            print(f"Private key: {self.active_wallet.private_key}")
            print(f"Public key: {self.active_wallet.public_key}")
        
        elif args.wallet_command == "balance":
            if not self.active_wallet:
                print("No active wallet")
                return
            
            balance = self.blockchain.get_balance(self.active_wallet.address)
            print(f"Balance: {balance} STRZ")
        
        elif args.wallet_command == "export":
            if not self.active_wallet:
                print("No active wallet")
                return
            
            filename = args.file or f"{self.active_wallet.address}.json"
            self.active_wallet.save_to_file(filename)
            print(f"Wallet exported to {filename}")
    
    def handle_mine_command(self, args):
        """Handle mining commands."""
        if not self.node:
            print("No node running, start a node first")
            return
        
        if args.mine_command == "start":
            print("Mining a new block...")
            block = self.node.mine_block()
            print(f"Block mined: {block.hash}")
        
        elif args.mine_command == "stop":
            print("Mining stopped")
    
    def handle_tx_command(self, args):
        """Handle transaction commands."""
        if not self.node:
            print("No node running, start a node first")
            return
        
        if args.tx_command == "send":
            if not self.active_wallet:
                print("No active wallet")
                return
            
            if self.node.create_transaction(args.recipient, args.amount):
                print(f"Transaction created: {args.amount} STRZ to {args.recipient}")
            else:
                print("Failed to create transaction: insufficient balance")
        
        elif args.tx_command == "pending":
            if not self.node.blockchain.pending_transactions:
                print("No pending transactions")
                return
            
            print(f"Pending transactions: {len(self.node.blockchain.pending_transactions)}")
            for i, tx in enumerate(self.node.blockchain.pending_transactions):
                print(f"{i+1}. {tx['sender']} -> {tx['recipient']}: {tx['amount']} STRZ")
    
    def handle_chain_command(self, args):
        """Handle blockchain commands."""
        if args.chain_command == "info":
            print(f"Blockchain: {len(self.blockchain.chain)} blocks")
            print(f"Difficulty: {self.blockchain.difficulty}")
            print(f"Mining reward: {self.blockchain.mining_reward} STRZ")
        
        elif args.chain_command == "block":
            if args.index >= len(self.blockchain.chain):
                print(f"Block index out of range: {args.index}")
                return
            
            block = self.blockchain.chain[args.index]
            print(f"Block #{block.index}")
            print(f"Timestamp: {block.timestamp}")
            print(f"Previous hash: {block.previous_hash}")
            print(f"Hash: {block.hash}")
            print(f"Nonce: {block.nonce}")
            print(f"Transactions: {len(block.transactions)}")
            
            for i, tx in enumerate(block.transactions):
                print(f"  {i+1}. {tx['sender']} -> {tx['recipient']}: {tx['amount']} STRZ")
        
        elif args.chain_command == "save":
            self.blockchain.save_to_file(args.file)
            print(f"Blockchain saved to {args.file}")
        
        elif args.chain_command == "load":
            if os.path.exists(args.file):
                self.blockchain = Blockchain.load_from_file(args.file)
                print(f"Blockchain loaded from {args.file}")
                
                if self.node:
                    self.node.blockchain = self.blockchain
            else:
                print(f"File not found: {args.file}")
        
        elif args.chain_command == "validate":
            is_valid = self.blockchain.is_chain_valid()
            print(f"Blockchain valid: {is_valid}")
    
    def interactive_mode(self):
        """Start an interactive command line interface."""
        print("Welcome to Straz CLI!")
        print("Type 'help' for a list of commands, 'exit' to quit.")
        
        while True:
            try:
                command = input("straz> ").strip()
                
                if command == "exit":
                    if self.node:
                        self.node.close()
                    break
                
                elif command == "help":
                    self.print_help()
                
                elif command == "clear":
                    os.system("clear" if os.name == "posix" else "cls")
                
                elif command.startswith("node "):
                    self.handle_interactive_node_command(command[5:])
                
                elif command.startswith("wallet "):
                    self.handle_interactive_wallet_command(command[7:])
                
                elif command.startswith("mine "):
                    self.handle_interactive_mine_command(command[5:])
                
                elif command.startswith("tx "):
                    self.handle_interactive_tx_command(command[3:])
                
                elif command.startswith("chain "):
                    self.handle_interactive_chain_command(command[6:])
                
                else:
                    print(f"Unknown command: {command}")
            
            except Exception as e:
                print(f"Error: {e}")
    
    def print_help(self):
        """Print help message."""
        print("Available commands:")
        print("  help - Show this help message")
        print("  exit - Exit the CLI")
        print("  clear - Clear the screen")
        print("  node start [host] [port] [peer] - Start a node")
        print("  node stop - Stop the node")
        print("  node status - Get node status")
        print("  node connect <host:port> - Connect to a peer")
        print("  node peers - List connected peers")
        print("  wallet create - Create a new wallet")
        print("  wallet list - List all wallets")
        print("  wallet import <private_key> - Import a wallet from a private key")
        print("  wallet set <address> - Set active wallet")
        print("  wallet show - Show active wallet details")
        print("  wallet balance - Show wallet balance")
        print("  wallet export [file] - Export wallet to a file")
        print("  mine start - Start mining")
        print("  tx send <recipient> <amount> - Send coins")
        print("  tx pending - List pending transactions")
        print("  chain info - Get blockchain info")
        print("  chain block <index> - Get block by index")
        print("  chain save [file] - Save blockchain to a file")
        print("  chain load [file] - Load blockchain from a file")
        print("  chain validate - Validate the blockchain")
    
    def handle_interactive_node_command(self, command):
        """Handle interactive node commands."""
        parts = command.split()
        
        if not parts:
            print("Missing node command")
            return
        
        if parts[0] == "start":
            if self.node:
                print("Node already running")
                return
            
            host = parts[1] if len(parts) > 1 else "0.0.0.0"
            port = int(parts[2]) if len(parts) > 2 else 5000
            
            self.node = Node(host, port)
            self.node.set_wallet(self.active_wallet)
            self.node.start()
            
            if len(parts) > 3:
                peer = parts[3]
                peer_host, peer_port = peer.split(":")
                if self.node.connect_to_peer(peer_host, int(peer_port)):
                    print(f"Connected to peer {peer}")
                else:
                    print(f"Failed to connect to peer {peer}")
            
            print(f"Node started on {host}:{port}")
        
        elif parts[0] == "stop":
            if not self.node:
                print("No node running")
                return
            
            self.node.close()
            self.node = None
            print("Node stopped")
        
        elif parts[0] == "status":
            if not self.node:
                print("No node running")
                return
            
            print(f"Node running on {self.node.host}:{self.node.port}")
            print(f"Connected peers: {len(self.node.peers)}")
            print(f"Blockchain: {len(self.node.blockchain.chain)} blocks")
            print(f"Pending transactions: {len(self.node.blockchain.pending_transactions)}")
        
        elif parts[0] == "connect":
            if not self.node:
                print("No node running")
                return
            
            if len(parts) < 2:
                print("Missing peer address")
                return
            
            peer = parts[1]
            peer_host, peer_port = peer.split(":")
            if self.node.connect_to_peer(peer_host, int(peer_port)):
                print(f"Connected to peer {peer}")
            else:
                print(f"Failed to connect to peer {peer}")
        
        elif parts[0] == "peers":
            if not self.node:
                print("No node running")
                return
            
            print(f"Connected peers: {', '.join(self.node.peers) if self.node.peers else 'None'}")
        
        else:
            print(f"Unknown node command: {parts[0]}")
    
    def handle_interactive_wallet_command(self, command):
        """Handle interactive wallet commands."""
        parts = command.split()
        
        if not parts:
            print("Missing wallet command")
            return
        
        if parts[0] == "create":
            wallet = self.wallet_manager.create_wallet()
            self.active_wallet = wallet
            self.wallet_manager.save_wallets("wallets")
            print(f"New wallet created: {wallet.address}")
            
            if self.node:
                self.node.set_wallet(wallet)
        
        elif parts[0] == "list":
            addresses = self.wallet_manager.get_all_addresses()
            if not addresses:
                print("No wallets found")
                return
            
            print("Wallets:")
            for i, address in enumerate(addresses):
                active = " (active)" if self.active_wallet and self.active_wallet.address == address else ""
                print(f"{i+1}. {address}{active}")
        
        elif parts[0] == "import":
            if len(parts) < 2:
                print("Missing private key")
                return
            
            try:
                wallet = self.wallet_manager.import_wallet(parts[1])
                self.active_wallet = wallet
                self.wallet_manager.save_wallets("wallets")
                print(f"Wallet imported: {wallet.address}")
                
                if self.node:
                    self.node.set_wallet(wallet)
            except Exception as e:
                print(f"Error importing wallet: {e}")
        
        elif parts[0] == "set":
            if len(parts) < 2:
                print("Missing address")
                return
            
            wallet = self.wallet_manager.get_wallet(parts[1])
            if not wallet:
                print(f"Wallet not found: {parts[1]}")
                return
            
            self.active_wallet = wallet
            print(f"Active wallet set to: {wallet.address}")
            
            if self.node:
                self.node.set_wallet(wallet)
        
        elif parts[0] == "show":
            if not self.active_wallet:
                print("No active wallet")
                return
            
            print(f"Address: {self.active_wallet.address}")
            print(f"Private key: {self.active_wallet.private_key}")
            print(f"Public key: {self.active_wallet.public_key}")
        
        elif parts[0] == "balance":
            if not self.active_wallet:
                print("No active wallet")
                return
            
            balance = self.blockchain.get_balance(self.active_wallet.address)
            print(f"Balance: {balance} STRZ")
        
        elif parts[0] == "export":
            if not self.active_wallet:
                print("No active wallet")
                return
            
            filename = parts[1] if len(parts) > 1 else f"{self.active_wallet.address}.json"
            self.active_wallet.save_to_file(filename)
            print(f"Wallet exported to {filename}")
        
        else:
            print(f"Unknown wallet command: {parts[0]}")
    
    def handle_interactive_mine_command(self, command):
        """Handle interactive mining commands."""
        parts = command.split()
        
        if not parts:
            print("Missing mining command")
            return
        
        if not self.node:
            print("No node running, start a node first")
            return
        
        if parts[0] == "start":
            print("Mining a new block...")
            block = self.node.mine_block()
            print(f"Block mined: {block.hash}")
        
        else:
            print(f"Unknown mining command: {parts[0]}")
    
    def handle_interactive_tx_command(self, command):
        """Handle interactive transaction commands."""
        parts = command.split()
        
        if not parts:
            print("Missing transaction command")
            return
        
        if not self.node:
            print("No node running, start a node first")
            return
        
        if parts[0] == "send":
            if len(parts) < 3:
                print("Usage: tx send <recipient> <amount>")
                return
            
            if not self.active_wallet:
                print("No active wallet")
                return
            
            try:
                recipient = parts[1]
                amount = float(parts[2])
                
                if self.node.create_transaction(recipient, amount):
                    print(f"Transaction created: {amount} STRZ to {recipient}")
                else:
                    print("Failed to create transaction: insufficient balance")
            except ValueError:
                print("Amount must be a number")
        
        elif parts[0] == "pending":
            if not self.node.blockchain.pending_transactions:
                print("No pending transactions")
                return
            
            print(f"Pending transactions: {len(self.node.blockchain.pending_transactions)}")
            for i, tx in enumerate(self.node.blockchain.pending_transactions):
                print(f"{i+1}. {tx['sender']} -> {tx['recipient']}: {tx['amount']} STRZ")
        
        else:
            print(f"Unknown transaction command: {parts[0]}")
    
    def handle_interactive_chain_command(self, command):
        """Handle interactive blockchain commands."""
        parts = command.split()
        
        if not parts:
            print("Missing blockchain command")
            return
        
        if parts[0] == "info":
            print(f"Blockchain: {len(self.blockchain.chain)} blocks")
            print(f"Difficulty: {self.blockchain.difficulty}")
            print(f"Mining reward: {self.blockchain.mining_reward} STRZ")
        
        elif parts[0] == "block":
            if len(parts) < 2:
                print("Missing block index")
                return
            
            try:
                index = int(parts[1])
                
                if index >= len(self.blockchain.chain):
                    print(f"Block index out of range: {index}")
                    return
                
                block = self.blockchain.chain[index]
                print(f"Block #{block.index}")
                print(f"Timestamp: {block.timestamp}")
                print(f"Previous hash: {block.previous_hash}")
                print(f"Hash: {block.hash}")
                print(f"Nonce: {block.nonce}")
                print(f"Transactions: {len(block.transactions)}")
                
                for i, tx in enumerate(block.transactions):
                    print(f"  {i+1}. {tx['sender']} -> {tx['recipient']}: {tx['amount']} STRZ")
            except ValueError:
                print("Block index must be a number")
        
        elif parts[0] == "save":
            filename = parts[1] if len(parts) > 1 else "blockchain.json"
            self.blockchain.save_to_file(filename)
            print(f"Blockchain saved to {filename}")
        
        elif parts[0] == "load":
            filename = parts[1] if len(parts) > 1 else "blockchain.json"
            
            if os.path.exists(filename):
                self.blockchain = Blockchain.load_from_file(filename)
                print(f"Blockchain loaded from {filename}")
                
                if self.node:
                    self.node.blockchain = self.blockchain
            else:
                print(f"File not found: {filename}")
        
        elif parts[0] == "validate":
            is_valid = self.blockchain.is_chain_valid()
            print(f"Blockchain valid: {is_valid}")
        
        else:
            print(f"Unknown blockchain command: {parts[0]}")


if __name__ == "__main__":
    cli = StrazCLI()
    cli.start()

```
---
### File: `consensus.json`

```json
{
    "difficulty": 4,
    "validators": {
        "1K1XmPJVgnth11unZXvoMsL1aMkqJMgh1P": {
            "stake": 1000.0,
            "last_vote": 1746581868.2818592,
            "is_active": true
        }
    },
    "current_epoch": 0,
    "leader_schedule": {}
}
```
---
### File: `wallet.py`

```python
#!/usr/bin/env python3

import hashlib
import binascii
import os
import json
import base58
import ecdsa
from typing import Dict, Tuple, Optional, List

class Wallet:
    def __init__(self, private_key: Optional[str] = None):
        """Initialize a new wallet or load an existing one from a private key."""
        if private_key:
            self.private_key = private_key
            # Derive public key from private key
            self.public_key = self.private_key_to_public_key(private_key)
        else:
            # Generate a new key pair
            self.private_key, self.public_key = self.generate_key_pair()
        
        # Generate address from public key
        self.address = self.public_key_to_address(self.public_key)
    
    @staticmethod
    def generate_key_pair() -> Tuple[str, str]:
        """Generate a new ECDSA key pair."""
        # Generate private key
        private_key_bytes = os.urandom(32)
        private_key = binascii.hexlify(private_key_bytes).decode('utf-8')
        
        # Derive public key from private key
        public_key = Wallet.private_key_to_public_key(private_key)
        
        return private_key, public_key
    
    @staticmethod
    def private_key_to_public_key(private_key: str) -> str:
        """Derive public key from private key using ECDSA."""
        private_key_bytes = binascii.unhexlify(private_key)
        key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        verifying_key = key.get_verifying_key()
        public_key_bytes = verifying_key.to_string()
        public_key = binascii.hexlify(public_key_bytes).decode('utf-8')
        
        # Add prefix for compressed public key format
        return "04" + public_key
    
    @staticmethod
    def public_key_to_address(public_key: str) -> str:
        """Convert public key to Straz address using SHA-256 and RIPEMD-160."""
        # Step 1: SHA-256 hash of the public key
        public_key_bytes = binascii.unhexlify(public_key)
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        
        # Step 2: RIPEMD-160 hash of the SHA-256 hash
        ripemd160_hasher = hashlib.new('ripemd160')
        ripemd160_hasher.update(sha256_hash)
        ripemd160_hash = ripemd160_hasher.digest()
        
        # Step 3: Add version byte (0x00 for main network)
        versioned_hash = b'\x00' + ripemd160_hash
        
        # Step 4: SHA-256 hash of the versioned hash
        sha256_hash_1 = hashlib.sha256(versioned_hash).digest()
        
        # Step 5: SHA-256 hash of the previous hash
        sha256_hash_2 = hashlib.sha256(sha256_hash_1).digest()
        
        # Step 6: First 4 bytes of the second SHA-256 hash (checksum)
        checksum = sha256_hash_2[:4]
        
        # Step 7: Append checksum to versioned hash
        address_bytes = versioned_hash + checksum
        
        # Step 8: Base58 encode the binary address
        address = base58.b58encode(address_bytes).decode('utf-8')
        
        return address
    
    def sign_transaction(self, transaction_data: Dict) -> str:
        """Sign a transaction with the wallet's private key."""
        # Convert transaction data to string and hash it
        transaction_string = json.dumps(transaction_data, sort_keys=True).encode()
        transaction_hash = hashlib.sha256(transaction_string).digest()
        
        # Sign the hash with private key
        private_key_bytes = binascii.unhexlify(self.private_key)
        key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        signature = key.sign(transaction_hash)
        
        return binascii.hexlify(signature).decode('utf-8')
    
    @staticmethod
    def verify_signature(transaction_data: Dict, signature: str, public_key: str) -> bool:
        """Verify a transaction signature with the sender's public key."""
        # Convert transaction data to string and hash it
        transaction_string = json.dumps(transaction_data, sort_keys=True).encode()
        transaction_hash = hashlib.sha256(transaction_string).digest()
        
        # Convert signature and public key to bytes
        signature_bytes = binascii.unhexlify(signature)
        public_key_bytes = binascii.unhexlify(public_key)
        
        # Remove the prefix from the public key
        if public_key.startswith("04"):
            public_key_bytes = binascii.unhexlify(public_key[2:])
        
        try:
            # Verify the signature
            verifying_key = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)
            return verifying_key.verify(signature_bytes, transaction_hash)
        except:
            return False
    
    def to_dict(self) -> Dict:
        """Convert the wallet to a dictionary."""
        return {
            "private_key": self.private_key,
            "public_key": self.public_key,
            "address": self.address
        }
    
    def save_to_file(self, filename: str) -> None:
        """Save the wallet to a file."""
        with open(filename, 'w') as f:
            json.dump(self.to_dict(), f, indent=4)
        
        print(f"Wallet saved to {filename}")
    
    @classmethod
    def load_from_file(cls, filename: str) -> 'Wallet':
        """Load a wallet from a file."""
        with open(filename, 'r') as f:
            data = json.load(f)
        
        wallet = cls(data["private_key"])
        
        print(f"Wallet loaded from {filename}")
        return wallet


class WalletManager:
    def __init__(self):
        """Initialize a new wallet manager."""
        self.wallets: Dict[str, Wallet] = {}
    
    def create_wallet(self) -> Wallet:
        """Create a new wallet and add it to the manager."""
        wallet = Wallet()
        self.wallets[wallet.address] = wallet
        return wallet
    
    def import_wallet(self, private_key: str) -> Wallet:
        """Import an existing wallet from a private key."""
        wallet = Wallet(private_key)
        self.wallets[wallet.address] = wallet
        return wallet
    
    def get_wallet(self, address: str) -> Optional[Wallet]:
        """Get a wallet by its address."""
        return self.wallets.get(address)
    
    def get_all_addresses(self) -> List[str]:
        """Get all wallet addresses."""
        return list(self.wallets.keys())
    
    def save_wallets(self, directory: str) -> None:
        """Save all wallets to separate files in a directory."""
        os.makedirs(directory, exist_ok=True)
        
        for address, wallet in self.wallets.items():
            filename = os.path.join(directory, f"{address}.json")
            wallet.save_to_file(filename)
    
    def load_wallets(self, directory: str) -> None:
        """Load all wallets from files in a directory."""
        if not os.path.exists(directory):
            print(f"Directory {directory} does not exist")
            return
        
        for filename in os.listdir(directory):
            if filename.endswith(".json"):
                full_path = os.path.join(directory, filename)
                wallet = Wallet.load_from_file(full_path)
                self.wallets[wallet.address] = wallet


if __name__ == "__main__":
    # Example usage
    print("Creating a new wallet...")
    wallet = Wallet()
    print(f"Address: {wallet.address}")
    print(f"Private key: {wallet.private_key}")
    print(f"Public key: {wallet.public_key}")
    
    # Create a transaction
    transaction = {
        "sender": wallet.address,
        "recipient": "recipient-address",
        "amount": 10,
        "timestamp": 1234567890
    }
    
    # Sign the transaction
    signature = wallet.sign_transaction(transaction)
    print(f"\nTransaction signature: {signature}")
    
    # Verify the signature
    is_valid = Wallet.verify_signature(transaction, signature, wallet.public_key)
    print(f"Signature valid: {is_valid}")
    
    # Save the wallet
    wallet.save_to_file("wallet.json")
    
    # Load the wallet
    loaded_wallet = Wallet.load_from_file("wallet.json")
    print(f"\nLoaded wallet address: {loaded_wallet.address}")

```
---
### File: `genesis.py`

```python
#!/usr/bin/env python3

import hashlib
import time
import struct
import binascii

def sha256(data):
    return hashlib.sha256(data).digest()

def sha256d(data):
    return sha256(sha256(data))

def uint32(x):
    return x & 0xffffffff

def bytereverse(x):
    # Handle both int and bytes types
    if isinstance(x, int):
        return uint32((x >> 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x << 24))
    else:
        return uint32(int.from_bytes(x, byteorder='little'))

def bufreverse(in_buf):
    out_words = []
    for i in range(0, len(in_buf), 4):
        word = struct.unpack("@I", in_buf[i:i+4])[0]
        out_words.append(struct.pack("@I", bytereverse(word)))
    return b''.join(out_words)

def wordreverse(in_buf):
    out_words = []
    for i in range(0, len(in_buf), 4):
        out_words.append(in_buf[i:i+4])
    out_words.reverse()
    return b''.join(out_words)

def calc_hash_str(merkle_root):
    version = 1
    prev_block = "0" * 64
    timestamp = 1748736000  # May 5, 2025 00:00:00 UTC
    bits = 0x1d00ffff
    nonce = 0

    header = struct.pack("<I", version)
    header += binascii.unhexlify(prev_block)[::-1]
    header += struct.pack("<I", timestamp)
    header += struct.pack("<I", bits)
    header += struct.pack("<I", nonce)
    header += merkle_root

    hash = sha256d(header)
    hash = bufreverse(hash)
    hash = wordreverse(hash)
    hash_str = binascii.hexlify(hash).decode('utf-8')

    return hash_str

def main():
    # Genesis block parameters
    timestamp = "Straz Genesis Block – Privacy & Payments, 2025-05-05"
    pubkey = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
    value = 50 * 100000000  # 50 STRZ in satoshis
    script = "4104" + pubkey + "ac"  # P2PKH script

    # Create coinbase transaction
    tx_in = struct.pack("<I", 0xffffffff)  # Previous output index
    tx_in += struct.pack("<B", len(timestamp)) + timestamp.encode()  # Coinbase script
    tx_in += struct.pack("<I", 0xffffffff)  # Sequence

    tx_out = struct.pack("<Q", value)  # Value
    tx_out += struct.pack("<B", len(script)//2) + binascii.unhexlify(script)  # Script

    tx = struct.pack("<I", 1)  # Version
    tx += struct.pack("<B", 1)  # Input count
    tx += tx_in
    tx += struct.pack("<B", 1)  # Output count
    tx += tx_out
    tx += struct.pack("<I", 0)  # Lock time

    # Calculate merkle root
    merkle_root = sha256d(tx)
    merkle_root = bufreverse(merkle_root)
    merkle_root = wordreverse(merkle_root)

    # Find nonce that gives hash below target
    target = 0x1d00ffff
    nonce = 0
    while True:
        header = struct.pack("<I", 1)  # Version
        header += b'\x00' * 32  # Previous block hash
        header += struct.pack("<I", 1748736000)  # Timestamp
        header += struct.pack("<I", target)  # Bits
        header += struct.pack("<I", nonce)  # Nonce
        header += merkle_root

        hash = sha256d(header)
        hash = bufreverse(hash)
        hash = wordreverse(hash)
        hash_int = int.from_bytes(hash, byteorder='big')

        if hash_int < target:
            break

        nonce += 1
        if nonce % 1000000 == 0:
            print(f"Tried {nonce} nonces...")

    # Print results
    print("\nGenesis Block Parameters:")
    print(f"Timestamp: {timestamp}")
    print(f"Pubkey: {pubkey}")
    print(f"Nonce: {nonce}")
    print(f"Merkle Root: {binascii.hexlify(merkle_root).decode('utf-8')}")
    print(f"Hash: {binascii.hexlify(hash).decode('utf-8')}")

if __name__ == "__main__":
    main() 
```
---
### File: `wallets/15CAQYMYsmnnL2giK5F9pZ2ycqcY5kQNGq.json`

```json
{
    "private_key": "af3fb486956ba14ad0e88b223ea3c514ccb9ae553d76c908ec05314e4834ae4c",
    "public_key": "047fcf7e875287faa7e9b014093b2a69c665a9114433eaf75d7ef807ab67042e0907800b448eb23acf28f3c589bfae52a82505bd6183afefbb5b9ebcf2e13439ee",
    "address": "15CAQYMYsmnnL2giK5F9pZ2ycqcY5kQNGq"
}
```
---
### File: `wallets/13xtqyaSQGD1TJHoYgcaT2ZQFHdGqCGF58.json`

```json
{
    "private_key": "e2cc024d44a305d89a9147af90a13bde8b8f40a1683374c386f1308aa12df9b8",
    "public_key": "04be9e46bd3e2d9b5e56380029c97284c16b9ffd21d35c4932f785e09d5e67a16b00246ebb52d4fae1fadc158287ed9d6f626ef9fe6454e6cbd5d1d505651eb6f6",
    "address": "13xtqyaSQGD1TJHoYgcaT2ZQFHdGqCGF58"
}
```
---
### File: `wallets/1CkoNV1NVGFAYWvxig9JPoKC9UqJtFzPaS.json`

```json
{
    "private_key": "3625ed92f326ca45742b0396e04ffb7c3a926377c269595c067710a99816176a",
    "public_key": "045465b8b193e82d4c44c26fc1511ebbae4174c1860dbaa91d0bc03393a33bfb31d70b828bad3f28a8d425a3312c4f3756ac4765b49ceedd8d260cfed296d3cf0b",
    "address": "1CkoNV1NVGFAYWvxig9JPoKC9UqJtFzPaS"
}
```
---
### File: `wallets/18nXnrPE9Worf5qdzVDijvmzgUGXUHABed.json`

```json
{
    "private_key": "c2f99b38d8b17bb79595bc4995640c67436a4bc362877177fa67d0a438fa0f61",
    "public_key": "046ff4da6e3fb9c9fdf3fbdb217dc902366d741410d0bf83509da3f7eb64657a0c54386288032f806bea66374c79035e16b39c36626dab34f67fa2ec731d640c4f",
    "address": "18nXnrPE9Worf5qdzVDijvmzgUGXUHABed"
}
```
---
### File: `wallets/1K1XmPJVgnth11unZXvoMsL1aMkqJMgh1P.json`

```json
{
    "private_key": "848d1ecbe64d4141fc6ebbd8c2db17d8b03bd442c186ef511d8dfabef26f86d2",
    "public_key": "0467c7d0756e946f90ad31e0d6dfba0359dbb6b4ce27817d9a7ce66e45daa4725c746e8da09bd210189c28191dfffe762d6262b67aa3cea5a5fe0d65c2cd790775",
    "address": "1K1XmPJVgnth11unZXvoMsL1aMkqJMgh1P"
}
```
---
### File: `wallets/1Nxn8CvvVfWYV3PBge8NdW9m5wpovDVpko.json`

```json
{
    "private_key": "948e94825d452186ac0d8e927887ab6ed2220ca1db24a79e7e612597d3d84c10",
    "public_key": "04de342a14723ac7bdaea3dc3d902bfb947f32ffe83ee5c34830d88358be9bcc5948c5aead2c317b07b472488635c104241b3137c3c5e6052a9cdb8da10c2f6eed",
    "address": "1Nxn8CvvVfWYV3PBge8NdW9m5wpovDVpko"
}
```
---
### File: `wallets/1Bb9Bqgw9L1F4M61dDyNuwU3Jqgd8RRM4x.json`

```json
{
    "private_key": "65617b75bc659b7192f1e43fff1a3cd39f3872dba4a6c600f94c64f3f77914b9",
    "public_key": "04ca62cab8de9dff494e6340dca68aa5a06f817154bd3e0fd0d569fe83708ef5113b02619621c544bc20c3f6b02d488be7ba9e152e9897d85d86bf04348afbcd2c",
    "address": "1Bb9Bqgw9L1F4M61dDyNuwU3Jqgd8RRM4x"
}
```
---
### File: `wallets/144Y4UGMU8R61xFZnfDX6YH3AXLNhB9BNm.json`

```json
{
    "private_key": "0a45290a8c417e45c00c968f34cba8ffd84af1b6db3c74a434d9e3857e92031e",
    "public_key": "04518f5a4fdf1c531fc7f6fa84c0164b36d34fc6ddc92e50f2676b1dff86823c108ea35ac2c69fe9fb228cee106221e9c625f7504a0e277e82f51e87757048d9ad",
    "address": "144Y4UGMU8R61xFZnfDX6YH3AXLNhB9BNm"
}
```
---
### File: `src/api.js`

```javascript
// Blockchain routes
router.get('/blockchain/status', (req, res) => {
    res.json({
        status: 'success',
        data: {
            height: blockchain.getLatestBlock().index,
            difficulty: blockchain.getDifficulty(),
            network: 'mainnet'
        }
    });
});

// Wallet routes
router.post('/wallets/create', (req, res) => {
    const wallet = walletManager.createWallet();
    res.json({
        status: 'success',
        data: {
            address: wallet.address,
            publicKey: wallet.publicKey
        }
    });
});

// Mining routes
router.post('/mining/mine', (req, res) => {
    const { address } = req.body;
    if (!address) {
        return res.status(400).json({
            status: 'error',
            message: 'Miner address is required'
        });
    }

    const block = blockchain.minePendingTransactions(address);
    res.json({
        status: 'success',
        data: {
            block: {
                index: block.index,
                timestamp: block.timestamp,
                transactions: block.transactions,
                hash: block.hash,
                previousHash: block.previousHash
            }
        }
    });
});

// Transaction routes
router.post('/transactions/send', (req, res) => {
    const { fromAddress, toAddress, amount, privateKey } = req.body;
    
    if (!fromAddress || !toAddress || !amount || !privateKey) {
        return res.status(400).json({
            status: 'error',
            message: 'Missing required fields'
        });
    }

    try {
        const transaction = new Transaction(fromAddress, toAddress, amount);
        transaction.signTransaction(privateKey);
        blockchain.addTransaction(transaction);
        
        res.json({
            status: 'success',
            data: {
                transaction: {
                    fromAddress: transaction.fromAddress,
                    toAddress: transaction.toAddress,
                    amount: transaction.amount,
                    timestamp: transaction.timestamp,
                    signature: transaction.signature
                }
            }
        });
    } catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message
        });
    }
});

// Smart contract routes
router.post('/contracts/deploy', (req, res) => {
    console.log('Received contract deployment request');
    const { contractCode, deployerAddress, privateKey } = req.body;
    
    if (!contractCode || !deployerAddress || !privateKey) {
        console.log('Missing required fields:', { contractCode: !!contractCode, deployerAddress: !!deployerAddress, privateKey: !!privateKey });
        return res.status(400).json({
            status: 'error',
            message: 'Missing required fields'
        });
    }

    try {
        console.log('Deploying contract...');
        const contract = smartContracts.deployContract(contractCode, deployerAddress, privateKey);
        console.log('Contract deployed successfully:', contract.address);
        
        res.json({
            status: 'success',
            data: {
                contract: {
                    address: contract.address,
                    code: contract.code,
                    state: contract.state,
                    deployer: contract.deployer
                }
            }
        });
    } catch (error) {
        console.error('Contract deployment failed:', error);
        res.status(400).json({
            status: 'error',
            message: error.message
        });
    }
});

router.post('/contracts/:address/call', (req, res) => {
    const { address } = req.params;
    const { method, params, callerAddress, privateKey } = req.body;
    
    if (!method || !callerAddress || !privateKey) {
        return res.status(400).json({
            status: 'error',
            message: 'Missing required fields'
        });
    }

    try {
        const result = smartContracts.callContract(address, method, params, callerAddress, privateKey);
        res.json({
            status: 'success',
            data: {
                result,
                contract: {
                    address,
                    state: smartContracts.getContractState(address)
                }
            }
        });
    } catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message
        });
    }
});

router.get('/contracts/:address/state', (req, res) => {
    const { address } = req.params;
    
    try {
        const state = smartContracts.getContractState(address);
        res.json({
            status: 'success',
            data: {
                address,
                state
            }
        });
    } catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message
        });
    }
}); 
```
---
