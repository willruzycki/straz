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
