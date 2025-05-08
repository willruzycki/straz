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
