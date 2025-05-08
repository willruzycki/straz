import pytest
import time
from src.blockchain import Blockchain
from src.wallet import Wallet, WalletManager

@pytest.fixture
def blockchain_instance():
    """Create a fresh blockchain instance for testing"""
    return Blockchain(difficulty=2)  # Use lower difficulty for faster tests

@pytest.fixture
def wallet_manager():
    """Create a fresh wallet manager for testing"""
    return WalletManager()

def test_blockchain_initialization(blockchain_instance):
    """Test that a new blockchain is properly initialized"""
    assert len(blockchain_instance.chain) == 1  # Should have genesis block
    assert blockchain_instance.difficulty == 2
    assert blockchain_instance.pending_transactions == []

def test_add_transaction(blockchain_instance, wallet_manager):
    """Test adding a transaction to the blockchain"""
    # Create two wallets
    wallet1 = wallet_manager.create_wallet()
    wallet2 = wallet_manager.create_wallet()
    
    # Add a transaction
    success = blockchain_instance.create_transaction(
        wallet1.address,
        wallet2.address,
        1.0,  # amount
        0.001  # fee
    )
    
    assert success
    assert len(blockchain_instance.pending_transactions) == 1
    tx = blockchain_instance.pending_transactions[0]
    assert tx.sender == wallet1.address
    assert tx.recipient == wallet2.address
    assert tx.amount == 1.0
    assert tx.fee == 0.001

def test_mine_pending_transactions(blockchain_instance, wallet_manager):
    """Test mining pending transactions"""
    # Create wallets and add a transaction
    wallet1 = wallet_manager.create_wallet()
    wallet2 = wallet_manager.create_wallet()
    blockchain_instance.create_transaction(
        wallet1.address,
        wallet2.address,
        1.0,
        0.001
    )
    
    # Mine the transaction
    blockchain_instance.mine_pending_transactions(wallet1.address)
    
    # Check that the transaction was mined
    assert len(blockchain_instance.pending_transactions) == 0
    assert len(blockchain_instance.chain) == 2  # Genesis block + new block
    
    # Check that the miner received the reward
    assert blockchain_instance.get_balance(wallet1.address) > 0

# More tests will be added here, for example:
# def test_block_creation(sample_block):
#     assert sample_block.index == 1
#     assert sample_block.data == "Sample Block"

# def test_add_block_to_blockchain(blockchain_instance, sample_block):
#     initial_length = len(blockchain_instance.chain)
#     blockchain_instance.add_block(sample_block) # Assuming an add_block method
#     assert len(blockchain_instance.chain) == initial_length + 1
#     assert blockchain_instance.chain[-1] == sample_block

# def test_block_validation(blockchain_instance):
#     # Create a valid block and an invalid block
#     # Test blockchain_instance.is_block_valid(...) or similar
#     pass

# def test_chain_validation(blockchain_instance):
#     # Test blockchain_instance.is_chain_valid(...) or similar
#     pass

# --- Tests based on your initial request ---

# def test_block_mining():
#     # This will involve importing mining functions/logic from blockchain.py or consensus.py
#     # Create a new block, mine it (find a valid nonce)
#     # Assert that the mined block is valid according to consensus rules
#     pass

# def test_block_validation_logic():
#     # Create a block
#     # Test its validation (e.g., hash, PoW, signature if applicable)
#     pass

# smart_contract.py related tests might go into a separate test_smart_contract.py
# For now, focusing on blockchain.py

# Fork resolution might involve both blockchain.py and consensus.py,
# so those tests could be in test_consensus.py or a more general test_integration.py 