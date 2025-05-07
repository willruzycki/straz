#!/usr/bin/env python3

from flask import Flask, request, jsonify
from blockchain import Blockchain
from wallet import Wallet, WalletManager
import os
import json
from typing import Dict, Any
import logging

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
        blockchain.create_transaction(
            data["sender"],
            data["recipient"],
            float(data["amount"])
        )
        return jsonify({"message": "Transaction added to pool"}), 201
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

# Initialize on startup
load_or_create_wallet_manager()
load_or_create_blockchain()

if __name__ == "__main__":
    # Print registered routes
    logger.info("Registered routes:")
    for rule in app.url_map.iter_rules():
        logger.info(f"{rule.endpoint}: {rule.methods} {rule.rule}")
    
    app.run(host="0.0.0.0", port=5002, debug=True) 