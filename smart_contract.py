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