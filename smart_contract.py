#!/usr/bin/env python3

from typing import Dict, Any, List, Optional
import json
import hashlib
from dataclasses import dataclass
import time

@dataclass
class ContractState:
    balance: float
    storage: Dict[str, Any]
    code: str
    owner: str

class SmartContract:
    def __init__(self, address: str, code: str, owner: str):
        self.address = address
        self.code = code
        self.owner = owner
        self.state = ContractState(
            balance=0.0,
            storage={},
            code=code,
            owner=owner
        )
        self.last_execution = 0
        self.gas_used = 0
        
        # Compile the code into a namespace
        self.namespace = {}
        try:
            exec(code, self.namespace)
        except Exception as e:
            raise ValueError(f"Invalid contract code: {str(e)}")

    def execute(self, method: str, params: List[Any], sender: str, value: float = 0) -> Dict[str, Any]:
        """Execute a contract method with parameters"""
        # Basic gas calculation
        gas_cost = len(method) + sum(len(str(p)) for p in params)
        
        # Check if method exists
        if method not in self.namespace:
            return {"success": False, "error": f"Method {method} not found", "gas_used": gas_cost}
        
        # Add value to contract balance
        if value > 0:
            self.state.balance += value
        
        # Create contract context
        context = {
            "sender": sender,
            "value": value,
            "balance": self.state.balance,
            "storage": self.state.storage,
            "address": self.address,
            "owner": self.owner
        }
        
        try:
            # Execute the method in the contract's namespace
            result = self.namespace[method](self, *params)
            return {
                "success": True,
                "result": result,
                "gas_used": gas_cost,
                "context": context
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "gas_used": gas_cost,
                "context": context
            }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "code": self.code,
            "owner": self.owner,
            "state": {
                "balance": self.state.balance,
                "storage": self.state.storage
            }
        }
        
    def __getattr__(self, name: str):
        """Allow access to storage as attributes"""
        if name in self.state.storage:
            return self.state.storage[name]
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")
        
    def __setattr__(self, name: str, value: Any):
        """Allow setting storage as attributes"""
        if name in ["address", "code", "owner", "state", "last_execution", "gas_used", "namespace"]:
            super().__setattr__(name, value)
        else:
            if not hasattr(self, "state"):
                super().__setattr__(name, value)
            else:
                self.state.storage[name] = value

class ContractManager:
    def __init__(self):
        self.contracts: Dict[str, SmartContract] = {}
        self.contract_code: Dict[str, str] = {}

    def deploy_contract(self, contractCode: str, deployerAddress: str, privateKey: str) -> SmartContract:
        """Deploy a new smart contract
        
        Args:
            contractCode: The smart contract code to deploy
            deployerAddress: The address of the contract deployer
            privateKey: The private key of the deployer for signing
            
        Returns:
            SmartContract: The deployed contract instance
            
        Raises:
            ValueError: If the contract code is invalid or deployment fails
        """
        # Generate contract address
        contract_hash = hashlib.sha256(f"{contractCode}{deployerAddress}{time.time()}".encode()).hexdigest()
        address = f"0x{contract_hash[:40]}"
        
        # Create and store contract
        contract = SmartContract(address, contractCode, deployerAddress)
        self.contracts[address] = contract
        self.contract_code[address] = contractCode
        
        return contract

    def get_contract(self, address: str) -> Optional[SmartContract]:
        """Get a contract by its address"""
        return self.contracts.get(address)

    def execute_contract(self, address: str, method: str, params: List[Any], sender: str, value: float = 0) -> Dict[str, Any]:
        """Execute a contract method"""
        contract = self.get_contract(address)
        if not contract:
            return {"success": False, "error": "Contract not found"}
        
        return contract.execute(method, params, sender, value)

    def save_contracts(self, filename: str):
        """Save contracts to a file"""
        data = {
            "contracts": {
                addr: contract.to_dict() 
                for addr, contract in self.contracts.items()
            },
            "code": self.contract_code
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)

    @classmethod
    def load_contracts(cls, filename: str) -> 'ContractManager':
        """Load contracts from a file"""
        manager = cls()
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                
            for addr, contract_data in data["contracts"].items():
                contract = SmartContract(
                    addr,
                    data["code"][addr],
                    contract_data["owner"]
                )
                contract.state.balance = contract_data["state"]["balance"]
                contract.state.storage = contract_data["state"]["storage"]
                manager.contracts[addr] = contract
                manager.contract_code[addr] = data["code"][addr]
        except FileNotFoundError:
            pass
        
        return manager 