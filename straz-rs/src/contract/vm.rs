use crate::Result;
use crate::contract::Contract;
use crate::crypto::KeyPair;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OpCode {
    // Stack operations
    Push(Vec<u8>),
    Pop,
    Dup(u8),
    Swap(u8),
    
    // Arithmetic operations
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    
    // Bitwise operations
    And,
    Or,
    Xor,
    Not,
    
    // Comparison operations
    Eq,
    Lt,
    Gt,
    
    // Storage operations
    SLoad,
    SStore,
    
    // Cryptographic operations
    Hash,
    Verify,
    Sign,
    
    // Control flow
    Jump,
    JumpI,
    PC,
    Stop,
    Return,
    Revert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QRVM {
    stack: Vec<Vec<u8>>,
    memory: Vec<u8>,
    storage: HashMap<Vec<u8>, Vec<u8>>,
    pc: usize,
    code: Vec<OpCode>,
    running: bool,
}

impl QRVM {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            memory: Vec::new(),
            storage: HashMap::new(),
            pc: 0,
            code: Vec::new(),
            running: false,
        }
    }
    
    pub fn load_contract(&mut self, contract: &Contract) {
        self.code = self.parse_code(&contract.code);
        self.storage = contract.storage.clone();
        self.pc = 0;
        self.running = true;
    }
    
    pub fn execute(&mut self) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
        while self.running && self.pc < self.code.len() {
            let op = &self.code[self.pc];
            self.execute_op(op)?;
            self.pc += 1;
        }
        
        Ok(self.storage.clone())
    }
    
    fn execute_op(&mut self, op: &OpCode) -> Result<()> {
        match op {
            OpCode::Push(data) => {
                self.stack.push(data.clone());
            }
            OpCode::Pop => {
                self.stack.pop().ok_or_else(|| {
                    crate::StrazError::Contract("Stack underflow".into())
                })?;
            }
            OpCode::Dup(n) => {
                let idx = self.stack.len() - 1 - *n as usize;
                let value = self.stack.get(idx)
                    .ok_or_else(|| {
                        crate::StrazError::Contract("Stack underflow".into())
                    })?
                    .clone();
                self.stack.push(value);
            }
            OpCode::Swap(n) => {
                let idx = self.stack.len() - 1 - *n as usize;
                let len = self.stack.len();
                self.stack.swap(len - 1, idx);
            }
            OpCode::Add => {
                let b = self.pop_u64()?;
                let a = self.pop_u64()?;
                self.push_u64(a + b);
            }
            OpCode::Sub => {
                let b = self.pop_u64()?;
                let a = self.pop_u64()?;
                self.push_u64(a - b);
            }
            OpCode::Mul => {
                let b = self.pop_u64()?;
                let a = self.pop_u64()?;
                self.push_u64(a * b);
            }
            OpCode::Div => {
                let b = self.pop_u64()?;
                let a = self.pop_u64()?;
                if b == 0 {
                    return Err(crate::StrazError::Contract("Division by zero".into()));
                }
                self.push_u64(a / b);
            }
            OpCode::Mod => {
                let b = self.pop_u64()?;
                let a = self.pop_u64()?;
                if b == 0 {
                    return Err(crate::StrazError::Contract("Modulo by zero".into()));
                }
                self.push_u64(a % b);
            }
            OpCode::And => {
                let b = self.pop_u64()?;
                let a = self.pop_u64()?;
                self.push_u64(a & b);
            }
            OpCode::Or => {
                let b = self.pop_u64()?;
                let a = self.pop_u64()?;
                self.push_u64(a | b);
            }
            OpCode::Xor => {
                let b = self.pop_u64()?;
                let a = self.pop_u64()?;
                self.push_u64(a ^ b);
            }
            OpCode::Not => {
                let a = self.pop_u64()?;
                self.push_u64(!a);
            }
            OpCode::Eq => {
                let b = self.pop_bytes()?;
                let a = self.pop_bytes()?;
                self.push_u64((a == b) as u64);
            }
            OpCode::Lt => {
                let b = self.pop_u64()?;
                let a = self.pop_u64()?;
                self.push_u64((a < b) as u64);
            }
            OpCode::Gt => {
                let b = self.pop_u64()?;
                let a = self.pop_u64()?;
                self.push_u64((a > b) as u64);
            }
            OpCode::SLoad => {
                let key = self.pop_bytes()?;
                let value = self.storage.get(&key)
                    .cloned()
                    .unwrap_or_default();
                self.stack.push(value);
            }
            OpCode::SStore => {
                let value = self.pop_bytes()?;
                let key = self.pop_bytes()?;
                self.storage.insert(key, value);
            }
            OpCode::Hash => {
                let data = self.pop_bytes()?;
                let mut hasher = sha3::Sha3_256::new();
                hasher.update(&data);
                self.stack.push(hasher.finalize().to_vec());
            }
            OpCode::Verify => {
                let signature = self.pop_bytes()?;
                let message = self.pop_bytes()?;
                let keypair = KeyPair::new()?;
                self.push_u64(keypair.verify(&message, &signature)? as u64);
            }
            OpCode::Sign => {
                let message = self.pop_bytes()?;
                let keypair = KeyPair::new()?;
                let signature = keypair.sign(&message)?;
                self.stack.push(signature);
            }
            OpCode::Jump => {
                let target = self.pop_u64()? as usize;
                if target >= self.code.len() {
                    return Err(crate::StrazError::Contract("Invalid jump target".into()));
                }
                self.pc = target;
            }
            OpCode::JumpI => {
                let target = self.pop_u64()? as usize;
                let condition = self.pop_u64()?;
                if condition != 0 && target < self.code.len() {
                    self.pc = target;
                }
            }
            OpCode::PC => {
                self.push_u64(self.pc as u64);
            }
            OpCode::Stop => {
                self.running = false;
            }
            OpCode::Return => {
                self.running = false;
            }
            OpCode::Revert => {
                return Err(crate::StrazError::Contract("Contract reverted".into()));
            }
        }
        
        Ok(())
    }
    
    fn parse_code(&self, code: &[u8]) -> Vec<OpCode> {
        // Here we would implement the bytecode parser
        // For now, return empty code
        Vec::new()
    }
    
    fn pop_u64(&mut self) -> Result<u64> {
        let bytes = self.pop_bytes()?;
        if bytes.len() != 8 {
            return Err(crate::StrazError::Contract("Invalid u64".into()));
        }
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }
    
    fn push_u64(&mut self, value: u64) {
        self.stack.push(value.to_le_bytes().to_vec());
    }
    
    fn pop_bytes(&mut self) -> Result<Vec<u8>> {
        self.stack.pop().ok_or_else(|| {
            crate::StrazError::Contract("Stack underflow".into())
        })
    }
} 