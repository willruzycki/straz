use std::collections::HashMap;
use std::fmt;
use crate::vm::compiler::OpCode;
use crate::blockchain::transaction::Transaction; // For context if needed later

const STACK_LIMIT: usize = 1024;
const MEMORY_LIMIT: usize = 1024; // Max number of keys in storage

#[derive(Debug)]
pub enum VmExecutionError {
    StackOverflow,
    StackUnderflow,
    InvalidOpcode(u8),
    IpOutOfBounds,
    UnexpectedEndOfBytecode,
    DivideByZero,
    InvalidStringLength,
    InvalidUtf8String,
    InvalidJumpAddress,
    StoreError(String),
    LoadErrorNotFound(String),
    MemoryLimitExceeded,
}

impl fmt::Display for VmExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmExecutionError::StackOverflow => write!(f, "VM Stack Overflow"),
            VmExecutionError::StackUnderflow => write!(f, "VM Stack Underflow"),
            VmExecutionError::InvalidOpcode(op) => write!(f, "Invalid VM Opcode: 0x{:02X}", op),
            VmExecutionError::IpOutOfBounds => write!(f, "Instruction Pointer out of bounds"),
            VmExecutionError::UnexpectedEndOfBytecode => write!(f, "Unexpected end of bytecode during execution"),
            VmExecutionError::DivideByZero => write!(f, "VM attempted to divide by zero"),
            VmExecutionError::InvalidStringLength => write!(f, "Invalid string length for Load/Store operand"),
            VmExecutionError::InvalidUtf8String => write!(f, "Invalid UTF-8 for Load/Store identifier"),
            VmExecutionError::InvalidJumpAddress => write!(f, "Invalid jump address in bytecode"),
            VmExecutionError::StoreError(s) => write!(f, "Failed to store value: {}", s),
            VmExecutionError::LoadErrorNotFound(s) => write!(f, "Failed to load value: key '{}' not found", s),
            VmExecutionError::MemoryLimitExceeded => write!(f, "VM memory limit exceeded"),
        }
    }
}
impl std::error::Error for VmExecutionError {}

pub struct VirtualMachine {
    pub stack: Vec<i64>,
    pub storage: HashMap<String, i64>, // Contract storage
    ip: usize, // Instruction pointer
    bytecode: Vec<u8>,
}

impl VirtualMachine {
    pub fn new(bytecode: Vec<u8>) -> Self {
        VirtualMachine {
            stack: Vec::with_capacity(STACK_LIMIT),
            storage: HashMap::new(),
            ip: 0,
            bytecode,
        }
    }

    // Allows state/blockchain to inject initial storage or inspect it
    pub fn set_storage(&mut self, storage: HashMap<String, i64>) {
        self.storage = storage;
    }

    pub fn get_storage(&self) -> &HashMap<String, i64> {
        &self.storage
    }
    
    pub fn consume_storage(self) -> HashMap<String, i64> {
        self.storage
    }

    fn push(&mut self, val: i64) -> Result<(), VmExecutionError> {
        if self.stack.len() >= STACK_LIMIT {
            return Err(VmExecutionError::StackOverflow);
        }
        self.stack.push(val);
        Ok(())
    }

    fn pop(&mut self) -> Result<i64, VmExecutionError> {
        self.stack.pop().ok_or(VmExecutionError::StackUnderflow)
    }

    fn read_opcode(&mut self) -> Result<OpCode, VmExecutionError> {
        if self.ip >= self.bytecode.len() {
            return Err(VmExecutionError::IpOutOfBounds);
        }
        let opcode_byte = self.bytecode[self.ip];
        self.ip += 1;
        // Using the same temporary matcher from disassembler.rs context
        // Ideally, OpCode would have a proper from_u8 or FromRepr
        crate::vm::disassembler::temp_opcode_matcher::from_u8(opcode_byte)
            .ok_or(VmExecutionError::InvalidOpcode(opcode_byte))
    }

    fn read_i64(&mut self) -> Result<i64, VmExecutionError> {
        if self.ip + 8 > self.bytecode.len() {
            return Err(VmExecutionError::UnexpectedEndOfBytecode);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.bytecode[self.ip..self.ip + 8]);
        self.ip += 8;
        Ok(i64::from_be_bytes(bytes))
    }

    fn read_string_identifier(&mut self) -> Result<String, VmExecutionError> {
        if self.ip >= self.bytecode.len() {
            return Err(VmExecutionError::UnexpectedEndOfBytecode);
        }
        let len = self.bytecode[self.ip] as usize;
        self.ip += 1;
        if self.ip + len > self.bytecode.len() {
            return Err(VmExecutionError::InvalidStringLength);
        }
        let name_bytes = &self.bytecode[self.ip..self.ip + len];
        self.ip += len;
        String::from_utf8(name_bytes.to_vec()).map_err(|_| VmExecutionError::InvalidUtf8String)
    }
    
    fn read_u32_address(&mut self) -> Result<u32, VmExecutionError> {
        if self.ip + 4 > self.bytecode.len() {
            return Err(VmExecutionError::InvalidJumpAddress);
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.bytecode[self.ip..self.ip+4]);
        self.ip += 4;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn run(&mut self, _tx_context: &Transaction) -> Result<(), VmExecutionError> {
        // In a real scenario, tx_context might provide gas, sender, etc.
        loop {
            if self.ip >= self.bytecode.len() {
                // Allow graceful exit if IP is at end and last op was not STOP, but that might be an error.
                // For now, require explicit STOP.
                return Err(VmExecutionError::IpOutOfBounds);
            }
            let opcode = self.read_opcode()?;

            match opcode {
                OpCode::Stop => return Ok(()),
                OpCode::Push => {
                    let val = self.read_i64()?;
                    self.push(val)?;
                }
                OpCode::Add => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(a.wrapping_add(b))?;
                }
                OpCode::Sub => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(a.wrapping_sub(b))?;
                }
                OpCode::Mul => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(a.wrapping_mul(b))?;
                }
                OpCode::Div => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    if b == 0 { return Err(VmExecutionError::DivideByZero); }
                    self.push(a.wrapping_div(b))?;
                }
                OpCode::Pop => {
                    self.pop()?;
                }
                OpCode::Store => {
                    let val = self.pop()?;
                    let name = self.read_string_identifier()?;
                    if self.storage.len() >= MEMORY_LIMIT && !self.storage.contains_key(&name) {
                        return Err(VmExecutionError::MemoryLimitExceeded);
                    }
                    self.storage.insert(name, val);
                }
                OpCode::Load => {
                    let name = self.read_string_identifier()?;
                    match self.storage.get(&name) {
                        Some(&val) => self.push(val)?,
                        None => return Err(VmExecutionError::LoadErrorNotFound(name)),
                    }
                }
                OpCode::Jump => {
                    let target_ip = self.read_u32_address()? as usize;
                    if target_ip >= self.bytecode.len() && target_ip != self.bytecode.len() { // Allow jump to end for implicit stop
                        return Err(VmExecutionError::IpOutOfBounds);
                    }
                    self.ip = target_ip;
                }
                OpCode::JumpI => { // Jump if top of stack is not zero (true)
                    let target_ip = self.read_u32_address()? as usize;
                    let condition = self.pop()?;
                    if condition != 0 {
                        if target_ip >= self.bytecode.len() && target_ip != self.bytecode.len() {
                            return Err(VmExecutionError::IpOutOfBounds);
                        }
                        self.ip = target_ip;
                    }
                }
                // Placeholder for other ops
                OpCode::Hash | OpCode::Sign | OpCode::Verify | OpCode::Call | OpCode::Ret => {
                    // For now, treat as NOP or error
                    // For Call/Ret, a call stack would be needed.
                    // For Hash/Sign/Verify, interaction with crypto primitives.
                    return Err(VmExecutionError::InvalidOpcode(opcode as u8)); // Or implement them
                }
            }
        }
    }
} 