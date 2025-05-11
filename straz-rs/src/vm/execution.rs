use std::collections::HashMap;
use std::fmt;
use crate::vm::compiler::OpCode;
use crate::blockchain::transaction::Transaction; // For context if needed later
use crate::crypto::hash_data; // For GetSender hashing

const STACK_LIMIT: usize = 1024;
const MEMORY_LIMIT: usize = 1024; // Max number of keys in storage
const CALL_STACK_LIMIT: usize = 256;

// Gas costs (example values)
fn get_opcode_gas_cost(opcode: OpCode) -> u64 {
    match opcode {
        OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::Div | OpCode::Pop => 1,
        OpCode::Push => 1,
        OpCode::Load | OpCode::Store => 5, 
        OpCode::Jump | OpCode::JumpI => 3,
        OpCode::Call | OpCode::Ret => 10,
        OpCode::GetBlockNumber | OpCode::GetSender => 3,
        OpCode::Stop => 0, // Stop usually costs 0 or very little
        OpCode::Hash | OpCode::Sign | OpCode::Verify => 20, // Placeholder for more expensive ops
    }
}

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
    OutOfGas,             // New
    CallStackOverflow,    // New
    CallStackUnderflow,   // New
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
            VmExecutionError::OutOfGas => write!(f, "VM Out of Gas"),
            VmExecutionError::CallStackOverflow => write!(f, "VM Call Stack Overflow"),
            VmExecutionError::CallStackUnderflow => write!(f, "VM Call Stack Underflow"),
        }
    }
}
impl std::error::Error for VmExecutionError {}

pub struct VirtualMachine {
    pub stack: Vec<i64>,
    pub storage: HashMap<String, i64>, // Contract storage
    ip: usize, // Instruction pointer
    bytecode: Vec<u8>,
    call_stack: Vec<usize>, // New: For CALL/RET return addresses
}

impl VirtualMachine {
    pub fn new(bytecode: Vec<u8>) -> Self {
        VirtualMachine {
            stack: Vec::with_capacity(STACK_LIMIT),
            storage: HashMap::new(),
            ip: 0,
            bytecode,
            call_stack: Vec::with_capacity(CALL_STACK_LIMIT),
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

    fn push_val_stack(&mut self, val: i64) -> Result<(), VmExecutionError> {
        if self.stack.len() >= STACK_LIMIT {
            return Err(VmExecutionError::StackOverflow);
        }
        self.stack.push(val);
        Ok(())
    }

    fn pop_val_stack(&mut self) -> Result<i64, VmExecutionError> {
        self.stack.pop().ok_or(VmExecutionError::StackUnderflow)
    }

    fn push_call_stack(&mut self, addr: usize) -> Result<(), VmExecutionError> {
        if self.call_stack.len() >= CALL_STACK_LIMIT {
            return Err(VmExecutionError::CallStackOverflow);
        }
        self.call_stack.push(addr);
        Ok(())
    }

    fn pop_call_stack(&mut self) -> Result<usize, VmExecutionError> {
        self.call_stack.pop().ok_or(VmExecutionError::CallStackUnderflow)
    }

    fn read_opcode_from_bytecode(&mut self) -> Result<OpCode, VmExecutionError> { 
        if self.ip >= self.bytecode.len() {
            return Err(VmExecutionError::IpOutOfBounds); 
        }
        let opcode_byte = self.bytecode[self.ip];
        // Try to convert to OpCode first
        match OpCode::from_repr(opcode_byte) {
            Some(opcode) => {
                self.ip += 1; // Consume the valid opcode byte
                Ok(opcode)
            }
            None => {
                self.ip += 1; // Consume the invalid opcode byte before erroring
                Err(VmExecutionError::InvalidOpcode(opcode_byte))
            }
        }
    }

    fn consume_gas(&mut self, amount: u64, gas_remaining: &mut u64) -> Result<(), VmExecutionError> {
        if *gas_remaining < amount {
            *gas_remaining = 0;
            Err(VmExecutionError::OutOfGas)
        } else {
            *gas_remaining -= amount;
            Ok(())
        }
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

    pub fn run(
        &mut self, 
        gas_limit: u64, 
        block_number: u64, 
        sender_pk_bytes: &[u8] // Typically full PublicKey bytes
    ) -> Result<u64, VmExecutionError> { // Returns gas_used
        
        let mut gas_remaining = gas_limit;
        let initial_gas = gas_limit;
        self.ip = 0; // Reset IP for each run
        self.stack.clear(); // Clear stack for each run
        self.call_stack.clear(); // Clear call stack for each run
        // Storage is NOT cleared here, it's managed by `set_storage` and `consume_storage`

        loop {
            if self.ip >= self.bytecode.len() {
                // If execution reaches here, it means bytecode ended without an explicit STOP.
                // This could be an error or an implicit stop. For now, error.
                return Err(VmExecutionError::IpOutOfBounds); 
            }

            // Peek at opcode to determine gas cost, then read/consume it.
            // This is slightly inefficient but ensures gas is charged before IP moves for the opcode itself.
            if self.ip >= self.bytecode.len() { return Err(VmExecutionError::IpOutOfBounds); } // Should be caught by loop condition
            let opcode_byte_for_gas = self.bytecode[self.ip];
            let opcode_for_gas = OpCode::from_repr(opcode_byte_for_gas).ok_or(VmExecutionError::InvalidOpcode(opcode_byte_for_gas))?;
            self.consume_gas(get_opcode_gas_cost(opcode_for_gas), &mut gas_remaining)?;
            
            // Now read and advance IP for the opcode
            // read_opcode_from_bytecode itself advances self.ip for the opcode byte
            let opcode = self.read_opcode_from_bytecode()?;
            // DO NOT increment self.ip here again for the opcode byte itself.

            match opcode {
                OpCode::Stop => return Ok(initial_gas - gas_remaining),
                OpCode::Push => {
                    // Gas for operand reading is implicitly part of PUSH cost or could be separate
                    let val = self.read_i64()?;
                    self.push_val_stack(val)?;
                }
                OpCode::Add => {
                    let b = self.pop_val_stack()?;
                    let a = self.pop_val_stack()?;
                    self.push_val_stack(a.wrapping_add(b))?;
                }
                OpCode::Sub => {
                    let b = self.pop_val_stack()?;
                    let a = self.pop_val_stack()?;
                    self.push_val_stack(a.wrapping_sub(b))?;
                }
                OpCode::Mul => {
                    let b = self.pop_val_stack()?;
                    let a = self.pop_val_stack()?;
                    self.push_val_stack(a.wrapping_mul(b))?;
                }
                OpCode::Div => {
                    let b = self.pop_val_stack()?;
                    let a = self.pop_val_stack()?;
                    if b == 0 { return Err(VmExecutionError::DivideByZero); }
                    self.push_val_stack(a.wrapping_div(b))?;
                }
                OpCode::Pop => {
                    self.pop_val_stack()?;
                }
                OpCode::Store => {
                    let val = self.pop_val_stack()?;
                    let name = self.read_string_identifier()?;
                    if self.storage.len() >= MEMORY_LIMIT && !self.storage.contains_key(&name) {
                        return Err(VmExecutionError::MemoryLimitExceeded);
                    }
                    self.storage.insert(name, val);
                }
                OpCode::Load => {
                    let name = self.read_string_identifier()?;
                    match self.storage.get(&name) {
                        Some(&val) => self.push_val_stack(val)?,
                        None => return Err(VmExecutionError::LoadErrorNotFound(name)),
                    }
                }
                OpCode::Jump => {
                    let target_ip = self.read_u32_address()? as usize;
                    if target_ip > self.bytecode.len() { 
                        return Err(VmExecutionError::IpOutOfBounds);
                    }
                    self.ip = target_ip;
                }
                OpCode::JumpI => { 
                    let target_ip = self.read_u32_address()? as usize;
                    let condition = self.pop_val_stack()?;
                    if condition != 0 {
                        if target_ip > self.bytecode.len() {
                            return Err(VmExecutionError::IpOutOfBounds);
                        }
                        self.ip = target_ip;
                    }
                }
                OpCode::Call => {
                    let target_ip = self.read_u32_address()? as usize;
                    if target_ip > self.bytecode.len() {
                        return Err(VmExecutionError::IpOutOfBounds);
                    }
                    self.push_call_stack(self.ip)?;
                    self.ip = target_ip;
                }
                OpCode::Ret => {
                    let return_addr = self.pop_call_stack()?;
                     if return_addr > self.bytecode.len() { 
                        return Err(VmExecutionError::IpOutOfBounds);
                    }
                    self.ip = return_addr;
                }
                OpCode::GetBlockNumber => {
                    self.push_val_stack(block_number as i64)?;
                }
                OpCode::GetSender => {
                    let hash_result = hash_data(sender_pk_bytes);
                    let mut sender_val_bytes = [0u8; 8];
                    sender_val_bytes.copy_from_slice(&hash_result.0[0..8]);
                    self.push_val_stack(i64::from_be_bytes(sender_val_bytes))?;
                }
                OpCode::Hash | OpCode::Sign | OpCode::Verify => {
                    return Err(VmExecutionError::InvalidOpcode(opcode as u8)); 
                }
            }
        }
    }
} 