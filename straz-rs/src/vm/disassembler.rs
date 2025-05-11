use crate::vm::parser::Instr;
use crate::vm::compiler::OpCode;
use std::fmt;

#[derive(Debug)]
pub enum DisassemblyError {
    UnknownOpCode(u8),
    UnexpectedEndOfBytecode,
    InvalidStringLength,
    InvalidUtf8String,
    InvalidJumpAddress,
}

impl fmt::Display for DisassemblyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DisassemblyError::UnknownOpCode(op) => write!(f, "Unknown opcode: 0x{:02X}", op),
            DisassemblyError::UnexpectedEndOfBytecode => write!(f, "Unexpected end of bytecode"),
            DisassemblyError::InvalidStringLength => write!(f, "Invalid string length in bytecode for Load/Store"),
            DisassemblyError::InvalidUtf8String => write!(f, "Invalid UTF-8 string in bytecode for Load/Store identifier"),
            DisassemblyError::InvalidJumpAddress => write!(f, "Invalid jump address encoding (expected 4 bytes)"),
        }
    }
}
impl std::error::Error for DisassemblyError {}

pub fn disassemble(bytecode: &[u8]) -> Result<Vec<Instr>, DisassemblyError> {
    let mut instructions = Vec::new();
    let mut ip = 0; // instruction pointer

    while ip < bytecode.len() {
        let opcode_byte = bytecode[ip];
        ip += 1;

        match OpCode::from_repr(opcode_byte) { 
            Some(OpCode::Add) => instructions.push(Instr::Add),
            Some(OpCode::Sub) => instructions.push(Instr::Sub),
            Some(OpCode::Mul) => instructions.push(Instr::Mul),
            Some(OpCode::Div) => instructions.push(Instr::Div),
            Some(OpCode::Pop) => instructions.push(Instr::Pop),
            Some(OpCode::Hash) => instructions.push(Instr::Hash),
            Some(OpCode::Sign) => instructions.push(Instr::Sign),
            Some(OpCode::Verify) => instructions.push(Instr::Verify),
            Some(OpCode::Ret) => instructions.push(Instr::Ret),
            Some(OpCode::Stop) => instructions.push(Instr::Stop),
            Some(OpCode::GetBlockNumber) => instructions.push(Instr::GetBlockNumber),
            Some(OpCode::GetSender) => instructions.push(Instr::GetSender),
            Some(OpCode::Push) => {
                if ip + 8 > bytecode.len() {
                    return Err(DisassemblyError::UnexpectedEndOfBytecode);
                }
                let mut val_bytes = [0u8; 8];
                val_bytes.copy_from_slice(&bytecode[ip..ip + 8]);
                instructions.push(Instr::Push(i64::from_be_bytes(val_bytes)));
                ip += 8;
            }
            Some(OpCode::Load) => {
                if ip >= bytecode.len() { return Err(DisassemblyError::UnexpectedEndOfBytecode); }
                let len = bytecode[ip] as usize;
                ip += 1;
                if ip + len > bytecode.len() { return Err(DisassemblyError::InvalidStringLength); }
                let name_bytes = &bytecode[ip..ip+len];
                let name = String::from_utf8(name_bytes.to_vec()).map_err(|_| DisassemblyError::InvalidUtf8String)?;
                instructions.push(Instr::Load(name));
                ip += len;
            }
            Some(OpCode::Store) => {
                if ip >= bytecode.len() { return Err(DisassemblyError::UnexpectedEndOfBytecode); }
                let len = bytecode[ip] as usize;
                ip += 1;
                if ip + len > bytecode.len() { return Err(DisassemblyError::InvalidStringLength); }
                let name_bytes = &bytecode[ip..ip+len];
                let name = String::from_utf8(name_bytes.to_vec()).map_err(|_| DisassemblyError::InvalidUtf8String)?;
                instructions.push(Instr::Store(name));
                ip += len;
            }
            Some(OpCode::Jump) | Some(OpCode::JumpI) | Some(OpCode::Call) => {
                if ip + 4 > bytecode.len() {
                    return Err(DisassemblyError::InvalidJumpAddress);
                }
                let mut addr_bytes = [0u8; 4];
                addr_bytes.copy_from_slice(&bytecode[ip..ip + 4]);
                let target_addr = u32::from_be_bytes(addr_bytes);
                let label = format!("ADDR_{}", target_addr); 
                match OpCode::from_repr(opcode_byte).unwrap() { // Safe due to outer match
                    OpCode::Jump => instructions.push(Instr::Jump(label)),
                    OpCode::JumpI => instructions.push(Instr::JumpI(label)),
                    OpCode::Call => instructions.push(Instr::Call(label)),
                    _ => unreachable!(), 
                }
                ip += 4;
            }
            None => return Err(DisassemblyError::UnknownOpCode(opcode_byte)),
        }
    }
    Ok(instructions)
}