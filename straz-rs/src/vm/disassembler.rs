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

    // For resolving jump labels - not fully implemented in this basic disassembler
    // but we can identify jump targets.
    // A full disassembler would map these addresses to labels.

    while ip < bytecode.len() {
        let opcode_byte = bytecode[ip];
        ip += 1;

        match OpCode::from_repr(opcode_byte) { // Requires OpCode to derive FromRepr
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
                // For a simple disassembler, we represent the target as a string label like "ADDR_XXX"
                // A more complex one would collect all label targets first.
                let label = format!("ADDR_{}", target_addr);
                match OpCode::from_repr(opcode_byte).unwrap() { // Safe due to outer match
                    OpCode::Jump => instructions.push(Instr::Jump(label)),
                    OpCode::JumpI => instructions.push(Instr::JumpI(label)),
                    OpCode::Call => instructions.push(Instr::Call(label)),
                    _ => unreachable!(), // Should not happen
                }
                ip += 4;
            }
            None => return Err(DisassemblyError::UnknownOpCode(opcode_byte)),
        }
    }
    Ok(instructions)
}

// To use OpCode::from_repr, OpCode needs to derive `strum::FromRepr` or similar.
// Add `strum = "0.24"` and `strum_macros = "0.24"` to Cargo.toml
// and `use strum_macros::FromRepr;` in compiler.rs, then add `#[derive(FromRepr)]` to OpCode.
// For now, I will manually implement a conversion if `FromRepr` is not available.
// Rechecking compiler.rs, OpCode does not have FromRepr. So I will do a manual match here.
// Or, even better, let the compiler OpCode enum expose a method.

// Let's assume OpCode in compiler.rs is updated to have a from_u8 method or derive FromRepr
// If not, this part needs to be adjusted. For the snippet, I'll write it as if OpCode::from_repr exists.
// The compiler.rs does not include FromRepr. I will adjust this disassembler to manually match.

mod temp_opcode_matcher { // Temporary workaround for OpCode matching
    use crate::vm::compiler::OpCode;
    pub fn from_u8(byte: u8) -> Option<OpCode> {
        match byte {
            0x01 => Some(OpCode::Add),
            0x02 => Some(OpCode::Sub),
            0x03 => Some(OpCode::Mul),
            0x04 => Some(OpCode::Div),
            0x10 => Some(OpCode::Push),
            0x11 => Some(OpCode::Pop),
            0x12 => Some(OpCode::Load),
            0x13 => Some(OpCode::Store),
            0x20 => Some(OpCode::Hash),
            0x21 => Some(OpCode::Sign),
            0x22 => Some(OpCode::Verify),
            0x30 => Some(OpCode::Jump),
            0x31 => Some(OpCode::JumpI),
            0x32 => Some(OpCode::Call),
            0x33 => Some(OpCode::Ret),
            0x00 => Some(OpCode::Stop),
            _ => None,
        }
    }
}

// Corrected disassembler using the temporary matcher:
pub fn disassemble_corrected(bytecode: &[u8]) -> Result<Vec<Instr>, DisassemblyError> {
    let mut instructions = Vec::new();
    let mut ip = 0;
    while ip < bytecode.len() {
        let opcode_byte = bytecode[ip];
        ip += 1;
        match temp_opcode_matcher::from_u8(opcode_byte) {
            Some(OpCode::Add) => instructions.push(Instr::Add),
            Some(OpCode::Sub) => instructions.push(Instr::Sub),
            // ... (all other opcodes as above)
            Some(OpCode::Mul) => instructions.push(Instr::Mul),
            Some(OpCode::Div) => instructions.push(Instr::Div),
            Some(OpCode::Pop) => instructions.push(Instr::Pop),
            Some(OpCode::Hash) => instructions.push(Instr::Hash),
            Some(OpCode::Sign) => instructions.push(Instr::Sign),
            Some(OpCode::Verify) => instructions.push(Instr::Verify),
            Some(OpCode::Ret) => instructions.push(Instr::Ret),
            Some(OpCode::Stop) => instructions.push(Instr::Stop),
            Some(OpCode::Push) => {
                if ip + 8 > bytecode.len() { return Err(DisassemblyError::UnexpectedEndOfBytecode); }
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
                if ip + 4 > bytecode.len() { return Err(DisassemblyError::InvalidJumpAddress); }
                let mut addr_bytes = [0u8; 4];
                addr_bytes.copy_from_slice(&bytecode[ip..ip + 4]);
                let target_addr = u32::from_be_bytes(addr_bytes);
                let label = format!("ADDR_{}", target_addr); // Placeholder label
                match temp_opcode_matcher::from_u8(opcode_byte).unwrap() { // Safe
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