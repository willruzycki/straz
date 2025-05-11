use std::collections::HashMap;
use std::fmt;
use crate::vm::parser::{Lexer, Parser, Instr, ParseError};

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum OpCode {
    Add = 0x01,
    Sub = 0x02,
    Mul = 0x03,
    Div = 0x04,
    Push = 0x10, // Expects 8-byte i64 immediate
    Pop = 0x11,
    Load = 0x12, // Placeholder, needs operand (e.g. address or var name)
    Store = 0x13, // Placeholder, needs operand
    Hash = 0x20,  // Placeholder, needs operand (data to hash)
    Sign = 0x21,  // Placeholder
    Verify = 0x22, // Placeholder
    Jump = 0x30,  // Expects 4-byte u32 relative offset or absolute address
    JumpI = 0x31, // Expects 4-byte u32 relative offset or absolute address
    Call = 0x32, // Expects 4-byte u32 relative offset or absolute address
    Ret = 0x33,
    Stop = 0x00,
    // Note: Labels are resolved during compilation and don't have a direct opcode.
}

// AST Node as defined in the prompt, maps closely to `Instr` for this simple compiler
#[derive(Debug, PartialEq, Clone)]
pub enum AstNode {
    Push(i64),
    Op(OpCode),
    Label(String),      // Label definition
    Jump(String),       // Jump to label
    JumpI(String),      // Conditional Jump to label
    Call(String),       // Call label
}

#[derive(Debug)]
pub enum CompileError {
    ParseError(ParseError),
    UndefinedLabel(String),
    LabelRedefinition(String),
    InvalidInstruction(String),
    OperandTooLarge(i64),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompileError::ParseError(pe) => write!(f, "Parser error: {}", pe),
            CompileError::UndefinedLabel(s) => write!(f, "Undefined label: {}", s),
            CompileError::LabelRedefinition(s) => write!(f, "Label redefined: {}", s),
            CompileError::InvalidInstruction(s) => write!(f, "Invalid instruction: {}", s),
            CompileError::OperandTooLarge(val) => write!(f, "Operand {} too large for current representation", val),
        }
    }
}

impl From<ParseError> for CompileError {
    fn from(err: ParseError) -> Self {
        CompileError::ParseError(err)
    }
}

impl std::error::Error for CompileError {}

// Simplified compile function that converts Instr to Vec<u8>
// This version will handle label resolution.
pub fn compile(instructions: &[Instr]) -> Result<Vec<u8>, CompileError> {
    let mut bytecode = Vec::new();
    let mut label_addresses = HashMap::new();
    let mut unresolved_jumps = Vec::new(); // Store (bytecode_index_of_operand, label_name)

    // First pass: identify label addresses and lay out non-jump instructions
    let mut current_address: u32 = 0;

    for instr in instructions {
        match instr {
            Instr::Label(name) => {
                if label_addresses.contains_key(name) {
                    return Err(CompileError::LabelRedefinition(name.clone()));
                }
                label_addresses.insert(name.clone(), current_address);
                // Labels themselves don't produce bytecode in this model
            }
            Instr::Add => { bytecode.push(OpCode::Add as u8); current_address += 1; }
            Instr::Sub => { bytecode.push(OpCode::Sub as u8); current_address += 1; }
            Instr::Mul => { bytecode.push(OpCode::Mul as u8); current_address += 1; }
            Instr::Div => { bytecode.push(OpCode::Div as u8); current_address += 1; }
            Instr::Pop => { bytecode.push(OpCode::Pop as u8); current_address += 1; }
            Instr::Load(name) => {
                bytecode.push(OpCode::Load as u8);
                current_address += 1;
                if name.len() > 255 {
                    return Err(CompileError::InvalidInstruction(format!("Identifier '{}' too long for Load operation", name)));
                }
                let name_bytes = name.as_bytes();
                bytecode.push(name_bytes.len() as u8);
                current_address += 1;
                bytecode.extend_from_slice(name_bytes);
                current_address += name_bytes.len() as u32;
            }
            Instr::Store(name) => {
                bytecode.push(OpCode::Store as u8);
                current_address += 1;
                if name.len() > 255 {
                    return Err(CompileError::InvalidInstruction(format!("Identifier '{}' too long for Store operation", name)));
                }
                let name_bytes = name.as_bytes();
                bytecode.push(name_bytes.len() as u8);
                current_address += 1;
                bytecode.extend_from_slice(name_bytes);
                current_address += name_bytes.len() as u32;
            }
            Instr::Hash => { bytecode.push(OpCode::Hash as u8); current_address += 1; } // Placeholder
            Instr::Sign => { bytecode.push(OpCode::Sign as u8); current_address += 1; } // Placeholder
            Instr::Verify => { bytecode.push(OpCode::Verify as u8); current_address += 1; } // Placeholder
            Instr::Ret => { bytecode.push(OpCode::Ret as u8); current_address += 1; }
            Instr::Stop => { bytecode.push(OpCode::Stop as u8); current_address += 1; }
            Instr::Push(val) => {
                bytecode.push(OpCode::Push as u8);
                bytecode.extend_from_slice(&val.to_be_bytes());
                current_address += 1 + 8; // Opcode + 8 byte literal
            }
            Instr::Jump(label_name) => {
                bytecode.push(OpCode::Jump as u8);
                unresolved_jumps.push((bytecode.len(), label_name.clone(), current_address));
                bytecode.extend_from_slice(&[0u8; 4]); // Placeholder for 4-byte address
                current_address += 1 + 4;
            }
            Instr::JumpI(label_name) => {
                bytecode.push(OpCode::JumpI as u8);
                unresolved_jumps.push((bytecode.len(), label_name.clone(), current_address));
                bytecode.extend_from_slice(&[0u8; 4]); // Placeholder for 4-byte address
                current_address += 1 + 4;
            }
            Instr::Call(label_name) => {
                bytecode.push(OpCode::Call as u8);
                unresolved_jumps.push((bytecode.len(), label_name.clone(), current_address));
                bytecode.extend_from_slice(&[0u8; 4]); // Placeholder for 4-byte address
                current_address += 1 + 4;
            }
        }
    }

    // Second pass: resolve jumps
    for (patch_idx, label_name, _jump_instr_addr) in unresolved_jumps {
        match label_addresses.get(&label_name) {
            Some(&target_address) => {
                let offset_bytes = target_address.to_be_bytes();
                bytecode[patch_idx..patch_idx+4].copy_from_slice(&offset_bytes);
            }
            None => return Err(CompileError::UndefinedLabel(label_name.clone())),
        }
    }

    Ok(bytecode)
}


// The prompt's `compile(ast: &[AstNode])` seems to map more to what we have as `compile(instructions: &[Instr])`
// If AstNode were a different structure (e.g. from a higher-level language), then a separate AstNode->Instr step would be needed.
// For now, we'll assume the prompt's `AstNode` is analogous to our `Instr` for direct compilation.
// The prompt asks for `compile(ast: &[AstNode]) -> Vec<u8>` and `assemble(source: &str) -> Result<Vec<u8>, CompileError>`
// So, `assemble` will do `parser -> Vec<Instr>`, and then we need a function that does `Vec<Instr> -> Vec<u8>`.
// The `compile` function above already does `Vec<Instr> -> Result<Vec<u8>, CompileError>`.

pub fn assemble(source: &str) -> Result<Vec<u8>, CompileError> {
    let lexer = Lexer::new(source);
    let mut parser = Parser::new(lexer);
    let instructions = parser.parse()?; // This returns Result<Vec<Instr>, ParseError>
    compile(&instructions) // This returns Result<Vec<u8>, CompileError>
} 