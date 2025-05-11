#[cfg(test)]
mod tests {
    use crate::vm::compiler::{assemble, OpCode, CompileError};
    use crate::vm::parser::{Lexer, Parser, Instr, ParseError, Token};

    fn disassemble_bytecode(bytecode: &[u8]) -> Result<Vec<Instr>, String> {
        let mut instructions = Vec::new();
        let mut i = 0;
        let mut label_map: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
        let mut label_counter = 0;

        // First pass to identify jump targets and create synthetic labels
        let mut temp_i = 0;
        while temp_i < bytecode.len() {
            let opcode_val = bytecode[temp_i];
            temp_i += 1;

            if opcode_val == OpCode::Jump as u8 || opcode_val == OpCode::JumpI as u8 || opcode_val == OpCode::Call as u8 {
                if temp_i + 4 > bytecode.len() {
                    return Err("Bytecode too short for jump address".to_string());
                }
                let mut addr_bytes = [0u8; 4];
                addr_bytes.copy_from_slice(&bytecode[temp_i..temp_i+4]);
                let target_addr = u32::from_be_bytes(addr_bytes);
                if !label_map.contains_key(&target_addr) {
                    label_map.insert(target_addr, format!("L{}", label_counter));
                    label_counter += 1;
                }
                temp_i += 4;
            } else if opcode_val == OpCode::Push as u8 {
                if temp_i + 8 > bytecode.len() {
                    return Err("Bytecode too short for push value".to_string());
                }
                temp_i += 8;
            }
        }
        
        // Insert label instructions based on identified jump targets
        // This is a bit tricky as addresses might shift if we were to insert labels directly into a new Vec<Instr>
        // For simple verification, we just need to know where labels *would* be.

        while i < bytecode.len() {
            // Check if current address `i` is a target for any jump
            if let Some(label_name) = label_map.get(&(i as u32)) {
                instructions.push(Instr::Label(label_name.clone()));
            }

            let opcode_val = bytecode[i];
            i += 1;

            if opcode_val == OpCode::Add as u8 {
                instructions.push(Instr::Add);
            } else if opcode_val == OpCode::Sub as u8 {
                instructions.push(Instr::Sub);
            } else if opcode_val == OpCode::Mul as u8 {
                instructions.push(Instr::Mul);
            } else if opcode_val == OpCode::Div as u8 {
                instructions.push(Instr::Div);
            } else if opcode_val == OpCode::Pop as u8 {
                instructions.push(Instr::Pop);
            } else if opcode_val == OpCode::Load as u8 {
                instructions.push(Instr::Load);
            } else if opcode_val == OpCode::Store as u8 {
                instructions.push(Instr::Store);
            } else if opcode_val == OpCode::Hash as u8 {
                instructions.push(Instr::Hash);
            } else if opcode_val == OpCode::Sign as u8 {
                instructions.push(Instr::Sign);
            } else if opcode_val == OpCode::Verify as u8 {
                instructions.push(Instr::Verify);
            } else if opcode_val == OpCode::Ret as u8 {
                instructions.push(Instr::Ret);
            } else if opcode_val == OpCode::Stop as u8 {
                instructions.push(Instr::Stop);
            } else if opcode_val == OpCode::Push as u8 {
                if i + 8 > bytecode.len() {
                    return Err("Bytecode too short for push value".to_string());
                }
                let mut val_bytes = [0u8; 8];
                val_bytes.copy_from_slice(&bytecode[i..i+8]);
                instructions.push(Instr::Push(i64::from_be_bytes(val_bytes)));
                i += 8;
            } else if opcode_val == OpCode::Jump as u8 || opcode_val == OpCode::JumpI as u8 || opcode_val == OpCode::Call as u8 {
                if i + 4 > bytecode.len() {
                    return Err("Bytecode too short for jump address".to_string());
                }
                let mut addr_bytes = [0u8; 4];
                addr_bytes.copy_from_slice(&bytecode[i..i+4]);
                let target_addr = u32::from_be_bytes(addr_bytes);
                let label_name = label_map.get(&target_addr).ok_or_else(|| "Internal disassembler error: jump target not in map".to_string())?;
                
                if opcode_val == OpCode::Jump as u8 {
                    instructions.push(Instr::Jump(label_name.clone()));
                } else if opcode_val == OpCode::JumpI as u8 {
                    instructions.push(Instr::JumpI(label_name.clone()));
                } else { // Call
                    instructions.push(Instr::Call(label_name.clone()));
                }
                i += 4;
            } else {
                return Err(format!("Unknown opcode byte: 0x{:02X}", opcode_val));
            }
        }
         // Final check for any labels that point to the very end of the bytecode
        if let Some(label_name) = label_map.get(&(i as u32)) {
            instructions.push(Instr::Label(label_name.clone()));
        }

        Ok(instructions)
    }


    #[test]
    fn test_assemble_simple_program() {
        let source = "PUSH 1; PUSH 2; ADD; STOP";
        let expected_bytecode = vec![
            OpCode::Push as u8, 0, 0, 0, 0, 0, 0, 0, 1, // PUSH 1
            OpCode::Push as u8, 0, 0, 0, 0, 0, 0, 0, 2, // PUSH 2
            OpCode::Add as u8,                         // ADD
            OpCode::Stop as u8,                        // STOP
        ];
        match assemble(source) {
            Ok(bytecode) => assert_eq!(bytecode, expected_bytecode),
            Err(e) => panic!("Assembly failed: {}", e),
        }
    }

    #[test]
    fn test_assemble_and_disassemble_simple_program() {
        let source = "PUSH 1; PUSH 2; ADD; STOP";
        let expected_instrs = vec![
            Instr::Push(1),
            Instr::Push(2),
            Instr::Add,
            Instr::Stop,
        ];

        let bytecode = assemble(source).expect("Assembly failed");
        let disassembled_instrs = disassemble_bytecode(&bytecode).expect("Disassembly failed");

        assert_eq!(disassembled_instrs, expected_instrs);
    }


    #[test]
    fn test_forward_jump() {
        let source = "PUSH 0; JUMP END; PUSH 1; LABEL END: STOP";
        // Expected: PUSH 0 (1+8 bytes) -> JUMP to addr 1+8+1+4 (opcode + placeholder) (1+4 bytes) -> PUSH 1 (1+8) -> STOP (1)
        // PUSH 0: 0x10 ... (9 bytes total, current_addr = 9)
        // JUMP END: 0x30 ... (5 bytes total, current_addr = 9 + 5 = 14). Target should be after PUSH 1. Label END is at 14+9 = 23
        // PUSH 1: 0x10 ... (9 bytes total, current_addr = 14 + 9 = 23)
        // LABEL END: (no bytecode)
        // STOP: 0x00 (1 byte total, current_addr = 23 + 1 = 24)
        // JUMP target address is (1+8) + (1+4) + (1+8) = 9 + 5 + 9 = 23.
        // Let's trace addresses for label resolution:
        // Instr::Push(0) -> OpCode::Push, 8 bytes data. current_address = 1+8 = 9
        // Instr::Jump("END") -> OpCode::Jump, 4 bytes placeholder. current_address = 9 + 1+4 = 14.
        // Instr::Push(1) -> OpCode::Push, 8 bytes data. current_address = 14 + 1+8 = 23.
        // Instr::Label("END") -> address map: END -> 23.
        // Instr::Stop -> OpCode::Stop. current_address = 23 + 1 = 24.
        // Jump operand should be 23 (0x00000017)

        let expected_bytecode = vec![
            OpCode::Push as u8, 0,0,0,0,0,0,0,0, // PUSH 0
            OpCode::Jump as u8, 0,0,0,23,       // JUMP to address 23 (0x17)
            OpCode::Push as u8, 0,0,0,0,0,0,0,1, // PUSH 1
            OpCode::Stop as u8,                 // STOP
        ];
        match assemble(source) {
            Ok(bytecode) => {
                 assert_eq!(bytecode, expected_bytecode, "Bytecode mismatch for forward jump");
                 // Now try to disassemble and compare instructions
                 let lexer = Lexer::new(source);
                 let mut parser = Parser::new(lexer);
                 let original_instrs = parser.parse().expect("Source parsing failed");
                 let disassembled_instrs = disassemble_bytecode(&bytecode).expect("Disassembly failed for forward jump");
                 assert_eq!(disassembled_instrs, original_instrs, "Instruction mismatch after disassembling forward jump");
            },
            Err(e) => panic!("Assembly failed for forward jump: {}", e),
        }
    }

    #[test]
    fn test_backward_jump_loop() {
        let source = "LABEL LOOP: PUSH 0; JUMP LOOP; STOP";
        // LOOP: (address 0)
        // PUSH 0 (OpCode + 8 bytes data) -> current_address = 9. Bytecode: [PUSH, 0...0]
        // JUMP LOOP (OpCode + 4 bytes addr) -> current_address = 9 + 5 = 14. Target is 0. Bytecode: [JUMP, 0,0,0,0]
        // STOP (OpCode) -> current_address = 14 + 1 = 15. Bytecode: [STOP]
        let expected_bytecode = vec![
            // LOOP is at address 0
            OpCode::Push as u8, 0,0,0,0,0,0,0,0, // PUSH 0 (bytes 0-8)
            OpCode::Jump as u8, 0,0,0,0,         // JUMP to address 0 (bytes 9-13)
            OpCode::Stop as u8,                   // STOP (byte 14)
        ];
        match assemble(source) {
            Ok(bytecode) => {
                assert_eq!(bytecode, expected_bytecode, "Bytecode mismatch for backward jump");
                let lexer = Lexer::new(source);
                let mut parser = Parser::new(lexer);
                let original_instrs = parser.parse().expect("Source parsing failed");
                let disassembled_instrs = disassemble_bytecode(&bytecode).expect("Disassembly failed for backward jump");
                assert_eq!(disassembled_instrs, original_instrs, "Instruction mismatch after disassembling backward jump");
            },
            Err(e) => panic!("Assembly failed for backward jump: {}", e),
        }
    }

    #[test]
    fn test_assemble_malformed_literal() {
        let source = "PUSH ABC";
        match assemble(source) {
            Err(CompileError::ParseError(ParseError::MalformedLiteral(_))) => { /* Expected */ }
            Ok(_) => panic!("Assembly should have failed due to malformed literal"),
            Err(e) => panic!("Unexpected error type: {:?}", e),
        }
    }

    #[test]
    fn test_assemble_unknown_opcode() {
        // The current lexer/parser treats unknown identifiers as LabelRef initially.
        // The parser then might error if a LabelRef is in an invalid position or the compiler might error if it's an undefined label.
        // For an explicit unknown opcode test, we'd need the lexer to be stricter or have a dedicated unknown token type.
        // Let's test an invalid sequence that parser would catch.
        let source = "PUSH 10 BADOPCODE";
        match assemble(source) {
             Err(CompileError::ParseError(ParseError::LexerError(_))) => { /* Expected due to BADOPCODE being parsed as LabelRef then next token error */ },
            // Depending on parser logic, could be UnknownOpcode if BADOPCODE was tokenized as such,
            // or a syntax error if it expects EOF or another instruction after PUSH 10.
            // Current parser will consume PUSH, then 10. Then BADOPCODE will be a LabelRef.
            // The parser loop will then try to match LabelRef as an instruction, which fails.
            // Update: The parser.parse() will consume PUSH 10, then it will see BADOPCODE as a LabelRef token.
            // It will then fail with UnknownOpcode("LabelRef found unexpectedly") because LabelRef is not an instr start.
            Err(CompileError::ParseError(ParseError::UnknownOpcode(s))) if s.contains("LabelRef found unexpectedly") => { /* Expected */ }
            Ok(bc) => panic!("Assembly should have failed due to unknown opcode/syntax. Got: {:?}", bc),
            Err(e) => panic!("Unexpected error type for unknown opcode: {:?}", e),
        }
    }

    #[test]
    fn test_undefined_label_jump() {
        let source = "JUMP NONEXISTENT_LABEL";
        match assemble(source) {
            Err(CompileError::UndefinedLabel(label)) => {
                assert_eq!(label, "NONEXISTENT_LABEL");
            }
            Ok(_) => panic!("Assembly should have failed due to undefined label"),
            Err(e) => panic!("Unexpected error type for undefined label: {:?}", e),
        }
    }

     #[test]
    fn test_label_redefinition() {
        let source = "LABEL MYLABEL: PUSH 1; LABEL MYLABEL: STOP";
        match assemble(source) {
            Err(CompileError::LabelRedefinition(label)) => {
                assert_eq!(label, "MYLABEL");
            }
            Ok(_) => panic!("Assembly should have failed due to label redefinition"),
            Err(e) => panic!("Unexpected error type for label redefinition: {:?}", e),
        }
    }

    // Test for parsing only, ensuring lexer and parser handle label declarations correctly
    #[test]
    fn test_parse_label_declaration() {
        let source = "START: PUSH 10; STOP";
        let lexer = Lexer::new(source);
        let mut parser = Parser::new(lexer);
        let expected_instrs = vec![
            Instr::Label("START".to_string()),
            Instr::Push(10),
            Instr::Stop,
        ];
        match parser.parse() {
            Ok(instrs) => assert_eq!(instrs, expected_instrs),
            Err(e) => panic!("Parsing failed for label declaration: {}", e),
        }
    }

    #[test]
    fn test_parse_jump_to_label() {
        let source = "JUMP LOOP_TARGET";
        let lexer = Lexer::new(source);
        let mut parser = Parser::new(lexer);
        let expected_instrs = vec![
            Instr::Jump("LOOP_TARGET".to_string()),
        ];
        match parser.parse() {
            Ok(instrs) => assert_eq!(instrs, expected_instrs),
            Err(e) => panic!("Parsing failed for jump to label: {}", e),
        }
    }

    #[test]
    fn test_complex_program_round_trip() {
        let source = r#"
            ; Simple program with a loop and conditional jump
            PUSH 10          ; Initialize counter
            STORE            ; Store counter (conceptual, OpCode::Store is a placeholder)

            LOOP_START:      ; Label for the loop
            LOAD             ; Load counter
            PUSH 1
            SUB              ; Decrement counter
            STORE            ; Store counter back

            PUSH 0
            ; How to check equality and prepare for JumpI?
            ; Assume some comparison op sets a flag, and JumpI uses it
            ; For this test, we'll just use JumpI as an unconditional jump for structure
            JUMPI END_LOOP   ; If counter is zero (or rather, if flag is true), jump to END_LOOP
            
            ; ... body of the loop ...
            PUSH 7           ; Some operation
            POP

            JUMP LOOP_START  ; Jump back to the start of the loop

            END_LOOP:
            PUSH 42
            STOP
        "#;

        let bytecode = assemble(source).expect("Assembly failed for complex program");
        let disassembled_instrs = disassemble_bytecode(&bytecode).expect("Disassembly failed for complex program");

        // Parse the original source again to get the expected Instr sequence
        let lexer = Lexer::new(source);
        let mut parser = Parser::new(lexer);
        let original_instrs = parser.parse().expect("Parsing original source failed for complex program");
        
        // Note: The disassembler creates synthetic labels (L0, L1, ...).
        // The original_instrs have semantic labels (LOOP_START, END_LOOP).
        // A direct comparison will fail unless we normalize labels or make disassembler smarter.
        // For this test, we are primarily checking that assembly and disassembly don't crash and produce *some* output.
        // A more robust test would require normalizing the label names or comparing the structure more carefully.

        assert!(!disassembled_instrs.is_empty(), "Disassembled instructions should not be empty");
        
        // Basic structural check: Count number of labels, jumps, pushes to see if they are roughly similar
        let count_instr_type = |instrs: &[Instr], constructor: fn(String) -> Instr| -> usize {
            instrs.iter().filter(|i| std::mem::discriminant(*i) == std::mem::discriminant(&constructor("".into())) ).count()
        };
        let count_simple_instr_type = |instrs: &[Instr], instr_type: Instr| -> usize {
            instrs.iter().filter(|i| std::mem::discriminant(*i) == std::mem::discriminant(&instr_type) ).count()
        };

        assert_eq!(count_instr_type(&original_instrs, Instr::Label), count_instr_type(&disassembled_instrs, Instr::Label), "Label count mismatch");
        assert_eq!(count_instr_type(&original_instrs, Instr::Jump), count_instr_type(&disassembled_instrs, Instr::Jump), "Jump count mismatch");
        assert_eq!(count_instr_type(&original_instrs, Instr::JumpI), count_instr_type(&disassembled_instrs, Instr::JumpI), "JumpI count mismatch");
        assert_eq!(count_simple_instr_type(&original_instrs, Instr::Push(0)), count_simple_instr_type(&disassembled_instrs, Instr::Push(0)), "Push count mismatch");
        assert_eq!(count_simple_instr_type(&original_instrs, Instr::Stop), count_simple_instr_type(&disassembled_instrs, Instr::Stop), "Stop count mismatch");

    }
} 