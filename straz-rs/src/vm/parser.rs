use std::fmt;

#[derive(Debug, PartialEq, Clone)]
pub enum Token {
    // Opcodes
    Add,
    Sub,
    Mul,
    Div, // Added Div for completeness, can be removed if not in VM spec
    Push,
    Pop, // Added Pop for completeness
    LoadIdent, // New: LOAD <identifier>
    StoreIdent, // New: STORE <identifier>
    Hash,
    Sign,
    Verify,
    Jump,
    JumpI, // Jump if true (conditional)
    Call,  // New: CALL <label>
    Ret,   // New: RET
    Stop,
    GetBlockNumber, // New
    GetSender,      // New
    LabelDecl(String), // Declaration of a label e.g. LOOP:
    // Operands
    Literal(i64),
    LabelRef(String), // Reference to a label e.g. JUMP LOOP or for LOAD/STORE
    Identifier(String), // For LOAD/STORE operands specifically if different from LabelRef
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Token::Add => write!(f, "ADD"),
            Token::Sub => write!(f, "SUB"),
            Token::Mul => write!(f, "MUL"),
            Token::Div => write!(f, "DIV"),
            Token::Push => write!(f, "PUSH"),
            Token::Pop => write!(f, "POP"),
            Token::LoadIdent => write!(f, "LOAD"),
            Token::StoreIdent => write!(f, "STORE"),
            Token::Hash => write!(f, "HASH"),
            Token::Sign => write!(f, "SIGN"),
            Token::Verify => write!(f, "VERIFY"),
            Token::Jump => write!(f, "JUMP"),
            Token::JumpI => write!(f, "JUMPI"),
            Token::Call => write!(f, "CALL"),
            Token::Ret => write!(f, "RET"),
            Token::Stop => write!(f, "STOP"),
            Token::GetBlockNumber => write!(f, "GETBLOCKNUMBER"),
            Token::GetSender => write!(f, "GETSENDER"),
            Token::LabelDecl(s) => write!(f, "{}:", s),
            Token::Literal(n) => write!(f, "{}", n),
            Token::LabelRef(s) => write!(f, "{}", s),
            Token::Identifier(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Instr {
    Add,
    Sub,
    Mul,
    Div,
    Push(i64),
    Pop,
    Load(String), // Changed: Now takes identifier
    Store(String), // Changed: Now takes identifier
    Hash,
    Sign,
    Verify,
    Jump(String),    // Target is a label string, to be resolved later
    JumpI(String),   // Target is a label string
    Call(String),    // New: Target is a label string
    Ret,             // New
    Stop,
    GetBlockNumber,  // New
    GetSender,       // New
    Label(String),   // A label definition
}

#[derive(Debug, PartialEq)]
pub enum ParseError {
    UnknownOpcode(String),
    MalformedLiteral(String),
    UnexpectedEndOfInput,
    ExpectedOperand,
    ExpectedLabel,
    LexerError(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::UnknownOpcode(s) => write!(f, "Unknown opcode: {}", s),
            ParseError::MalformedLiteral(s) => write!(f, "Malformed literal: {}", s),
            ParseError::UnexpectedEndOfInput => write!(f, "Unexpected end of input"),
            ParseError::ExpectedOperand => write!(f, "Expected an operand for instruction"),
            ParseError::ExpectedLabel => write!(f, "Expected a label"),
            ParseError::LexerError(s) => write!(f, "Lexer error: {}", s),
        }
    }
}
impl std::error::Error for ParseError {}

pub struct Lexer<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Lexer { input, pos: 0 }
    }

    fn skip_whitespace_and_comments(&mut self) {
        while self.pos < self.input.len() {
            let char = self.input[self.pos..].chars().next().unwrap();
            if char.is_whitespace() {
                self.pos += char.len_utf8();
            } else if self.input[self.pos..].starts_with(';') { // comments start with ;
                while self.pos < self.input.len() && self.input[self.pos..].chars().next().unwrap() != '\n' {
                    self.pos += self.input[self.pos..].chars().next().unwrap().len_utf8();
                }
            } else {
                break;
            }
        }
    }

    fn read_identifier(&mut self) -> String {
        let start = self.pos;
        while self.pos < self.input.len() {
            let char = self.input[self.pos..].chars().next().unwrap();
            if char.is_alphanumeric() || char == '_' {
                self.pos += char.len_utf8();
            } else {
                break;
            }
        }
        self.input[start..self.pos].to_string()
    }

    fn read_number(&mut self) -> Result<i64, ParseError> {
        let start = self.pos;
        if self.pos < self.input.len() && self.input[self.pos..].chars().next().unwrap() == '-' {
            self.pos += 1;
        }
        while self.pos < self.input.len() && self.input[self.pos..].chars().next().unwrap().is_ascii_digit() {
            self.pos += self.input[self.pos..].chars().next().unwrap().len_utf8();
        }
        let num_str = &self.input[start..self.pos];
        if num_str == "-" || num_str.is_empty() {
             return Err(ParseError::MalformedLiteral("Incomplete number".to_string()));
        }
        num_str.parse::<i64>().map_err(|_| ParseError::MalformedLiteral(num_str.to_string()))
    }

    pub fn next_token(&mut self) -> Option<Result<Token, ParseError>> {
        self.skip_whitespace_and_comments();

        if self.pos >= self.input.len() {
            return None;
        }

        let ident = self.read_identifier();

        if ident.is_empty() { // Might be a number if identifier is empty and not EOF
             // Check for label declaration (e.g. MY_LABEL:)
            let current_char = self.input[self.pos..].chars().next().unwrap();
            if current_char.is_ascii_digit() || current_char == '-' {
                return match self.read_number() {
                    Ok(n) => Some(Ok(Token::Literal(n))),
                    Err(e) => Some(Err(e)),
                };
            } else {
                 // If it's not an identifier and not a number, it's an error or unhandled character.
                 // For now, let's assume an error. A more robust lexer might handle operators etc.
                 return Some(Err(ParseError::LexerError(format!("Unexpected character: {}", current_char))));
            }
        }


        if self.pos < self.input.len() && self.input[self.pos..].starts_with(':') {
            self.pos += 1; // Consume ':'
            return Some(Ok(Token::LabelDecl(ident.to_uppercase())));
        }

        match ident.to_uppercase().as_str() {
            "ADD" => Some(Ok(Token::Add)),
            "SUB" => Some(Ok(Token::Sub)),
            "MUL" => Some(Ok(Token::Mul)),
            "DIV" => Some(Ok(Token::Div)),
            "PUSH" => Some(Ok(Token::Push)),
            "POP" => Some(Ok(Token::Pop)),
            "LOAD" => Some(Ok(Token::LoadIdent)),
            "STORE" => Some(Ok(Token::StoreIdent)),
            "HASH" => Some(Ok(Token::Hash)),
            "SIGN" => Some(Ok(Token::Sign)),
            "VERIFY" => Some(Ok(Token::Verify)),
            "JUMP" => Some(Ok(Token::Jump)),
            "JUMPI" => Some(Ok(Token::JumpI)),
            "CALL" => Some(Ok(Token::Call)),
            "RET" => Some(Ok(Token::Ret)),
            "STOP" => Some(Ok(Token::Stop)),
            "GETBLOCKNUMBER" => Some(Ok(Token::GetBlockNumber)),
            "GETSENDER" => Some(Ok(Token::GetSender)),
            _ => { // If not an opcode, it could be a label reference or a literal if it's a number
                // Try to parse as a number first (e.g. PUSH 10)
                // This part is tricky because an identifier could be a label *or* a standalone number if we supported that
                // For now, assume if it's not an Opcode, it's a LabelRef.
                // The parser will decide if a LabelRef is valid in the current context.
                Some(Ok(Token::LabelRef(ident)))
            }
        }
    }
}

pub struct Parser<'a> {
    lexer: Lexer<'a>,
    current_token: Option<Result<Token, ParseError>>,
    peek_token: Option<Result<Token, ParseError>>,
}

impl<'a> Parser<'a> {
    pub fn new(lexer: Lexer<'a>) -> Self {
        let mut p = Parser { lexer, current_token: None, peek_token: None };
        p.advance_tokens(); // Initialize current_token
        p.advance_tokens(); // Initialize peek_token
        p
    }

    fn advance_tokens(&mut self) {
        self.current_token = self.peek_token.take();
        self.peek_token = self.lexer.next_token();
    }

    fn consume_token_if<F>(&mut self, predicate: F) -> Result<Token, ParseError>
    where
        F: FnOnce(&Token) -> bool,
    {
        if let Some(Ok(ref token)) = self.current_token {
            if predicate(token) {
                let result = self.current_token.take().unwrap(); // Safe due to check
                self.advance_tokens();
                return result;
            }
        }
        // Provide more context in error
        Err(ParseError::LexerError(format!(
            "Unexpected token: {:?}, while expecting a token satisfying predicate",
            self.current_token
        )))
    }


    pub fn parse(&mut self) -> Result<Vec<Instr>, ParseError> {
        let mut instructions = Vec::new();

        while let Some(ref token_res) = self.current_token {
            match token_res {
                Ok(token) => {
                    let instr = match token.clone() {
                        // Simple Opcodes (no arguments from parser's perspective here)
                        Token::Add => Instr::Add,
                        Token::Sub => Instr::Sub,
                        Token::Mul => Instr::Mul,
                        Token::Div => Instr::Div,
                        Token::Pop => Instr::Pop,
                        Token::Hash => Instr::Hash,
                        Token::Sign => Instr::Sign,
                        Token::Verify => Instr::Verify,
                        Token::Ret => Instr::Ret,
                        Token::Stop => Instr::Stop,
                        Token::GetBlockNumber => Instr::GetBlockNumber,
                        Token::GetSender => Instr::GetSender,

                        // Opcodes with arguments
                        Token::LoadIdent => {
                            self.advance_tokens(); // Consume LOAD
                            let ident_token = self.current_token.take().ok_or(ParseError::ExpectedOperand)??;
                            match ident_token {
                                Token::Identifier(ident) | Token::LabelRef(ident) => Instr::Load(ident),
                                _ => return Err(ParseError::MalformedLiteral(format!("Expected identifier for LOAD, got {:?}", ident_token))),
                            }
                        }
                        Token::StoreIdent => {
                            self.advance_tokens(); // Consume STORE
                            let ident_token = self.current_token.take().ok_or(ParseError::ExpectedOperand)??;
                             match ident_token {
                                Token::Identifier(ident) | Token::LabelRef(ident) => Instr::Store(ident),
                                _ => return Err(ParseError::MalformedLiteral(format!("Expected identifier for STORE, got {:?}", ident_token))),
                            }
                        }
                        Token::Push => {
                            self.advance_tokens(); // Consume PUSH
                            let literal_token = self.current_token.take().ok_or(ParseError::ExpectedOperand)??;
                            if let Token::Literal(val) = literal_token {
                                Instr::Push(val)
                            } else {
                                return Err(ParseError::MalformedLiteral(format!("Expected literal for PUSH, got {:?}", literal_token)));
                            }
                        }
                        Token::Jump => {
                            self.advance_tokens(); // Consume JUMP
                            let label_token = self.current_token.take().ok_or(ParseError::ExpectedLabel)??;
                            if let Token::LabelRef(label) = label_token {
                                Instr::Jump(label)
                            } else {
                                return Err(ParseError::ExpectedLabel);
                            }
                        }
                        Token::JumpI => {
                            self.advance_tokens(); // Consume JUMPI
                            let label_token = self.current_token.take().ok_or(ParseError::ExpectedLabel)??;
                            if let Token::LabelRef(label) = label_token {
                                Instr::JumpI(label)
                            } else {
                                return Err(ParseError::ExpectedLabel);
                            }
                        }
                        Token::Call => {
                            self.advance_tokens(); // Consume CALL
                            let label_token = self.current_token.take().ok_or(ParseError::ExpectedLabel)??;
                            if let Token::LabelRef(label) = label_token {
                                Instr::Call(label)
                            } else {
                                return Err(ParseError::ExpectedLabel);
                            }
                        }
                        Token::LabelDecl(label_name) => {
                            Instr::Label(label_name)
                        }
                        
                        // Tokens that should not start an instruction if they appear here
                        Token::Literal(val) => return Err(ParseError::UnknownOpcode(format!("Literal '{}' found unexpectedly as instruction start", val))),
                        Token::Identifier(s) => return Err(ParseError::UnknownOpcode(format!("Identifier '{}' found unexpectedly as instruction start",s))),
                        Token::LabelRef(s) => return Err(ParseError::UnknownOpcode(format!("LabelRef '{}' found unexpectedly as instruction start",s))),
                    };
                    instructions.push(instr);
                }
                Err(e) => return Err(ParseError::LexerError(e.to_string())), // Propagate lexer errors
            }
            self.advance_tokens();
            if self.current_token.is_none() {
                break; // End of input
            }
        }
        if instructions.is_empty() && self.input_is_not_empty_whitespace() {
             return Err(ParseError::UnexpectedEndOfInput); // Or some other appropriate error
        }

        Ok(instructions)
    }
     fn input_is_not_empty_whitespace(&self) -> bool {
        !self.lexer.input.trim().is_empty()
    }
} 