/// Instruction set for the Bitquid-Fi VM
///
/// A lightweight stack-based VM optimized for DeFi operations.
/// Simpler than EVM but includes native DeFi instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    // Arithmetic
    Add = 0x01,
    Sub = 0x02,
    Mul = 0x03,
    Div = 0x04,
    Mod = 0x05,

    // Comparison
    Lt = 0x10,
    Gt = 0x11,
    Eq = 0x12,
    IsZero = 0x13,

    // Bitwise
    And = 0x20,
    Or = 0x21,
    Xor = 0x22,
    Not = 0x23,
    Shl = 0x24,
    Shr = 0x25,

    // Stack operations
    Push = 0x30,
    Pop = 0x31,
    Dup = 0x32,
    Swap = 0x33,

    // Memory
    MLoad = 0x40,
    MStore = 0x41,
    MSize = 0x42,

    // Storage
    SLoad = 0x50,
    SStore = 0x51,

    // Control flow
    Jump = 0x60,
    JumpIf = 0x61,
    Halt = 0x62,
    Revert = 0x63,

    // Environment
    Caller = 0x70,
    CallValue = 0x71,
    CallDataLoad = 0x72,
    CallDataSize = 0x73,
    Address = 0x74,
    Balance = 0x75,
    BlockHeight = 0x76,
    Timestamp = 0x77,

    // Native DeFi operations
    Transfer = 0x80,
    Approve = 0x81,
    Mint = 0x82,
    Burn = 0x83,

    // AMM primitives
    SwapExact = 0x90,
    AddLiquidity = 0x91,
    RemoveLiquidity = 0x92,
    GetReserves = 0x93,

    // Lending primitives
    Deposit = 0xA0,
    Withdraw = 0xA1,
    Borrow = 0xA2,
    Repay = 0xA3,

    // Logging
    Log = 0xF0,
}

impl OpCode {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Add),
            0x02 => Some(Self::Sub),
            0x03 => Some(Self::Mul),
            0x04 => Some(Self::Div),
            0x05 => Some(Self::Mod),
            0x10 => Some(Self::Lt),
            0x11 => Some(Self::Gt),
            0x12 => Some(Self::Eq),
            0x13 => Some(Self::IsZero),
            0x20 => Some(Self::And),
            0x21 => Some(Self::Or),
            0x22 => Some(Self::Xor),
            0x23 => Some(Self::Not),
            0x24 => Some(Self::Shl),
            0x25 => Some(Self::Shr),
            0x30 => Some(Self::Push),
            0x31 => Some(Self::Pop),
            0x32 => Some(Self::Dup),
            0x33 => Some(Self::Swap),
            0x40 => Some(Self::MLoad),
            0x41 => Some(Self::MStore),
            0x42 => Some(Self::MSize),
            0x50 => Some(Self::SLoad),
            0x51 => Some(Self::SStore),
            0x60 => Some(Self::Jump),
            0x61 => Some(Self::JumpIf),
            0x62 => Some(Self::Halt),
            0x63 => Some(Self::Revert),
            0x70 => Some(Self::Caller),
            0x71 => Some(Self::CallValue),
            0x72 => Some(Self::CallDataLoad),
            0x73 => Some(Self::CallDataSize),
            0x74 => Some(Self::Address),
            0x75 => Some(Self::Balance),
            0x76 => Some(Self::BlockHeight),
            0x77 => Some(Self::Timestamp),
            0x80 => Some(Self::Transfer),
            0x81 => Some(Self::Approve),
            0x82 => Some(Self::Mint),
            0x83 => Some(Self::Burn),
            0x90 => Some(Self::SwapExact),
            0x91 => Some(Self::AddLiquidity),
            0x92 => Some(Self::RemoveLiquidity),
            0x93 => Some(Self::GetReserves),
            0xA0 => Some(Self::Deposit),
            0xA1 => Some(Self::Withdraw),
            0xA2 => Some(Self::Borrow),
            0xA3 => Some(Self::Repay),
            0xF0 => Some(Self::Log),
            _ => None,
        }
    }
}
