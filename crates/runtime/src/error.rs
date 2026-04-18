use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("out of gas: used {used}, limit {limit}")]
    OutOfGas { used: u64, limit: u64 },

    #[error("stack overflow")]
    StackOverflow,

    #[error("stack underflow")]
    StackUnderflow,

    #[error("invalid opcode: 0x{0:02x}")]
    InvalidOpcode(u8),

    #[error("invalid memory access: offset={offset}, size={size}")]
    InvalidMemoryAccess { offset: usize, size: usize },

    #[error("execution reverted: {0}")]
    Revert(String),

    #[error("call depth exceeded: {0}")]
    CallDepthExceeded(usize),

    #[error("invalid jump destination: {0}")]
    InvalidJump(usize),

    #[error("division by zero")]
    DivisionByZero,

    #[error("contract too large: {size} > {max}")]
    ContractTooLarge { size: usize, max: usize },

    #[error("state error: {0}")]
    State(String),
}
