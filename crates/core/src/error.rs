use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid block: {0}")]
    InvalidBlock(String),

    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("invalid state transition: {0}")]
    InvalidStateTransition(String),

    #[error("insufficient balance: need {need}, have {have}")]
    InsufficientBalance { need: u64, have: u64 },

    #[error("nonce mismatch: expected {expected}, got {got}")]
    NonceMismatch { expected: u64, got: u64 },

    #[error("block height mismatch: expected {expected}, got {got}")]
    HeightMismatch { expected: u64, got: u64 },

    #[error("duplicate transaction: {0}")]
    DuplicateTransaction(String),

    #[error("block too large: {size} > {max}")]
    BlockTooLarge { size: usize, max: usize },

    #[error("gas limit exceeded: used {used}, limit {limit}")]
    GasLimitExceeded { used: u64, limit: u64 },

    #[error("crypto error: {0}")]
    Crypto(#[from] bitquid_crypto::CryptoError),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("account not found: {0}")]
    AccountNotFound(String),

    #[error("genesis already initialized")]
    GenesisAlreadyInitialized,
}
