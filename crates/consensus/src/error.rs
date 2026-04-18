use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("not the leader for this view")]
    NotLeader,

    #[error("invalid proposal: {0}")]
    InvalidProposal(String),

    #[error("duplicate message from {0}")]
    DuplicateMessage(String),

    #[error("insufficient votes: have {have}, need {need}")]
    InsufficientVotes { have: usize, need: usize },

    #[error("invalid view: expected {expected}, got {got}")]
    InvalidView { expected: u64, got: u64 },

    #[error("validator not found: {0}")]
    ValidatorNotFound(String),

    #[error("view change timeout")]
    ViewChangeTimeout,

    #[error("block validation failed: {0}")]
    BlockValidation(String),

    #[error("invalid block: {0}")]
    InvalidBlock(String),

    #[error("crypto error: {0}")]
    Crypto(#[from] bitquid_crypto::CryptoError),

    #[error("core error: {0}")]
    Core(#[from] bitquid_core::CoreError),
}
