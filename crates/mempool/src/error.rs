use thiserror::Error;

#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("transaction already in pool")]
    DuplicateTransaction,

    #[error("transaction was previously rejected")]
    PreviouslyRejected,

    #[error("mempool is full")]
    PoolFull,

    #[error("sender has too many pending transactions")]
    SenderLimitReached,

    #[error("transaction gas price too low")]
    GasPriceTooLow,

    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("nonce too low: {0}")]
    NonceTooLow(u64),
}
