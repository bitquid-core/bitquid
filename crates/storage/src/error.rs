use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("deserialization error: {0}")]
    Deserialization(String),

    #[error("key not found: {0}")]
    NotFound(String),

    #[error("storage corruption detected: {0}")]
    Corruption(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
