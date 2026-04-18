use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("invalid hash length: expected {expected}, got {got}")]
    InvalidHashLength { expected: usize, got: usize },

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}
