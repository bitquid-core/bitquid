use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("peer disconnected: {0}")]
    PeerDisconnected(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("peer not found: {0}")]
    PeerNotFound(String),

    #[error("max peers reached: {0}")]
    MaxPeersReached(usize),

    #[error("banned peer: {0}")]
    BannedPeer(String),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("message too large: {size} > {max}")]
    MessageTooLarge { size: usize, max: usize },
}
