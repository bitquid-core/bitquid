use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("server error: {0}")]
    Server(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("method not found: {0}")]
    MethodNotFound(String),

    #[error("invalid params: {0}")]
    InvalidParams(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("not found: {0}")]
    NotFound(String),
}

impl RpcError {
    pub fn code(&self) -> i32 {
        match self {
            Self::InvalidRequest(_) => -32600,
            Self::MethodNotFound(_) => -32601,
            Self::InvalidParams(_) => -32602,
            Self::Internal(_) => -32603,
            Self::Server(_) => -32000,
            Self::NotFound(_) => -32001,
        }
    }
}
