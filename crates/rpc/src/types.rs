use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC 2.0 Request
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    pub id: Value,
}

/// JSON-RPC 2.0 Response
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: Value, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: None,
            }),
            id,
        }
    }
}

/// Block response for RPC
#[derive(Debug, Serialize)]
pub struct BlockResponse {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub timestamp: u64,
    pub proposer: String,
    pub tx_count: u32,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub state_root: String,
    pub size: usize,
}

/// Transaction response for RPC
#[derive(Debug, Serialize)]
pub struct TransactionResponse {
    pub hash: String,
    pub tx_type: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub block_height: Option<u64>,
    pub index: Option<u32>,
}

/// Account response for RPC
#[derive(Debug, Serialize)]
pub struct AccountResponse {
    pub address: String,
    pub balance: String,
    pub nonce: u64,
    pub staked: String,
    pub is_contract: bool,
}

/// Node status response
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub version: String,
    pub chain_id: u32,
    pub latest_height: u64,
    pub peer_count: usize,
    pub mempool_size: usize,
    pub syncing: bool,
}
