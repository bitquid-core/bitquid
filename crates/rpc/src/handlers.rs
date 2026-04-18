use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};
use tracing::debug;

use crate::error::RpcError;
use crate::types::*;
use crate::AppState;

/// Health check endpoint
pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// Node status endpoint
pub async fn status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        version: state.version.clone(),
        chain_id: state.chain_id,
        latest_height: state.storage.latest_height(),
        peer_count: 0,
        mempool_size: state.mempool.len(),
        syncing: false,
    })
}

/// Main JSON-RPC handler
pub async fn json_rpc_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<JsonRpcRequest>,
) -> Json<JsonRpcResponse> {
    debug!("RPC call: {}", req.method);

    let result = match req.method.as_str() {
        "bqf_blockNumber" => handle_block_number(&state).await,
        "bqf_getBlockByNumber" => handle_get_block_by_number(&state, &req.params).await,
        "bqf_getBlockByHash" => handle_get_block_by_hash(&state, &req.params).await,
        "bqf_getBalance" => handle_get_balance(&state, &req.params).await,
        "bqf_getAccount" => handle_get_account(&state, &req.params).await,
        "bqf_getTransactionReceipt" => handle_get_receipt(&state, &req.params).await,
        "bqf_sendTransaction" => handle_send_transaction(&state, &req.params).await,
        "bqf_chainId" => Ok(json!(format!("0x{:x}", state.chain_id))),
        "bqf_gasPrice" => Ok(json!("0x1")),
        "bqf_mempoolStatus" => {
            let stats = state.mempool.stats();
            Ok(json!({
                "txCount": stats.tx_count,
                "totalBytes": stats.total_bytes,
                "senderCount": stats.sender_count,
            }))
        }
        "net_version" => Ok(json!(state.chain_id.to_string())),
        "net_peerCount" => Ok(json!("0x0")),
        _ => Err(RpcError::MethodNotFound(req.method.clone())),
    };

    match result {
        Ok(value) => Json(JsonRpcResponse::success(req.id, value)),
        Err(e) => Json(JsonRpcResponse::error(req.id, e.code(), e.to_string())),
    }
}

async fn handle_block_number(state: &AppState) -> Result<Value, RpcError> {
    let height = state.storage.latest_height();
    Ok(json!(format!("0x{:x}", height)))
}

async fn handle_get_block_by_number(
    state: &AppState,
    params: &Value,
) -> Result<Value, RpcError> {
    let height = params
        .get(0)
        .and_then(|v| v.as_str())
        .and_then(|s| {
            let s = s.strip_prefix("0x").unwrap_or(s);
            u64::from_str_radix(s, 16).ok()
        })
        .ok_or_else(|| RpcError::InvalidParams("missing height".into()))?;

    let block = state
        .storage
        .get_block_by_height(height)
        .map_err(|e| RpcError::Internal(e.to_string()))?
        .ok_or_else(|| RpcError::NotFound(format!("block at height {height}")))?;

    let hash = block.hash();
    Ok(json!(BlockResponse {
        height: block.height(),
        hash: format!("0x{}", hex::encode(hash)),
        prev_hash: format!("0x{}", hex::encode(block.header.prev_hash)),
        timestamp: block.header.timestamp,
        proposer: block.header.proposer.to_hex(),
        tx_count: block.header.tx_count,
        gas_used: block.header.gas_used,
        gas_limit: block.header.gas_limit,
        state_root: format!("0x{}", hex::encode(block.header.state_root)),
        size: block.byte_size(),
    }))
}

async fn handle_get_block_by_hash(
    state: &AppState,
    params: &Value,
) -> Result<Value, RpcError> {
    let hash_str = params
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("missing hash".into()))?;

    let hash_str = hash_str.strip_prefix("0x").unwrap_or(hash_str);
    let hash_bytes =
        hex::decode(hash_str).map_err(|e| RpcError::InvalidParams(e.to_string()))?;

    if hash_bytes.len() != 32 {
        return Err(RpcError::InvalidParams("hash must be 32 bytes".into()));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_bytes);

    let block = state
        .storage
        .get_block_by_hash(&hash)
        .map_err(|e| RpcError::Internal(e.to_string()))?
        .ok_or_else(|| RpcError::NotFound("block not found".into()))?;

    Ok(json!(BlockResponse {
        height: block.height(),
        hash: format!("0x{}", hex::encode(block.hash())),
        prev_hash: format!("0x{}", hex::encode(block.header.prev_hash)),
        timestamp: block.header.timestamp,
        proposer: block.header.proposer.to_hex(),
        tx_count: block.header.tx_count,
        gas_used: block.header.gas_used,
        gas_limit: block.header.gas_limit,
        state_root: format!("0x{}", hex::encode(block.header.state_root)),
        size: block.byte_size(),
    }))
}

async fn handle_get_balance(state: &AppState, params: &Value) -> Result<Value, RpcError> {
    let addr_str = params
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("missing address".into()))?;

    let addr = bitquid_crypto::Address::from_hex(addr_str)
        .map_err(|e| RpcError::InvalidParams(e.to_string()))?;

    let ws = state.world_state.read().await;
    let balance = ws.get_balance(&addr);

    Ok(json!(format!("0x{:x}", balance)))
}

async fn handle_get_account(state: &AppState, params: &Value) -> Result<Value, RpcError> {
    let addr_str = params
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("missing address".into()))?;

    let addr = bitquid_crypto::Address::from_hex(addr_str)
        .map_err(|e| RpcError::InvalidParams(e.to_string()))?;

    let ws = state.world_state.read().await;
    let account = ws
        .get_account(&addr)
        .ok_or_else(|| RpcError::NotFound("account not found".into()))?;

    Ok(json!(AccountResponse {
        address: addr.to_hex(),
        balance: account.balance.to_string(),
        nonce: account.nonce,
        staked: account.staked.to_string(),
        is_contract: account.is_contract,
    }))
}

async fn handle_get_receipt(state: &AppState, params: &Value) -> Result<Value, RpcError> {
    let hash_str = params
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("missing tx hash".into()))?;

    let hash_str = hash_str.strip_prefix("0x").unwrap_or(hash_str);
    let hash_bytes =
        hex::decode(hash_str).map_err(|e| RpcError::InvalidParams(e.to_string()))?;

    if hash_bytes.len() != 32 {
        return Err(RpcError::InvalidParams("hash must be 32 bytes".into()));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_bytes);

    let receipt = state
        .storage
        .get_receipt(&hash)
        .map_err(|e| RpcError::Internal(e.to_string()))?
        .ok_or_else(|| RpcError::NotFound("receipt not found".into()))?;

    Ok(json!({
        "txHash": format!("0x{}", hex::encode(receipt.tx_hash)),
        "blockHeight": receipt.block_height,
        "index": receipt.index,
        "success": receipt.success,
        "gasUsed": receipt.gas_used,
    }))
}

async fn handle_send_transaction(
    state: &AppState,
    params: &Value,
) -> Result<Value, RpcError> {
    let raw_hex = params
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("expected hex-encoded signed transaction".into()))?;

    let raw_hex = raw_hex.strip_prefix("0x").unwrap_or(raw_hex);
    let tx_bytes = hex::decode(raw_hex)
        .map_err(|e| RpcError::InvalidParams(format!("invalid hex: {e}")))?;

    let mut signed_tx: bitquid_core::transaction::SignedTransaction =
        bincode::deserialize(&tx_bytes)
            .map_err(|e| RpcError::InvalidParams(format!("invalid tx encoding: {e}")))?;

    signed_tx.recompute_hash();

    if signed_tx.inner.chain_id != state.chain_id {
        return Err(RpcError::InvalidParams(format!(
            "wrong chain_id: expected {}, got {}",
            state.chain_id, signed_tx.inner.chain_id
        )));
    }

    signed_tx
        .verify()
        .map_err(|e| RpcError::InvalidParams(format!("signature verification failed: {e}")))?;

    if signed_tx.inner.gas_price < state.min_gas_price {
        return Err(RpcError::InvalidParams(format!(
            "gas_price {} below minimum {}",
            signed_tx.inner.gas_price, state.min_gas_price
        )));
    }

    let ws = state.world_state.read().await;
    let sender = signed_tx.sender();
    let account_nonce = ws.get_nonce(&sender);
    if signed_tx.nonce() < account_nonce {
        return Err(RpcError::InvalidParams(format!(
            "nonce too low: expected >= {account_nonce}, got {}",
            signed_tx.nonce()
        )));
    }
    let balance = ws.get_balance(&sender);
    if signed_tx.total_cost() > balance {
        return Err(RpcError::InvalidParams(format!(
            "insufficient balance: need {}, have {balance}",
            signed_tx.total_cost()
        )));
    }
    drop(ws);

    let tx_hash = signed_tx.tx_hash();
    state
        .mempool
        .insert(signed_tx)
        .map_err(|e| RpcError::Internal(format!("mempool: {e}")))?;

    Ok(json!(format!("0x{}", hex::encode(tx_hash))))
}
