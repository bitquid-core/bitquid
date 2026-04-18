pub mod error;
pub mod handlers;
pub mod types;
pub mod auth;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tokio::sync::RwLock;
use tracing::{info, warn};

pub use error::RpcError;
pub use auth::{AuthConfig, create_jwt};

use bitquid_core::state::WorldState;
use bitquid_mempool::Mempool;
use bitquid_storage::Storage;

/// Shared application state for RPC handlers
pub struct AppState {
    pub storage: Arc<Storage>,
    pub mempool: Arc<Mempool>,
    pub world_state: Arc<RwLock<WorldState>>,
    pub chain_id: u32,
    pub version: String,
    pub min_gas_price: u64,
}

/// RPC server configuration
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// Authentication settings
    pub auth: AuthConfig,
    /// Allowed CORS origins. Empty = restrictive default (same-origin only).
    pub cors_origins: Vec<String>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            auth: AuthConfig::default(),
            cors_origins: Vec::new(),
        }
    }
}

/// Start the JSON-RPC server with full authentication and CORS configuration.
pub async fn start_rpc_server(
    listen_addr: SocketAddr,
    state: Arc<AppState>,
) -> Result<(), RpcError> {
    start_rpc_server_with_config(listen_addr, state, RpcConfig::default()).await
}

pub async fn start_rpc_server_with_config(
    listen_addr: SocketAddr,
    state: Arc<AppState>,
    config: RpcConfig,
) -> Result<(), RpcError> {
    let cors = if config.cors_origins.is_empty() {
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(std::iter::empty::<axum::http::HeaderValue>()))
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
    } else {
        let origins: Vec<_> = config
            .cors_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
    };

    let auth_config = Arc::new(config.auth);

    let mut app = Router::new()
        .route("/", post(handlers::json_rpc_handler))
        .route("/health", get(handlers::health))
        .route("/status", get(handlers::status))
        .with_state(state);

    if auth_config.is_enabled() {
        info!("RPC authentication enabled (API keys: {}, JWT: {})",
              auth_config.api_keys.len(),
              if auth_config.jwt_secret.is_some() { "yes" } else { "no" });
        let ac = auth_config.clone();
        app = app.layer(middleware::from_fn(move |req, next| {
            let config = ac.clone();
            auth::auth_middleware(config, req, next)
        }));
    } else {
        warn!("RPC authentication DISABLED — do NOT expose this endpoint to untrusted networks");
    }

    app = app.layer(cors).layer(TraceLayer::new_for_http());

    info!("RPC server listening on {listen_addr}");

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .map_err(|e| RpcError::Server(e.to_string()))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| RpcError::Server(e.to_string()))
}
