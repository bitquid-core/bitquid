//! RPC Authentication middleware.
//!
//! Supports two modes:
//!
//! 1. **API Key** — Static bearer token compared in constant-time.
//!    Header: `Authorization: Bearer <api_key>`
//!
//! 2. **JWT (HS256)** — HMAC-SHA256 signed JSON Web Token with expiry.
//!    Header: `Authorization: Bearer <jwt_token>`
//!
//! Health and status endpoints are always exempt from authentication.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::warn;

type HmacSha256 = Hmac<Sha256>;

/// Authentication configuration.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Static API keys that grant full access.
    pub api_keys: Vec<String>,
    /// Secret used to verify HS256 JWTs. If empty, JWT auth is disabled.
    pub jwt_secret: Option<String>,
    /// Paths that bypass authentication entirely.
    pub exempt_paths: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            api_keys: Vec::new(),
            jwt_secret: None,
            exempt_paths: vec!["/health".into()],
        }
    }
}

impl AuthConfig {
    pub fn is_enabled(&self) -> bool {
        !self.api_keys.is_empty() || self.jwt_secret.is_some()
    }
}

/// Axum middleware function that enforces authentication.
pub async fn auth_middleware(
    state: Arc<AuthConfig>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if !state.is_enabled() {
        return Ok(next.run(req).await);
    }

    let path = req.uri().path().to_string();
    if state.exempt_paths.iter().any(|p| path.starts_with(p)) {
        return Ok(next.run(req).await);
    }

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = auth_header.strip_prefix("Bearer ").unwrap_or("");
    if token.is_empty() {
        warn!("RPC auth: missing or malformed Authorization header from {}", path);
        return Err(StatusCode::UNAUTHORIZED);
    }

    if check_api_key(&state.api_keys, token) {
        return Ok(next.run(req).await);
    }

    if let Some(ref secret) = state.jwt_secret {
        if verify_jwt(token, secret) {
            return Ok(next.run(req).await);
        }
    }

    warn!("RPC auth: invalid credentials for {}", path);
    Err(StatusCode::UNAUTHORIZED)
}

fn check_api_key(keys: &[String], token: &str) -> bool {
    let token_bytes = token.as_bytes();
    for key in keys {
        let key_bytes = key.as_bytes();
        if constant_time_eq(token_bytes, key_bytes) {
            return true;
        }
    }
    false
}

/// Constant-time byte comparison to prevent timing side-channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Minimal HS256 JWT verification.
///
/// Token format: `base64url(header).base64url(payload).base64url(signature)`
///
/// We verify:
/// 1. The HMAC-SHA256 signature matches.
/// 2. If an `exp` claim exists, it hasn't passed.
fn verify_jwt(token: &str, secret: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);

    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(signing_input.as_bytes());

    let Ok(sig_bytes) = base64_url_decode(parts[2]) else {
        return false;
    };

    if mac.verify_slice(&sig_bytes).is_err() {
        return false;
    }

    let Ok(payload_bytes) = base64_url_decode(parts[1]) else {
        return false;
    };

    if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) {
        if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64()) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now > exp {
                warn!("RPC auth: JWT expired (exp={exp}, now={now})");
                return false;
            }
        }
    }

    true
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>, ()> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.decode(input).map_err(|_| ())
}

/// Helper: create an HS256 JWT for testing / CLI tooling.
pub fn create_jwt(secret: &str, expiry_secs: u64) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let payload = format!(r#"{{"iat":{},"exp":{}}}"#, now, now + expiry_secs);

    let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let p = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let signing_input = format!("{h}.{p}");

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC key length is always valid");
    mac.update(signing_input.as_bytes());
    let sig = mac.finalize().into_bytes();
    let s = URL_SAFE_NO_PAD.encode(&sig);

    format!("{signing_input}.{s}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_check() {
        let keys = vec!["test-key-123".to_string(), "other-key".to_string()];
        assert!(check_api_key(&keys, "test-key-123"));
        assert!(check_api_key(&keys, "other-key"));
        assert!(!check_api_key(&keys, "wrong-key"));
        assert!(!check_api_key(&keys, "test-key-12")); // prefix
        assert!(!check_api_key(&keys, ""));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_jwt_create_and_verify() {
        let secret = "super-secret-key-for-testing";
        let token = create_jwt(secret, 3600);
        assert!(verify_jwt(&token, secret));
        assert!(!verify_jwt(&token, "wrong-secret"));
    }

    #[test]
    fn test_jwt_expired() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let secret = "expired-test";
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let payload = r#"{"iat":1000000,"exp":1000001}"#;

        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signing_input = format!("{h}.{p}");

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signing_input.as_bytes());
        let sig = mac.finalize().into_bytes();
        let s = URL_SAFE_NO_PAD.encode(&sig);

        let token = format!("{signing_input}.{s}");
        assert!(!verify_jwt(&token, secret), "expired JWT must be rejected");
    }

    #[test]
    fn test_jwt_malformed() {
        assert!(!verify_jwt("not-a-jwt", "secret"));
        assert!(!verify_jwt("a.b", "secret"));
        assert!(!verify_jwt("", "secret"));
    }
}
