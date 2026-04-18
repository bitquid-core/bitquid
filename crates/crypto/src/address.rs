use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::hash::blake3_hash;
use crate::keys::PublicKey;

pub const ADDRESS_LEN: usize = 20;

/// 20-byte address derived from public key hash
#[derive(Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Address(#[serde(with = "hex::serde")] pub [u8; ADDRESS_LEN]);

impl Address {
    pub const ZERO: Address = Address([0u8; ADDRESS_LEN]);

    pub fn from_public_key(pubkey: &PublicKey) -> Self {
        let hash = blake3_hash(pubkey.as_bytes());
        let mut addr = [0u8; ADDRESS_LEN];
        addr.copy_from_slice(&hash[12..32]);
        Self(addr)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ADDRESS_LEN {
            return Err(CryptoError::InvalidAddress(format!(
                "expected {} bytes, got {}",
                ADDRESS_LEN,
                bytes.len()
            )));
        }
        let mut addr = [0u8; ADDRESS_LEN];
        addr.copy_from_slice(bytes);
        Ok(Self(addr))
    }

    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)?;
        Self::from_bytes(&bytes)
    }

    pub fn as_bytes(&self) -> &[u8; ADDRESS_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::ZERO
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Addr({})", self.to_hex())
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn test_address_from_pubkey() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        assert!(!addr.is_zero());
    }

    #[test]
    fn test_address_hex_roundtrip() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let hex_str = addr.to_hex();
        let recovered = Address::from_hex(&hex_str).unwrap();
        assert_eq!(addr, recovered);
    }

    #[test]
    fn test_deterministic_address() {
        let kp = KeyPair::generate();
        let addr1 = Address::from_public_key(&kp.public);
        let addr2 = Address::from_public_key(&kp.public);
        assert_eq!(addr1, addr2);
    }
}
