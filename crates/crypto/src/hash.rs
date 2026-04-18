use sha2::{Digest, Sha256};

pub const HASH_LEN: usize = 32;
pub type Hash = [u8; HASH_LEN];

/// BLAKE3 hash - used for internal state hashing (extremely fast)
#[inline]
pub fn blake3_hash(data: &[u8]) -> Hash {
    *blake3::hash(data).as_bytes()
}

/// SHA-256 hash - used for Bitcoin-compatible operations
#[inline]
pub fn sha256_hash(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; HASH_LEN];
    hash.copy_from_slice(&result);
    hash
}

/// Double SHA-256 - standard Bitcoin hashing
#[inline]
pub fn double_sha256(data: &[u8]) -> Hash {
    sha256_hash(&sha256_hash(data))
}

/// BLAKE3 keyed hash for domain separation
#[inline]
pub fn blake3_keyed_hash(key: &[u8; 32], data: &[u8]) -> Hash {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// Hash concatenation of two hashes (for Merkle tree)
#[inline]
pub fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut combined = [0u8; HASH_LEN * 2];
    combined[..HASH_LEN].copy_from_slice(left);
    combined[HASH_LEN..].copy_from_slice(right);
    blake3_hash(&combined)
}

/// Convert hash to hex string
#[inline]
pub fn hash_to_hex(hash: &Hash) -> String {
    hex::encode(hash)
}

/// Parse hex string to hash
pub fn hex_to_hash(s: &str) -> Result<Hash, crate::CryptoError> {
    let bytes = hex::decode(s)?;
    if bytes.len() != HASH_LEN {
        return Err(crate::CryptoError::InvalidHashLength {
            expected: HASH_LEN,
            got: bytes.len(),
        });
    }
    let mut hash = [0u8; HASH_LEN];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_deterministic() {
        let data = b"bitquid-fi";
        assert_eq!(blake3_hash(data), blake3_hash(data));
    }

    #[test]
    fn test_sha256_deterministic() {
        let data = b"bitquid-fi";
        assert_eq!(sha256_hash(data), sha256_hash(data));
    }

    #[test]
    fn test_double_sha256() {
        let data = b"test";
        let single = sha256_hash(data);
        let double = double_sha256(data);
        assert_ne!(single, double);
        assert_eq!(double, sha256_hash(&single));
    }

    #[test]
    fn test_hash_hex_roundtrip() {
        let hash = blake3_hash(b"test");
        let hex_str = hash_to_hex(&hash);
        let recovered = hex_to_hash(&hex_str).unwrap();
        assert_eq!(hash, recovered);
    }
}
