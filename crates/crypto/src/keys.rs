use ml_dsa::{
    MlDsa65,
    VerifyingKey as MlDsaVerifyingKey,
    Signature as MlDsaSignature,
    KeyGen, EncodedSignature, EncodedVerifyingKey,
};
use ml_dsa::signature::{Keypair, Signer, Verifier, SignatureEncoding};
use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::hash::Hash;

pub const SEED_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = SEED_LEN;

/// ML-DSA-65 verifying key (FIPS 204, security category 3, 1952 bytes)
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PublicKey(#[serde(with = "hex::serde")] pub Vec<u8>);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let enc: EncodedVerifyingKey<MlDsa65> = bytes.try_into().map_err(|_| {
            CryptoError::InvalidPublicKey(format!(
                "expected {} bytes, got {}",
                std::mem::size_of::<EncodedVerifyingKey<MlDsa65>>(),
                bytes.len()
            ))
        })?;
        let _vk = MlDsaVerifyingKey::<MlDsa65>::decode(&enc);
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_verifying_key(&self) -> Result<MlDsaVerifyingKey<MlDsa65>, CryptoError> {
        let enc: EncodedVerifyingKey<MlDsa65> = self.0.as_slice().try_into().map_err(|_| {
            CryptoError::InvalidPublicKey("invalid verifying key length".into())
        })?;
        Ok(MlDsaVerifyingKey::<MlDsa65>::decode(&enc))
    }

    pub fn to_address(&self) -> crate::Address {
        crate::Address::from_public_key(self)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({}...)", hex::encode(&self.0[..8.min(self.0.len())]))
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// Secret key: stores a 32-byte seed; ML-DSA-65 keypair is derived deterministically
/// via FIPS 204 ML-DSA.KeyGen_internal.
pub struct SecretKey {
    seed: [u8; SEED_LEN],
}

impl SecretKey {
    pub fn generate() -> Self {
        let mut seed = [0u8; SEED_LEN];
        rand::Rng::fill(&mut rand::thread_rng(), &mut seed);
        Self { seed }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let seed: [u8; SEED_LEN] = bytes.try_into().map_err(|_| CryptoError::InvalidSecretKey)?;
        Ok(Self { seed })
    }

    pub fn to_bytes(&self) -> [u8; SEED_LEN] {
        self.seed
    }

    fn derive_keypair(&self) -> <MlDsa65 as KeyGen>::KeyPair {
        MlDsa65::from_seed((&self.seed).into())
    }

    pub fn public_key(&self) -> PublicKey {
        let kp = self.derive_keypair();
        let vk = kp.verifying_key();
        let encoded = vk.encode();
        let bytes: &[u8] = encoded.as_ref();
        PublicKey(bytes.to_vec())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let hash = crate::blake3_hash(message);
        let kp = self.derive_keypair();
        let sig: MlDsaSignature<MlDsa65> = kp.signing_key().sign(&hash);
        let encoded = sig.to_bytes();
        let bytes: &[u8] = encoded.as_ref();
        Signature(bytes.to_vec())
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        Self { seed: self.seed }
    }
}

/// ML-DSA-65 signature (3,309 bytes, FIPS 204)
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "hex::serde")] pub Vec<u8>);

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let _: EncodedSignature<MlDsa65> = bytes.try_into().map_err(|_| {
            CryptoError::InvalidSignature(format!(
                "invalid ML-DSA-65 signature length: {}",
                bytes.len()
            ))
        })?;
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn verify(&self, message: &[u8], public_key: &PublicKey) -> Result<(), CryptoError> {
        let vk = public_key.to_verifying_key()?;
        let hash = crate::blake3_hash(message);
        let enc: EncodedSignature<MlDsa65> = self.0.as_slice().try_into().map_err(|_| {
            CryptoError::InvalidSignature("invalid signature length".into())
        })?;
        let sig = MlDsaSignature::<MlDsa65>::decode(&enc)
            .ok_or_else(|| CryptoError::InvalidSignature("decode failed".into()))?;
        vk.verify(&hash, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    pub fn verify_prehashed(&self, hash: &[u8], public_key: &PublicKey) -> Result<(), CryptoError> {
        let vk = public_key.to_verifying_key()?;
        let enc: EncodedSignature<MlDsa65> = self.0.as_slice().try_into().map_err(|_| {
            CryptoError::InvalidSignature("invalid signature length".into())
        })?;
        let sig = MlDsaSignature::<MlDsa65>::decode(&enc)
            .ok_or_else(|| CryptoError::InvalidSignature("decode failed".into()))?;
        vk.verify(hash, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self(vec![0u8; 3309])
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let preview = &self.0[..8.min(self.0.len())];
        write!(f, "Sig({}..)", hex::encode(preview))
    }
}

/// Combined key pair
pub struct KeyPair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = SecretKey::generate();
        let public = secret.public_key();
        Self { secret, public }
    }

    pub fn from_secret(secret: SecretKey) -> Self {
        let public = secret.public_key();
        Self { secret, public }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.secret.sign(message)
    }

    pub fn address(&self) -> crate::Address {
        self.public.to_address()
    }

    pub fn sign_hash(&self, hash: &Hash) -> Signature {
        let kp = self.secret.derive_keypair();
        let sig: MlDsaSignature<MlDsa65> = kp.signing_key().sign(hash);
        let encoded = sig.to_bytes();
        let bytes: &[u8] = encoded.as_ref();
        Signature(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let kp = KeyPair::generate();
        assert!(!kp.public.0.is_empty());
    }

    #[test]
    fn test_sign_verify() {
        let kp = KeyPair::generate();
        let msg = b"hello bitquid post-quantum";
        let sig = kp.sign(msg);
        assert!(sig.verify(msg, &kp.public).is_ok());
    }

    #[test]
    fn test_wrong_key_fails() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let msg = b"hello";
        let sig = kp1.sign(msg);
        assert!(sig.verify(msg, &kp2.public).is_err());
    }

    #[test]
    fn test_wrong_message_fails() {
        let kp = KeyPair::generate();
        let sig = kp.sign(b"hello");
        assert!(sig.verify(b"world", &kp.public).is_err());
    }

    #[test]
    fn test_secret_key_roundtrip() {
        let sk = SecretKey::generate();
        let bytes = sk.to_bytes();
        let sk2 = SecretKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk.public_key(), sk2.public_key());
    }

    #[test]
    fn test_sign_hash_verify() {
        let kp = KeyPair::generate();
        let hash = crate::blake3_hash(b"some data");
        let sig = kp.sign_hash(&hash);
        assert!(sig.verify_prehashed(&hash, &kp.public).is_ok());
    }
}
