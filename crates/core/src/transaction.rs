use bitquid_crypto::{blake3_hash, Address, Hash, KeyPair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TransactionType {
    Transfer = 0,
    ContractCall = 1,
    ContractCreate = 2,
    Stake = 5,
    Unstake = 6,
}

/// Raw transaction data (unsigned)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub tx_type: TransactionType,
    pub nonce: u64,
    pub from: Address,
    pub to: Address,
    pub value: u64,
    pub data: Vec<u8>,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub chain_id: u32,
}

impl Transaction {
    /// Compute the signing hash for this transaction
    pub fn signing_hash(&self) -> Hash {
        let encoded = bincode::serialize(self).expect("transaction serialization cannot fail");
        blake3_hash(&encoded)
    }

    /// Sign this transaction with a keypair, producing a SignedTransaction
    pub fn sign(self, keypair: &KeyPair) -> SignedTransaction {
        let hash = self.signing_hash();
        let signature = keypair.sign_hash(&hash);
        let sender_pubkey = keypair.public.clone();
        let tx_hash = compute_signed_tx_hash(&self, &signature, &sender_pubkey);
        SignedTransaction {
            inner: self,
            signature,
            sender_pubkey,
            hash: tx_hash,
            cached_size: None,
        }
    }

    pub fn estimated_size(&self) -> usize {
        128 + self.data.len()
    }
}

fn compute_signed_tx_hash(inner: &Transaction, sig: &Signature, pk: &PublicKey) -> Hash {
    let mut preimage = bincode::serialize(inner).expect("tx serialization");
    preimage.extend_from_slice(sig.as_bytes());
    preimage.extend_from_slice(pk.as_bytes());
    blake3_hash(&preimage)
}

/// Signed transaction ready for inclusion in a block.
/// Carries the sender's public key so signature can be independently verified
/// without an external key registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub inner: Transaction,
    pub signature: Signature,
    pub sender_pubkey: PublicKey,
    #[serde(skip)]
    pub hash: Hash,
    #[serde(skip)]
    pub cached_size: Option<usize>,
}

impl SignedTransaction {
    /// Transaction hash (unique identifier)
    pub fn tx_hash(&self) -> Hash {
        if self.hash != [0u8; 32] {
            return self.hash;
        }
        compute_signed_tx_hash(&self.inner, &self.signature, &self.sender_pubkey)
    }

    /// Recompute and cache the transaction hash (call after deserialization)
    pub fn recompute_hash(&mut self) {
        self.hash = compute_signed_tx_hash(&self.inner, &self.signature, &self.sender_pubkey);
    }

    /// Full cryptographic verification:
    /// 1. Derive address from embedded public key
    /// 2. Assert it matches the declared `from` field
    /// 3. Verify ECDSA signature against the signing hash
    pub fn verify(&self) -> Result<(), CoreError> {
        let derived_addr = self.sender_pubkey.to_address();
        if derived_addr != self.inner.from {
            return Err(CoreError::InvalidTransaction(format!(
                "sender mismatch: pubkey derives {} but from is {}",
                derived_addr, self.inner.from
            )));
        }
        let hash = self.inner.signing_hash();
        self.signature
            .verify_prehashed(&hash, &self.sender_pubkey)
            .map_err(|e| CoreError::InvalidTransaction(format!("signature verification: {e}")))
    }

    /// Verify against an externally provided public key
    pub fn verify_with_pubkey(&self, pubkey: &PublicKey) -> Result<(), CoreError> {
        let expected_addr = pubkey.to_address();
        if expected_addr != self.inner.from {
            return Err(CoreError::InvalidTransaction("address mismatch".into()));
        }
        let hash = self.inner.signing_hash();
        self.signature
            .verify_prehashed(&hash, pubkey)
            .map_err(|e| CoreError::InvalidTransaction(format!("signature: {e}")))
    }

    pub fn gas_cost(&self) -> u64 {
        self.inner.gas_limit.saturating_mul(self.inner.gas_price)
    }

    pub fn total_cost(&self) -> u64 {
        self.inner.value.saturating_add(self.gas_cost())
    }

    pub fn byte_size(&self) -> usize {
        if let Some(s) = self.cached_size {
            return s;
        }
        bincode::serialized_size(self).unwrap_or(256) as usize
    }

    pub fn sender(&self) -> Address {
        self.inner.from
    }

    pub fn nonce(&self) -> u64 {
        self.inner.nonce
    }

    pub fn effective_gas_price(&self) -> u64 {
        self.inner.gas_price
    }
}

impl PartialEq for SignedTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.tx_hash() == other.tx_hash()
    }
}
impl Eq for SignedTransaction {}

impl std::hash::Hash for SignedTransaction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.tx_hash().hash(state);
    }
}

/// Transaction receipt after execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub tx_hash: Hash,
    pub block_height: u64,
    pub index: u32,
    pub success: bool,
    pub gas_used: u64,
    pub logs: Vec<Log>,
    pub return_data: Vec<u8>,
}

/// Event log emitted during execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<Hash>,
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_tx(keypair: &KeyPair) -> SignedTransaction {
        let tx = Transaction {
            tx_type: TransactionType::Transfer,
            nonce: 0,
            from: keypair.address(),
            to: Address::ZERO,
            value: 1000,
            data: vec![],
            gas_limit: 21000,
            gas_price: 1,
            chain_id: 1,
        };
        tx.sign(keypair)
    }

    #[test]
    fn test_sign_and_verify_standalone() {
        let kp = KeyPair::generate();
        let stx = make_test_tx(&kp);
        assert!(stx.verify().is_ok(), "standalone verify must pass");
    }

    #[test]
    fn test_sign_and_verify_with_pubkey() {
        let kp = KeyPair::generate();
        let stx = make_test_tx(&kp);
        assert!(stx.verify_with_pubkey(&kp.public).is_ok());
    }

    #[test]
    fn test_verify_rejects_tampered_from() {
        let kp = KeyPair::generate();
        let mut stx = make_test_tx(&kp);
        stx.inner.from = Address::ZERO;
        assert!(stx.verify().is_err(), "tampered `from` must fail");
    }

    #[test]
    fn test_verify_rejects_wrong_pubkey() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let mut stx = make_test_tx(&kp1);
        stx.sender_pubkey = kp2.public.clone();
        assert!(stx.verify().is_err(), "wrong pubkey must fail");
    }

    #[test]
    fn test_tx_hash_deterministic() {
        let kp = KeyPair::generate();
        let stx = make_test_tx(&kp);
        let h1 = stx.tx_hash();
        let h2 = stx.tx_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_total_cost() {
        let kp = KeyPair::generate();
        let stx = make_test_tx(&kp);
        assert_eq!(stx.total_cost(), 1000 + 21000 * 1);
    }
}
