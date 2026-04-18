pub mod error;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use bitquid_core::transaction::SignedTransaction;
use bitquid_core::{Address, Hash};
use parking_lot::RwLock;
use tracing::debug;

pub use error::MempoolError;

/// Transaction ordering key: (gas_price descending, nonce ascending)
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct TxOrderKey {
    neg_gas_price: i128,
    nonce: u64,
    hash: Hash,
}

/// High-performance transaction mempool with priority ordering
pub struct Mempool {
    inner: Arc<RwLock<MempoolInner>>,
    config: MempoolConfig,
}

struct MempoolInner {
    ordered: BTreeMap<TxOrderKey, SignedTransaction>,
    by_hash: HashMap<Hash, TxOrderKey>,
    by_sender: HashMap<Address, BTreeMap<u64, Hash>>,
    rejected: BloomFilter,
    total_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct MempoolConfig {
    pub max_txs: usize,
    pub max_bytes: usize,
    pub max_per_sender: usize,
    /// Expected number of rejected hashes the bloom filter should hold
    pub max_rejected: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_txs: 50_000,
            max_bytes: 256 * 1024 * 1024,
            max_per_sender: 100,
            max_rejected: 100_000,
        }
    }
}

// ── Bloom filter ──

/// A space-efficient probabilistic set built for fast rejection of known-bad
/// transaction hashes.  Uses k=7 independent hash functions mapped from the
/// 32-byte transaction hash via byte-pair folding (no extra hashing needed).
struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
    count: usize,
    capacity: usize,
}

const BLOOM_K: usize = 7;

impl BloomFilter {
    fn new(expected_items: usize) -> Self {
        let num_bits = optimal_bits(expected_items, 0.01).max(512);
        let words = (num_bits + 63) / 64;
        Self {
            bits: vec![0u64; words],
            num_bits,
            count: 0,
            capacity: expected_items,
        }
    }

    fn insert(&mut self, hash: &Hash) {
        for i in 0..BLOOM_K {
            let idx = self.hash_index(hash, i);
            let word = idx / 64;
            let bit = idx % 64;
            self.bits[word] |= 1u64 << bit;
        }
        self.count += 1;

        if self.count > self.capacity * 2 {
            self.reset();
        }
    }

    fn contains(&self, hash: &Hash) -> bool {
        for i in 0..BLOOM_K {
            let idx = self.hash_index(hash, i);
            let word = idx / 64;
            let bit = idx % 64;
            if self.bits[word] & (1u64 << bit) == 0 {
                return false;
            }
        }
        true
    }

    fn reset(&mut self) {
        self.bits.fill(0);
        self.count = 0;
    }

    #[inline]
    fn hash_index(&self, hash: &Hash, k: usize) -> usize {
        let offset = (k * 4) % 28;
        let val = u32::from_le_bytes([
            hash[offset],
            hash[offset + 1],
            hash[offset + 2],
            hash[offset + 3],
        ]);
        val as usize % self.num_bits
    }
}

fn optimal_bits(n: usize, fp_rate: f64) -> usize {
    let ln2 = std::f64::consts::LN_2;
    let m = -(n as f64 * fp_rate.ln()) / (ln2 * ln2);
    m.ceil() as usize
}

// ── Mempool impl ──

impl Mempool {
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(MempoolInner {
                ordered: BTreeMap::new(),
                by_hash: HashMap::new(),
                by_sender: HashMap::new(),
                rejected: BloomFilter::new(config.max_rejected),
                total_bytes: 0,
            })),
            config,
        }
    }

    pub fn insert(&self, tx: SignedTransaction) -> Result<(), MempoolError> {
        let tx_hash = tx.tx_hash();
        let tx_size = tx.byte_size();
        let sender = tx.sender();

        let mut inner = self.inner.write();

        if inner.by_hash.contains_key(&tx_hash) {
            return Err(MempoolError::DuplicateTransaction);
        }

        if inner.rejected.contains(&tx_hash) {
            return Err(MempoolError::PreviouslyRejected);
        }

        if let Some(sender_txs) = inner.by_sender.get(&sender) {
            if sender_txs.len() >= self.config.max_per_sender {
                return Err(MempoolError::SenderLimitReached);
            }
        }

        if inner.ordered.len() >= self.config.max_txs
            || inner.total_bytes + tx_size > self.config.max_bytes
        {
            self.evict_lowest(&mut inner);
        }

        if inner.ordered.len() >= self.config.max_txs {
            return Err(MempoolError::PoolFull);
        }

        let key = TxOrderKey {
            neg_gas_price: -(tx.effective_gas_price() as i128),
            nonce: tx.nonce(),
            hash: tx_hash,
        };

        let tx_nonce = key.nonce;
        inner.ordered.insert(key.clone(), tx);
        inner.by_hash.insert(tx_hash, key);
        inner
            .by_sender
            .entry(sender)
            .or_default()
            .insert(tx_nonce, tx_hash);
        inner.total_bytes += tx_size;

        debug!("Mempool: added tx {}", hex::encode(&tx_hash[..8]));
        Ok(())
    }

    pub fn remove(&self, tx_hash: &Hash) -> Option<SignedTransaction> {
        let mut inner = self.inner.write();
        self.remove_inner(&mut inner, tx_hash)
    }

    fn remove_inner(
        &self,
        inner: &mut MempoolInner,
        tx_hash: &Hash,
    ) -> Option<SignedTransaction> {
        let key = inner.by_hash.remove(tx_hash)?;
        let tx = inner.ordered.remove(&key)?;
        inner.total_bytes = inner.total_bytes.saturating_sub(tx.byte_size());

        let sender = tx.sender();
        if let Some(sender_txs) = inner.by_sender.get_mut(&sender) {
            sender_txs.retain(|_, h| h != tx_hash);
            if sender_txs.is_empty() {
                inner.by_sender.remove(&sender);
            }
        }

        Some(tx)
    }

    fn evict_lowest(&self, inner: &mut MempoolInner) {
        if let Some((key, _)) = inner.ordered.iter().next_back() {
            let key = key.clone();
            let hash = key.hash;
            if let Some(tx) = inner.ordered.remove(&key) {
                inner.by_hash.remove(&hash);
                inner.total_bytes = inner.total_bytes.saturating_sub(tx.byte_size());
                let sender = tx.sender();
                if let Some(sender_txs) = inner.by_sender.get_mut(&sender) {
                    sender_txs.retain(|_, h| *h != hash);
                }
                debug!("Mempool: evicted tx {}", hex::encode(&hash[..8]));
            }
        }
    }

    pub fn pending_transactions(&self, max_count: usize, max_gas: u64) -> Vec<SignedTransaction> {
        let inner = self.inner.read();
        let mut result = Vec::with_capacity(max_count.min(inner.ordered.len()));
        let mut gas_used: u64 = 0;

        for (_, tx) in inner.ordered.iter() {
            if result.len() >= max_count {
                break;
            }
            let tx_gas = tx.inner.gas_limit;
            if gas_used.saturating_add(tx_gas) > max_gas {
                continue;
            }
            gas_used = gas_used.saturating_add(tx_gas);
            result.push(tx.clone());
        }

        result
    }

    pub fn remove_committed(&self, tx_hashes: &[Hash]) {
        let mut inner = self.inner.write();
        for hash in tx_hashes {
            self.remove_inner(&mut inner, hash);
        }
    }

    pub fn reject(&self, tx_hash: Hash) {
        let mut inner = self.inner.write();
        self.remove_inner(&mut inner, &tx_hash);
        inner.rejected.insert(&tx_hash);
    }

    pub fn contains(&self, tx_hash: &Hash) -> bool {
        self.inner.read().by_hash.contains_key(tx_hash)
    }

    pub fn len(&self) -> usize {
        self.inner.read().ordered.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().ordered.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.inner.read().total_bytes
    }

    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.ordered.clear();
        inner.by_hash.clear();
        inner.by_sender.clear();
        inner.total_bytes = 0;
    }

    pub fn stats(&self) -> MempoolStats {
        let inner = self.inner.read();
        MempoolStats {
            tx_count: inner.ordered.len(),
            total_bytes: inner.total_bytes,
            sender_count: inner.by_sender.len(),
            rejected_count: inner.rejected.count,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MempoolStats {
    pub tx_count: usize,
    pub total_bytes: usize,
    pub sender_count: usize,
    pub rejected_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitquid_core::transaction::{Transaction, TransactionType};
    use bitquid_crypto::KeyPair;

    fn make_tx(kp: &KeyPair, nonce: u64, gas_price: u64) -> SignedTransaction {
        Transaction {
            tx_type: TransactionType::Transfer,
            nonce,
            from: kp.address(),
            to: Address::ZERO,
            value: 100,
            data: vec![],
            gas_limit: 21000,
            gas_price,
            chain_id: 1,
        }
        .sign(kp)
    }

    #[test]
    fn test_insert_and_retrieve() {
        let pool = Mempool::new(MempoolConfig::default());
        let kp = KeyPair::generate();
        let tx = make_tx(&kp, 0, 10);
        pool.insert(tx).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_duplicate_rejection() {
        let pool = Mempool::new(MempoolConfig::default());
        let kp = KeyPair::generate();
        let tx = make_tx(&kp, 0, 10);
        pool.insert(tx.clone()).unwrap();
        assert!(pool.insert(tx).is_err());
    }

    #[test]
    fn test_pending_transactions_ordered() {
        let pool = Mempool::new(MempoolConfig::default());
        let kp = KeyPair::generate();

        pool.insert(make_tx(&kp, 0, 1)).unwrap();
        pool.insert(make_tx(&kp, 1, 100)).unwrap();
        pool.insert(make_tx(&kp, 2, 50)).unwrap();

        let pending = pool.pending_transactions(10, u64::MAX);
        assert_eq!(pending.len(), 3);
        assert!(pending[0].effective_gas_price() >= pending[1].effective_gas_price());
    }

    #[test]
    fn test_remove() {
        let pool = Mempool::new(MempoolConfig::default());
        let kp = KeyPair::generate();
        let tx = make_tx(&kp, 0, 10);
        let hash = tx.tx_hash();
        pool.insert(tx).unwrap();
        assert!(pool.remove(&hash).is_some());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_bloom_filter_basic() {
        let mut bf = BloomFilter::new(1000);
        let hash1: Hash = [1u8; 32];
        let hash2: Hash = [2u8; 32];

        assert!(!bf.contains(&hash1));
        bf.insert(&hash1);
        assert!(bf.contains(&hash1));
        assert!(!bf.contains(&hash2));
    }

    #[test]
    fn test_reject_via_bloom() {
        let pool = Mempool::new(MempoolConfig::default());
        let kp = KeyPair::generate();
        let tx = make_tx(&kp, 0, 10);
        let hash = tx.tx_hash();

        pool.insert(tx.clone()).unwrap();
        pool.reject(hash);

        assert!(pool.is_empty());
        assert!(pool.insert(tx).is_err());
    }

    #[test]
    fn test_bloom_filter_auto_reset() {
        let mut bf = BloomFilter::new(10);
        for i in 0..30u8 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            bf.insert(&hash);
        }
        assert!(bf.count < 30, "bloom should have auto-reset");
    }
}
