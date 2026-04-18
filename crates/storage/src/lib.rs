pub mod error;

use std::path::Path;
use std::sync::Arc;

use bitquid_core::{Account, Block, Hash, Address};
use bitquid_core::transaction::TransactionReceipt;
use parking_lot::RwLock;
use serde::{de::DeserializeOwned, Serialize};
use tracing::{debug, info};

pub use error::StorageError;

const BLOCKS_TREE: &str = "blocks";
const BLOCK_INDEX_TREE: &str = "block_index";
const ACCOUNTS_TREE: &str = "accounts";
const TX_TREE: &str = "transactions";
const TX_RECEIPTS_TREE: &str = "tx_receipts";
const META_TREE: &str = "meta";
const STATE_TREE: &str = "state";

/// Persistent storage engine backed by sled (embedded, pure-Rust)
pub struct Storage {
    db: sled::Db,
    blocks: sled::Tree,
    block_index: sled::Tree,
    accounts: sled::Tree,
    transactions: sled::Tree,
    receipts: sled::Tree,
    meta: sled::Tree,
    state: sled::Tree,
    latest_height: Arc<RwLock<u64>>,
}

impl Storage {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        info!("Opening storage at {}", path.display());

        let db = sled::Config::new()
            .path(path)
            .cache_capacity(256 * 1024 * 1024) // 256MB cache
            .flush_every_ms(Some(1000))
            .mode(sled::Mode::HighThroughput)
            .open()
            .map_err(StorageError::Sled)?;

        let blocks = db.open_tree(BLOCKS_TREE).map_err(StorageError::Sled)?;
        let block_index = db.open_tree(BLOCK_INDEX_TREE).map_err(StorageError::Sled)?;
        let accounts = db.open_tree(ACCOUNTS_TREE).map_err(StorageError::Sled)?;
        let transactions = db.open_tree(TX_TREE).map_err(StorageError::Sled)?;
        let receipts = db.open_tree(TX_RECEIPTS_TREE).map_err(StorageError::Sled)?;
        let meta = db.open_tree(META_TREE).map_err(StorageError::Sled)?;
        let state = db.open_tree(STATE_TREE).map_err(StorageError::Sled)?;

        let latest_height = meta
            .get(b"latest_height")
            .map_err(StorageError::Sled)?
            .map(|v| {
                let bytes: [u8; 8] = v.as_ref().try_into().unwrap_or([0; 8]);
                u64::from_be_bytes(bytes)
            })
            .unwrap_or(0);

        info!("Storage opened, latest height: {latest_height}");

        Ok(Self {
            db,
            blocks,
            block_index,
            accounts,
            transactions,
            receipts,
            meta,
            state,
            latest_height: Arc::new(RwLock::new(latest_height)),
        })
    }

    /// Open an in-memory storage (for testing)
    pub fn open_temporary() -> Result<Self, StorageError> {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .map_err(StorageError::Sled)?;

        let blocks = db.open_tree(BLOCKS_TREE).map_err(StorageError::Sled)?;
        let block_index = db.open_tree(BLOCK_INDEX_TREE).map_err(StorageError::Sled)?;
        let accounts = db.open_tree(ACCOUNTS_TREE).map_err(StorageError::Sled)?;
        let transactions = db.open_tree(TX_TREE).map_err(StorageError::Sled)?;
        let receipts = db.open_tree(TX_RECEIPTS_TREE).map_err(StorageError::Sled)?;
        let meta = db.open_tree(META_TREE).map_err(StorageError::Sled)?;
        let state = db.open_tree(STATE_TREE).map_err(StorageError::Sled)?;

        Ok(Self {
            db,
            blocks,
            block_index,
            accounts,
            transactions,
            receipts,
            meta,
            state,
            latest_height: Arc::new(RwLock::new(0)),
        })
    }

    // ── Block operations ──

    pub fn put_block(&self, block: &Block) -> Result<(), StorageError> {
        let height = block.height();
        let hash = block.hash();

        let encoded = serialize(block)?;
        let height_key = height.to_be_bytes();

        self.blocks.insert(&hash, encoded.as_slice()).map_err(StorageError::Sled)?;
        self.block_index.insert(&height_key, &hash).map_err(StorageError::Sled)?;

        // Index transactions
        for (i, tx) in block.transactions.iter().enumerate() {
            let tx_hash = tx.tx_hash();
            let tx_loc = TxLocation {
                block_hash: hash,
                block_height: height,
                index: i as u32,
            };
            let loc_bytes = serialize(&tx_loc)?;
            self.transactions.insert(&tx_hash, loc_bytes.as_slice()).map_err(StorageError::Sled)?;
        }

        // Update latest height
        let mut latest = self.latest_height.write();
        if height > *latest {
            *latest = height;
            self.meta
                .insert(b"latest_height", &height.to_be_bytes())
                .map_err(StorageError::Sled)?;
        }

        debug!("Stored block #{height} hash={}", hex::encode(&hash[..8]));
        Ok(())
    }

    pub fn get_block_by_hash(&self, hash: &Hash) -> Result<Option<Block>, StorageError> {
        match self.blocks.get(hash).map_err(StorageError::Sled)? {
            Some(bytes) => Ok(Some(deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, StorageError> {
        let height_key = height.to_be_bytes();
        match self.block_index.get(&height_key).map_err(StorageError::Sled)? {
            Some(hash_bytes) => {
                if hash_bytes.len() != 32 {
                    return Err(StorageError::Corruption(format!(
                        "block index at height {height}: expected 32 bytes, got {}",
                        hash_bytes.len()
                    )));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hash_bytes);
                self.get_block_by_hash(&hash)
            }
            None => Ok(None),
        }
    }

    pub fn get_block_hash_by_height(&self, height: u64) -> Result<Option<Hash>, StorageError> {
        let key = height.to_be_bytes();
        match self.block_index.get(&key).map_err(StorageError::Sled)? {
            Some(bytes) => {
                if bytes.len() != 32 {
                    return Err(StorageError::Corruption(format!(
                        "block hash at height: expected 32 bytes, got {}",
                        bytes.len()
                    )));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    pub fn latest_height(&self) -> u64 {
        *self.latest_height.read()
    }

    pub fn latest_block(&self) -> Result<Option<Block>, StorageError> {
        self.get_block_by_height(self.latest_height())
    }

    // ── Account operations ──

    pub fn put_account(&self, addr: &Address, account: &Account) -> Result<(), StorageError> {
        let encoded = serialize(account)?;
        self.accounts.insert(addr.as_bytes(), encoded.as_slice()).map_err(StorageError::Sled)?;
        Ok(())
    }

    pub fn get_account(&self, addr: &Address) -> Result<Option<Account>, StorageError> {
        match self.accounts.get(addr.as_bytes()).map_err(StorageError::Sled)? {
            Some(bytes) => Ok(Some(deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    // ── Transaction operations ──

    pub fn get_tx_location(&self, tx_hash: &Hash) -> Result<Option<TxLocation>, StorageError> {
        match self.transactions.get(tx_hash).map_err(StorageError::Sled)? {
            Some(bytes) => Ok(Some(deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_receipt(&self, receipt: &TransactionReceipt) -> Result<(), StorageError> {
        let encoded = serialize(receipt)?;
        self.receipts.insert(&receipt.tx_hash, encoded.as_slice()).map_err(StorageError::Sled)?;
        Ok(())
    }

    pub fn get_receipt(&self, tx_hash: &Hash) -> Result<Option<TransactionReceipt>, StorageError> {
        match self.receipts.get(tx_hash).map_err(StorageError::Sled)? {
            Some(bytes) => Ok(Some(deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    // ── State key-value storage ──

    pub fn state_put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.state.insert(key, value).map_err(StorageError::Sled)?;
        Ok(())
    }

    pub fn state_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.state.get(key).map_err(StorageError::Sled)?.map(|v| v.to_vec()))
    }

    // ── Maintenance ──

    pub fn flush(&self) -> Result<(), StorageError> {
        self.db.flush().map_err(StorageError::Sled)?;
        Ok(())
    }

    pub fn size_on_disk(&self) -> u64 {
        self.db.size_on_disk().unwrap_or(0)
    }

    /// Prune full block bodies below the given height.
    /// Re-stores each block with an empty transaction list to reclaim space
    /// while keeping the header chain intact for verification.
    /// Returns the number of blocks pruned.
    pub fn prune_below(&self, height: u64) -> Result<u64, StorageError> {
        let mut pruned = 0u64;
        for h in 0..height {
            let key = h.to_be_bytes();
            let hash = match self.block_index.get(&key).map_err(StorageError::Sled)? {
                Some(v) => {
                    if v.len() != 32 {
                        continue;
                    }
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&v);
                    hash
                }
                None => continue,
            };

            let block_bytes = match self.blocks.get(&hash).map_err(StorageError::Sled)? {
                Some(b) => b,
                None => continue,
            };

            let mut block: Block =
                deserialize(&block_bytes).map_err(|e| StorageError::Corruption(e.to_string()))?;

            if block.transactions.is_empty() {
                continue;
            }

            // Remove individual transaction index entries
            for tx in &block.transactions {
                let tx_hash = tx.tx_hash();
                let _ = self.transactions.remove(&tx_hash);
            }

            // Re-store block with empty body (header-only)
            block.transactions = Vec::new();
            let encoded = serialize(&block)?;
            self.blocks
                .insert(&hash, encoded.as_slice())
                .map_err(StorageError::Sled)?;

            pruned += 1;
        }

        if pruned > 0 {
            info!("Pruned {pruned} block bodies below height {height}");
        }
        Ok(pruned)
    }
}

/// Transaction location index entry
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxLocation {
    pub block_hash: Hash,
    pub block_height: u64,
    pub index: u32,
}

fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, StorageError> {
    bincode::serialize(value).map_err(|e| StorageError::Serialization(e.to_string()))
}

fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, StorageError> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Deserialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitquid_core::block::Block;
    use bitquid_core::ZERO_HASH;

    #[test]
    fn test_block_storage_roundtrip() {
        let storage = Storage::open_temporary().unwrap();
        let block = Block::genesis(1, ZERO_HASH);
        let hash = block.hash();

        storage.put_block(&block).unwrap();

        let retrieved = storage.get_block_by_hash(&hash).unwrap().unwrap();
        assert_eq!(retrieved.height(), 0);

        let by_height = storage.get_block_by_height(0).unwrap().unwrap();
        assert_eq!(by_height.hash(), hash);
    }

    #[test]
    fn test_account_storage_roundtrip() {
        let storage = Storage::open_temporary().unwrap();
        let addr = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let account = Account::new(42);

        storage.put_account(&addr, &account).unwrap();

        let retrieved = storage.get_account(&addr).unwrap().unwrap();
        assert_eq!(retrieved.balance, 42);
    }

    #[test]
    fn test_latest_height() {
        let storage = Storage::open_temporary().unwrap();
        assert_eq!(storage.latest_height(), 0);

        let block = Block::genesis(1, ZERO_HASH);
        storage.put_block(&block).unwrap();
        assert_eq!(storage.latest_height(), 0);
    }
}
