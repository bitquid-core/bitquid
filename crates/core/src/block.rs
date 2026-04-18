use bitquid_crypto::{blake3_hash, Address, Hash, Signature, ZERO_HASH};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::transaction::SignedTransaction;
use crate::MAX_BLOCK_SIZE;

/// Block header containing all metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub chain_id: u32,
    pub height: u64,
    pub timestamp: u64,
    pub prev_hash: Hash,
    pub state_root: Hash,
    pub transactions_root: Hash,
    pub receipts_root: Hash,
    /// Address of the block proposer
    pub proposer: Address,
    /// Number of transactions in the block
    pub tx_count: u32,
    /// Total gas used in this block
    pub gas_used: u64,
    /// Block gas limit
    pub gas_limit: u64,
    /// Extra data (up to 32 bytes for vanity / version info)
    pub extra_data: Vec<u8>,
    /// Block proposer's signature over the header hash
    pub signature: Signature,
}

impl BlockHeader {
    /// Compute the hash of this header (excluding signature)
    pub fn compute_hash(&self) -> Hash {
        let mut header_for_hash = self.clone();
        header_for_hash.signature = Signature::default();
        let encoded =
            bincode::serialize(&header_for_hash).expect("header serialization cannot fail");
        blake3_hash(&encoded)
    }

    /// Validate basic header constraints
    pub fn validate_basic(&self) -> Result<(), CoreError> {
        if self.extra_data.len() > 32 {
            return Err(CoreError::InvalidBlock("extra_data too large".into()));
        }
        if self.gas_used > self.gas_limit {
            return Err(CoreError::InvalidBlock(format!(
                "gas_used ({}) > gas_limit ({})",
                self.gas_used, self.gas_limit
            )));
        }
        if self.version == 0 {
            return Err(CoreError::InvalidBlock("version cannot be 0".into()));
        }
        Ok(())
    }

    pub fn is_genesis(&self) -> bool {
        self.height == 0 && self.prev_hash == ZERO_HASH
    }
}

/// Full block with header and transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<SignedTransaction>,
}

impl Block {
    /// Create a new block
    pub fn new(header: BlockHeader, transactions: Vec<SignedTransaction>) -> Self {
        Self {
            header,
            transactions,
        }
    }

    pub fn hash(&self) -> Hash {
        self.header.compute_hash()
    }

    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// Validate block structure (not state transitions)
    pub fn validate_structure(&self) -> Result<(), CoreError> {
        self.header.validate_basic()?;

        if self.header.tx_count as usize != self.transactions.len() {
            return Err(CoreError::InvalidBlock(format!(
                "tx_count mismatch: header says {}, body has {}",
                self.header.tx_count,
                self.transactions.len()
            )));
        }

        let tx_hashes: Vec<Hash> = self.transactions.iter().map(|tx| tx.tx_hash()).collect();
        let computed_root = bitquid_crypto::merkle::compute_merkle_root(&tx_hashes);
        if computed_root != self.header.transactions_root {
            return Err(CoreError::InvalidBlock(
                "transactions_root mismatch".into(),
            ));
        }

        let size = self.byte_size();
        if size > MAX_BLOCK_SIZE {
            return Err(CoreError::BlockTooLarge {
                size,
                max: MAX_BLOCK_SIZE,
            });
        }

        Ok(())
    }

    pub fn byte_size(&self) -> usize {
        bincode::serialized_size(self).unwrap_or(0) as usize
    }

    /// Create genesis block
    pub fn genesis(chain_id: u32, state_root: Hash) -> Self {
        let header = BlockHeader {
            version: 1,
            chain_id,
            height: 0,
            timestamp: 0,
            prev_hash: ZERO_HASH,
            state_root,
            transactions_root: ZERO_HASH,
            receipts_root: ZERO_HASH,
            proposer: Address::ZERO,
            tx_count: 0,
            gas_used: 0,
            gas_limit: 100_000_000,
            extra_data: b"Bitquid-Fi Genesis".to_vec(),
            signature: Signature::default(),
        };

        Self {
            header,
            transactions: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_block() {
        let block = Block::genesis(1, ZERO_HASH);
        assert!(block.header.is_genesis());
        assert_eq!(block.height(), 0);
        assert_eq!(block.transactions.len(), 0);
    }

    #[test]
    fn test_block_hash_deterministic() {
        let block = Block::genesis(1, ZERO_HASH);
        assert_eq!(block.hash(), block.hash());
    }

    #[test]
    fn test_genesis_validates() {
        let block = Block::genesis(1, ZERO_HASH);
        assert!(block.validate_structure().is_ok());
    }
}
