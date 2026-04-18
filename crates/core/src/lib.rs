pub mod block;
pub mod transaction;
pub mod account;
pub mod state;
pub mod genesis;
pub mod chain;
pub mod error;

pub use block::{Block, BlockHeader};
pub use transaction::{Transaction, TransactionType, SignedTransaction};
pub use account::Account;
pub use state::WorldState;
pub use genesis::GenesisConfig;
pub use chain::{ChainConfig, MAX_SUPPLY_DEFAULT, HALVING_INTERVAL_DEFAULT};
pub use error::CoreError;

pub use bitquid_crypto::{Hash, Address, ZERO_HASH};

/// Satoshi-like denomination: 1 BQF = 10^8 units
pub const BQF_DECIMALS: u32 = 8;
pub const ONE_BQF: u64 = 100_000_000;

/// Maximum block size in bytes
pub const MAX_BLOCK_SIZE: usize = 4 * 1024 * 1024; // 4 MB

/// Target block time in milliseconds
pub const TARGET_BLOCK_TIME_MS: u64 = 2_000; // 2 seconds

/// Maximum transactions per block
pub const MAX_TXS_PER_BLOCK: usize = 10_000;
