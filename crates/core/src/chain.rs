use serde::{Deserialize, Serialize};

/// Chain-wide configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub chain_id: u32,
    pub chain_name: String,
    /// Target block time in milliseconds
    pub block_time_ms: u64,
    /// Maximum gas per block
    pub block_gas_limit: u64,
    /// Minimum gas price (in smallest unit)
    pub min_gas_price: u64,
    /// Minimum validator stake
    pub min_validator_stake: u64,
    /// Maximum validators in the active set
    pub max_validators: usize,
    /// Number of blocks for finality checkpoint
    pub checkpoint_interval: u64,
    /// Enable DeFi runtime
    pub defi_enabled: bool,
    /// Maximum transaction size in bytes
    pub max_tx_size: usize,
    /// Block reward in smallest units (for the first halving era)
    pub initial_block_reward: u64,
    /// Maximum total supply in smallest units (hard cap)
    pub max_supply: u64,
    /// Number of blocks per halving era
    pub halving_interval: u64,
}

/// 21 million BQF maximum supply (in smallest units, 8 decimals)
pub const MAX_SUPPLY_DEFAULT: u64 = 21_000_000 * crate::ONE_BQF;

/// ~4 years of 2-second blocks: 4 * 365.25 * 24 * 3600 / 2 = 63,115,200
pub const HALVING_INTERVAL_DEFAULT: u64 = 63_115_200;

impl ChainConfig {
    pub fn mainnet() -> Self {
        Self {
            chain_id: 48_897,
            chain_name: "Bitquid-Fi Mainnet".into(),
            block_time_ms: 2_000,
            block_gas_limit: 100_000_000,
            min_gas_price: 1,
            min_validator_stake: 100_000 * crate::ONE_BQF,
            max_validators: 100,
            checkpoint_interval: 1000,
            defi_enabled: true,
            max_tx_size: 128 * 1024,
            initial_block_reward: 50 * crate::ONE_BQF,
            max_supply: MAX_SUPPLY_DEFAULT,
            halving_interval: HALVING_INTERVAL_DEFAULT,
        }
    }

    pub fn testnet() -> Self {
        Self {
            chain_id: 48_898,
            chain_name: "Bitquid-Fi Testnet".into(),
            block_time_ms: 1_000,
            block_gas_limit: 200_000_000,
            min_gas_price: 0,
            min_validator_stake: 1_000 * crate::ONE_BQF,
            max_validators: 21,
            checkpoint_interval: 100,
            defi_enabled: true,
            max_tx_size: 256 * 1024,
            initial_block_reward: 100 * crate::ONE_BQF,
            max_supply: MAX_SUPPLY_DEFAULT,
            halving_interval: 10_000,
        }
    }

    pub fn dev() -> Self {
        Self {
            chain_id: 1337,
            chain_name: "Bitquid-Fi Dev".into(),
            block_time_ms: 500,
            block_gas_limit: 500_000_000,
            min_gas_price: 0,
            min_validator_stake: 100 * crate::ONE_BQF,
            max_validators: 4,
            checkpoint_interval: 10,
            defi_enabled: true,
            max_tx_size: 1024 * 1024,
            initial_block_reward: 500 * crate::ONE_BQF,
            max_supply: MAX_SUPPLY_DEFAULT,
            halving_interval: 1_000,
        }
    }

    /// Compute the block reward for a given height, applying halving schedule.
    /// Returns 0 once the cumulative issuance would exceed `max_supply`.
    pub fn block_reward_at_height(&self, height: u64, total_minted_so_far: u64) -> u64 {
        if total_minted_so_far >= self.max_supply {
            return 0;
        }

        let era = height / self.halving_interval;
        if era >= 64 {
            return 0;
        }

        let reward = self.initial_block_reward >> era;
        if reward == 0 {
            return 0;
        }

        let remaining = self.max_supply.saturating_sub(total_minted_so_far);
        reward.min(remaining)
    }

    /// PBFT requires 3f+1 validators for f Byzantine faults
    pub fn max_byzantine_faults(&self) -> usize {
        (self.max_validators.saturating_sub(1)) / 3
    }

    pub fn quorum_size(&self) -> usize {
        2 * self.max_byzantine_faults() + 1
    }
}
