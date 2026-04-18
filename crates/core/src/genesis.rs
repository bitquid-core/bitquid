use std::collections::HashMap;

use bitquid_crypto::Address;
use serde::{Deserialize, Serialize};

use crate::account::Account;
use crate::block::Block;
use crate::state::WorldState;
use crate::ChainConfig;

/// Genesis configuration defining the initial state of the chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub chain_config: ChainConfig,
    pub alloc: HashMap<String, GenesisAllocation>,
    pub validators: Vec<ValidatorConfig>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAllocation {
    pub balance: u64,
    #[serde(default)]
    pub staked: u64,
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    pub address: String,
    pub pubkey: String,
    pub stake: u64,
}

impl GenesisConfig {
    pub fn build_state(&self) -> (WorldState, Block) {
        let mut state = WorldState::new();

        for (addr_hex, alloc) in &self.alloc {
            if let Ok(addr) = Address::from_hex(addr_hex) {
                let mut account = Account::new(alloc.balance);
                account.staked = alloc.staked;
                if let Some(code) = &alloc.code {
                    if let Ok(code_bytes) = hex::decode(code) {
                        state.set_code(&addr, code_bytes);
                    }
                }
                state.set_account(addr, account);
            }
        }

        // Set up validators
        for validator in &self.validators {
            if let Ok(addr) = Address::from_hex(&validator.address) {
                let account = state.get_or_create_account(&addr);
                account.add_balance(validator.stake);
                account.add_stake(validator.stake);
            }
        }

        let state_root = state.compute_state_root();
        let genesis_block = Block::genesis(self.chain_config.chain_id, state_root);

        (state, genesis_block)
    }

    /// Create a default development genesis for testing
    pub fn dev() -> Self {
        let mut alloc = HashMap::new();
        // Pre-fund development accounts
        for i in 1..=10 {
            alloc.insert(
                format!("0x{:040x}", i),
                GenesisAllocation {
                    balance: 1_000_000 * crate::ONE_BQF,
                    staked: 0,
                    code: None,
                },
            );
        }

        Self {
            chain_config: ChainConfig::dev(),
            alloc,
            validators: vec![
                ValidatorConfig {
                    address: "0x0000000000000000000000000000000000000001".into(),
                    pubkey: String::new(),
                    stake: 100_000 * crate::ONE_BQF,
                },
            ],
            timestamp: 0,
        }
    }
}
