use bitquid_crypto::{blake3_hash, Hash, ZERO_HASH};
use serde::{Deserialize, Serialize};

/// Account state in the world state trie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub nonce: u64,
    pub balance: u64,
    pub code_hash: Hash,
    pub storage_root: Hash,
    /// Staked amount (for validator nodes)
    pub staked: u64,
    /// Flag for contract accounts
    pub is_contract: bool,
}

impl Account {
    pub fn new(balance: u64) -> Self {
        Self {
            nonce: 0,
            balance,
            code_hash: ZERO_HASH,
            storage_root: ZERO_HASH,
            staked: 0,
            is_contract: false,
        }
    }

    pub fn new_contract(code: &[u8]) -> Self {
        Self {
            nonce: 0,
            balance: 0,
            code_hash: blake3_hash(code),
            storage_root: ZERO_HASH,
            staked: 0,
            is_contract: true,
        }
    }

    /// Hash of the entire account state
    pub fn state_hash(&self) -> Hash {
        let encoded = bincode::serialize(self).expect("account serialization cannot fail");
        blake3_hash(&encoded)
    }

    pub fn has_sufficient_balance(&self, amount: u64) -> bool {
        self.balance >= amount
    }

    pub fn available_balance(&self) -> u64 {
        self.balance.saturating_sub(self.staked)
    }

    pub fn increment_nonce(&mut self) {
        self.nonce = self.nonce.saturating_add(1);
    }

    pub fn add_balance(&mut self, amount: u64) {
        self.balance = self.balance.saturating_add(amount);
    }

    pub fn sub_balance(&mut self, amount: u64) -> bool {
        if self.balance >= amount {
            self.balance -= amount;
            true
        } else {
            false
        }
    }

    pub fn add_stake(&mut self, amount: u64) -> bool {
        if self.available_balance() >= amount {
            self.staked = self.staked.saturating_add(amount);
            true
        } else {
            false
        }
    }

    pub fn remove_stake(&mut self, amount: u64) -> bool {
        if self.staked >= amount {
            self.staked -= amount;
            true
        } else {
            false
        }
    }
}

impl Default for Account {
    fn default() -> Self {
        Self::new(0)
    }
}
