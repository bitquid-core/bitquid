use bitquid_core::Address;
use bitquid_crypto::PublicKey;
use serde::{Deserialize, Serialize};

/// A validator in the consensus protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub address: Address,
    pub public_key: PublicKey,
    pub stake: u64,
    pub is_active: bool,
}

/// Manages the active validator set
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    quorum_size: usize,
}

impl ValidatorSet {
    pub fn new(validators: Vec<Validator>) -> Self {
        let n = validators.iter().filter(|v| v.is_active).count();
        let f = n.saturating_sub(1) / 3;
        let quorum_size = 2 * f + 1;

        Self {
            validators,
            quorum_size,
        }
    }

    pub fn get_by_address(&self, addr: &Address) -> Option<&Validator> {
        self.validators.iter().find(|v| v.address == *addr)
    }

    pub fn get_pubkey(&self, addr: &Address) -> Option<&PublicKey> {
        self.get_by_address(addr).map(|v| &v.public_key)
    }

    pub fn is_validator(&self, addr: &Address) -> bool {
        self.validators.iter().any(|v| v.address == *addr && v.is_active)
    }

    /// Get the leader for a given view number (round-robin).
    /// Returns the first validator (or a default) if no active validators exist.
    pub fn leader_for_view(&self, view: u64) -> &Validator {
        let active: Vec<&Validator> = self.active_validators();
        if active.is_empty() {
            return self.validators.first().expect("validator set must not be empty");
        }
        let idx = (view as usize) % active.len();
        active[idx]
    }

    pub fn active_validators(&self) -> Vec<&Validator> {
        self.validators.iter().filter(|v| v.is_active).collect()
    }

    pub fn quorum_size(&self) -> usize {
        self.quorum_size
    }

    /// Total number of active validators
    pub fn active_count(&self) -> usize {
        self.validators.iter().filter(|v| v.is_active).count()
    }

    /// Maximum tolerable Byzantine faults
    pub fn max_faults(&self) -> usize {
        (self.active_count().saturating_sub(1)) / 3
    }

    pub fn total_stake(&self) -> u64 {
        self.validators
            .iter()
            .filter(|v| v.is_active)
            .map(|v| v.stake)
            .fold(0u64, |acc, s| acc.saturating_add(s))
    }

    pub fn add_validator(&mut self, validator: Validator) {
        if !self.is_validator(&validator.address) {
            self.validators.push(validator);
            self.recalculate_quorum();
        }
    }

    pub fn remove_validator(&mut self, addr: &Address) {
        self.validators.retain(|v| v.address != *addr);
        self.recalculate_quorum();
    }

    fn recalculate_quorum(&mut self) {
        let n = self.active_count();
        let f = n.saturating_sub(1) / 3;
        self.quorum_size = 2 * f + 1;
    }
}
