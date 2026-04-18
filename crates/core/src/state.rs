use std::collections::HashMap;

use bitquid_crypto::{blake3_hash, Address, Hash, ZERO_HASH};

use crate::account::Account;
use crate::chain::ChainConfig;
use crate::error::CoreError;
use crate::transaction::{SignedTransaction, TransactionReceipt, TransactionType};

/// In-memory world state (backed by storage layer for persistence)
#[derive(Debug, Clone)]
pub struct WorldState {
    accounts: HashMap<Address, Account>,
    /// Contract storage: address -> (key -> value)
    storage: HashMap<Address, HashMap<Hash, Vec<u8>>>,
    /// Contract code: code_hash -> bytecode
    code: HashMap<Hash, Vec<u8>>,
    /// Cumulative block rewards minted (for supply cap enforcement)
    minted: u64,
    /// Token allowances: (owner, spender) -> amount
    allowances: HashMap<(Address, Address), u64>,
}

impl WorldState {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            storage: HashMap::new(),
            code: HashMap::new(),
            minted: 0,
            allowances: HashMap::new(),
        }
    }

    pub fn total_minted(&self) -> u64 {
        self.minted
    }

    pub fn add_minted(&mut self, amount: u64) {
        self.minted = self.minted.saturating_add(amount);
    }

    pub fn get_account(&self, addr: &Address) -> Option<&Account> {
        self.accounts.get(addr)
    }

    pub fn get_account_mut(&mut self, addr: &Address) -> Option<&mut Account> {
        self.accounts.get_mut(addr)
    }

    pub fn get_or_create_account(&mut self, addr: &Address) -> &mut Account {
        self.accounts.entry(*addr).or_insert_with(Account::default)
    }

    pub fn set_account(&mut self, addr: Address, account: Account) {
        self.accounts.insert(addr, account);
    }

    pub fn account_exists(&self, addr: &Address) -> bool {
        self.accounts.contains_key(addr)
    }

    pub fn get_balance(&self, addr: &Address) -> u64 {
        self.accounts.get(addr).map(|a| a.balance).unwrap_or(0)
    }

    pub fn get_nonce(&self, addr: &Address) -> u64 {
        self.accounts.get(addr).map(|a| a.nonce).unwrap_or(0)
    }

    /// Store contract code
    pub fn set_code(&mut self, addr: &Address, code: Vec<u8>) {
        let code_hash = blake3_hash(&code);
        if let Some(account) = self.accounts.get_mut(addr) {
            account.code_hash = code_hash;
            account.is_contract = true;
        }
        self.code.insert(code_hash, code);
    }

    pub fn get_code(&self, addr: &Address) -> Option<&[u8]> {
        let account = self.accounts.get(addr)?;
        self.code.get(&account.code_hash).map(|c| c.as_slice())
    }

    pub fn get_allowance(&self, owner: &Address, spender: &Address) -> u64 {
        self.allowances.get(&(*owner, *spender)).copied().unwrap_or(0)
    }

    pub fn set_allowance(&mut self, owner: Address, spender: Address, amount: u64) {
        if amount == 0 {
            self.allowances.remove(&(owner, spender));
        } else {
            self.allowances.insert((owner, spender), amount);
        }
    }

    /// Contract storage operations
    pub fn storage_get(&self, addr: &Address, key: &Hash) -> Option<&Vec<u8>> {
        self.storage.get(addr)?.get(key)
    }

    pub fn storage_set(&mut self, addr: &Address, key: Hash, value: Vec<u8>) {
        self.storage
            .entry(*addr)
            .or_default()
            .insert(key, value);
    }

    /// Compute the state root hash (Merkle root of all account hashes)
    pub fn compute_state_root(&self) -> Hash {
        if self.accounts.is_empty() {
            return ZERO_HASH;
        }

        let mut account_hashes: Vec<Hash> = self
            .accounts
            .iter()
            .map(|(addr, account)| {
                let mut data = addr.0.to_vec();
                data.extend_from_slice(&account.state_hash());
                blake3_hash(&data)
            })
            .collect();

        account_hashes.sort();
        bitquid_crypto::merkle::compute_merkle_root(&account_hashes)
    }

    /// Apply a transaction and return a receipt.
    pub fn apply_transaction(
        &mut self,
        tx: &SignedTransaction,
        block_height: u64,
        tx_index: u32,
        _chain_config: &ChainConfig,
    ) -> Result<TransactionReceipt, CoreError> {
        let sender = tx.sender();
        let _gas_cost = tx.gas_cost();
        let base_gas: u64 = 21_000;

        // Validate nonce
        let expected_nonce = self.get_nonce(&sender);
        if tx.nonce() != expected_nonce {
            return Err(CoreError::NonceMismatch {
                expected: expected_nonce,
                got: tx.nonce(),
            });
        }

        // Validate balance
        let total_cost = tx.total_cost();
        let balance = self.get_balance(&sender);
        if balance < total_cost {
            return Err(CoreError::InsufficientBalance {
                need: total_cost,
                have: balance,
            });
        }

        let (success, gas_used, logs, return_data) = match tx.inner.tx_type {
            TransactionType::Transfer => {
                self.execute_transfer(&sender, &tx.inner.to, tx.inner.value)?;
                (true, base_gas, vec![], vec![])
            }
            TransactionType::Stake => {
                self.execute_stake(&sender, tx.inner.value)?;
                (true, base_gas, vec![], vec![])
            }
            TransactionType::Unstake => {
                self.execute_unstake(&sender, tx.inner.value)?;
                (true, base_gas, vec![], vec![])
            }
            _ => {
                return Err(CoreError::InvalidStateTransition(format!(
                    "tx type {:?} requires BlockExecutor (runtime)",
                    tx.inner.tx_type
                )));
            }
        };

        // Charge gas
        {
            let sender_account = self.get_or_create_account(&sender);
            let gas_fee = gas_used.saturating_mul(tx.inner.gas_price);
            sender_account.sub_balance(gas_fee);
            sender_account.increment_nonce();
        }

        Ok(TransactionReceipt {
            tx_hash: tx.tx_hash(),
            block_height,
            index: tx_index,
            success,
            gas_used,
            logs,
            return_data,
        })
    }

    pub fn execute_transfer(
        &mut self,
        from: &Address,
        to: &Address,
        value: u64,
    ) -> Result<(), CoreError> {
        if value == 0 {
            return Ok(());
        }

        let from_balance = self.get_balance(from);
        if from_balance < value {
            return Err(CoreError::InsufficientBalance {
                need: value,
                have: from_balance,
            });
        }

        self.get_or_create_account(from).sub_balance(value);
        self.get_or_create_account(to).add_balance(value);
        Ok(())
    }

    pub fn execute_stake(&mut self, addr: &Address, amount: u64) -> Result<(), CoreError> {
        let account = self
            .accounts
            .get_mut(addr)
            .ok_or_else(|| CoreError::AccountNotFound(addr.to_hex()))?;

        if !account.add_stake(amount) {
            return Err(CoreError::InsufficientBalance {
                need: amount,
                have: account.available_balance(),
            });
        }
        Ok(())
    }

    pub fn execute_unstake(&mut self, addr: &Address, amount: u64) -> Result<(), CoreError> {
        let account = self
            .accounts
            .get_mut(addr)
            .ok_or_else(|| CoreError::AccountNotFound(addr.to_hex()))?;

        if !account.remove_stake(amount) {
            return Err(CoreError::InvalidStateTransition(
                "insufficient staked amount".into(),
            ));
        }
        Ok(())
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Snapshot current state for rollback
    pub fn snapshot(&self) -> WorldState {
        self.clone()
    }
}

impl Default for WorldState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;

    #[test]
    fn test_transfer() {
        let mut state = WorldState::new();
        let alice = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let bob = Address::from_hex("0x0000000000000000000000000000000000000002").unwrap();

        state.set_account(alice, Account::new(1000));
        state.set_account(bob, Account::new(0));

        state.execute_transfer(&alice, &bob, 500).unwrap();

        assert_eq!(state.get_balance(&alice), 500);
        assert_eq!(state.get_balance(&bob), 500);
    }

    #[test]
    fn test_insufficient_transfer() {
        let mut state = WorldState::new();
        let alice = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let bob = Address::from_hex("0x0000000000000000000000000000000000000002").unwrap();

        state.set_account(alice, Account::new(100));

        assert!(state.execute_transfer(&alice, &bob, 200).is_err());
    }

    #[test]
    fn test_stake_unstake() {
        let mut state = WorldState::new();
        let addr = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        state.set_account(addr, Account::new(1000));

        state.execute_stake(&addr, 500).unwrap();
        assert_eq!(state.get_account(&addr).unwrap().staked, 500);
        assert_eq!(state.get_account(&addr).unwrap().available_balance(), 500);

        state.execute_unstake(&addr, 300).unwrap();
        assert_eq!(state.get_account(&addr).unwrap().staked, 200);
    }

    #[test]
    fn test_state_root_deterministic() {
        let mut state = WorldState::new();
        let addr = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        state.set_account(addr, Account::new(1000));

        let root1 = state.compute_state_root();
        let root2 = state.compute_state_root();
        assert_eq!(root1, root2);
    }
}
