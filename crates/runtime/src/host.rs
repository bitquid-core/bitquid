use bitquid_core::{Address, Hash, WorldState};
use bitquid_crypto::blake3_hash;

use crate::defi::{AmmPool, LendingPool};
use crate::engine::HostInterface;
use crate::error::RuntimeError;

/// Well-known system contract address for protocol-level AMM state.
const AMM_SYSTEM_ADDR: Address = Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
/// Well-known system contract address for protocol-level Lending state.
const LENDING_SYSTEM_ADDR: Address = Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0]);

/// Production host that bridges the VM's `HostInterface` to `WorldState`.
///
/// All persistent mutations (balance changes, storage writes, DeFi pool
/// updates) go directly through the wrapped `WorldState`, so a
/// `WorldState::snapshot()` / revert cycle rolls back everything.
pub struct StateHost<'a> {
    pub state: &'a mut WorldState,
    /// The EOA that originated the transaction.
    caller: Address,
    /// The contract address currently being executed.
    contract_addr: Address,
}

impl<'a> StateHost<'a> {
    pub fn new(state: &'a mut WorldState, caller: Address, contract_addr: Address) -> Self {
        Self { state, caller, contract_addr }
    }

    fn pool_key(prefix: &[u8], pool_id: u64) -> Hash {
        let mut data = prefix.to_vec();
        data.extend_from_slice(&pool_id.to_be_bytes());
        blake3_hash(&data)
    }

    fn user_pool_key(prefix: &[u8], user: &Address, pool_id: u64) -> Hash {
        let mut data = prefix.to_vec();
        data.extend_from_slice(&user.0);
        data.extend_from_slice(&pool_id.to_be_bytes());
        blake3_hash(&data)
    }

    fn load_amm_pool(&self, pool_id: u64) -> Result<AmmPool, RuntimeError> {
        let key = Self::pool_key(b"amm_pool", pool_id);
        match self.state.storage_get(&AMM_SYSTEM_ADDR, &key) {
            Some(data) => bincode::deserialize(data)
                .map_err(|e| RuntimeError::State(format!("amm pool decode: {e}"))),
            None => Err(RuntimeError::State(format!("amm pool {pool_id} not found"))),
        }
    }

    fn save_amm_pool(&mut self, pool_id: u64, pool: &AmmPool) -> Result<(), RuntimeError> {
        let key = Self::pool_key(b"amm_pool", pool_id);
        let data = bincode::serialize(pool)
            .map_err(|e| RuntimeError::State(format!("amm pool encode: {e}")))?;
        self.state.storage_set(&AMM_SYSTEM_ADDR, key, data);
        Ok(())
    }

    fn get_lp_balance(&self, user: &Address, pool_id: u64) -> u64 {
        let key = Self::user_pool_key(b"lp_bal", user, pool_id);
        self.state
            .storage_get(&AMM_SYSTEM_ADDR, &key)
            .and_then(|d| <[u8; 8]>::try_from(d.as_slice()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0)
    }

    fn set_lp_balance(&mut self, user: &Address, pool_id: u64, amount: u64) {
        let key = Self::user_pool_key(b"lp_bal", user, pool_id);
        self.state
            .storage_set(&AMM_SYSTEM_ADDR, key, amount.to_be_bytes().to_vec());
    }

    fn load_lending_pool(&self, pool_id: u64) -> Result<LendingPool, RuntimeError> {
        let key = Self::pool_key(b"lend_pool", pool_id);
        match self.state.storage_get(&LENDING_SYSTEM_ADDR, &key) {
            Some(data) => bincode::deserialize(data)
                .map_err(|e| RuntimeError::State(format!("lending pool decode: {e}"))),
            None => Err(RuntimeError::State(format!(
                "lending pool {pool_id} not found"
            ))),
        }
    }

    fn save_lending_pool(
        &mut self,
        pool_id: u64,
        pool: &LendingPool,
    ) -> Result<(), RuntimeError> {
        let key = Self::pool_key(b"lend_pool", pool_id);
        let data = bincode::serialize(pool)
            .map_err(|e| RuntimeError::State(format!("lending pool encode: {e}")))?;
        self.state.storage_set(&LENDING_SYSTEM_ADDR, key, data);
        Ok(())
    }

    fn get_user_deposit(&self, user: &Address, pool_id: u64) -> u64 {
        let key = Self::user_pool_key(b"lend_dep", user, pool_id);
        self.state
            .storage_get(&LENDING_SYSTEM_ADDR, &key)
            .and_then(|d| <[u8; 8]>::try_from(d.as_slice()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0)
    }

    fn set_user_deposit(&mut self, user: &Address, pool_id: u64, amount: u64) {
        let key = Self::user_pool_key(b"lend_dep", user, pool_id);
        self.state
            .storage_set(&LENDING_SYSTEM_ADDR, key, amount.to_be_bytes().to_vec());
    }

    fn get_user_borrow(&self, user: &Address, pool_id: u64) -> u64 {
        let key = Self::user_pool_key(b"lend_bor", user, pool_id);
        self.state
            .storage_get(&LENDING_SYSTEM_ADDR, &key)
            .and_then(|d| <[u8; 8]>::try_from(d.as_slice()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0)
    }

    fn set_user_borrow(&mut self, user: &Address, pool_id: u64, amount: u64) {
        let key = Self::user_pool_key(b"lend_bor", user, pool_id);
        self.state
            .storage_set(&LENDING_SYSTEM_ADDR, key, amount.to_be_bytes().to_vec());
    }
}

// ---------------------------------------------------------------------------
// HostInterface implementation — every VM opcode that touches state lands here
// ---------------------------------------------------------------------------

impl<'a> HostInterface for StateHost<'a> {
    fn sload(&self, contract: &Address, key: &Hash) -> Result<[u8; 32], RuntimeError> {
        match self.state.storage_get(contract, key) {
            Some(data) => {
                let mut val = [0u8; 32];
                let len = data.len().min(32);
                val[32 - len..].copy_from_slice(&data[..len]);
                Ok(val)
            }
            None => Ok([0u8; 32]),
        }
    }

    fn sstore(
        &mut self,
        contract: &Address,
        key: &Hash,
        value: [u8; 32],
    ) -> Result<[u8; 32], RuntimeError> {
        let old = self.sload(contract, key)?;
        self.state.storage_set(contract, *key, value.to_vec());
        Ok(old)
    }

    fn balance(&self, addr: &Address) -> Result<u64, RuntimeError> {
        Ok(self.state.get_balance(addr))
    }

    fn transfer(
        &mut self,
        from: &Address,
        to: &Address,
        amount: u64,
    ) -> Result<bool, RuntimeError> {
        if self.state.get_balance(from) < amount {
            return Ok(false);
        }
        self.state.get_or_create_account(from).sub_balance(amount);
        self.state.get_or_create_account(to).add_balance(amount);
        Ok(true)
    }

    fn approve(
        &mut self,
        owner: &Address,
        spender: &Address,
        amount: u64,
    ) -> Result<bool, RuntimeError> {
        self.state.set_allowance(*owner, *spender, amount);
        Ok(true)
    }

    /// Mint is restricted: only block rewards (outside VM) may create supply.
    /// Contracts cannot mint native BQF — always returns false.
    fn mint(&mut self, _to: &Address, _amount: u64) -> Result<bool, RuntimeError> {
        Ok(false)
    }

    /// Burn is restricted: a contract can only burn its own balance or the
    /// transaction caller's balance — never a third party's.
    fn burn(&mut self, from: &Address, amount: u64) -> Result<bool, RuntimeError> {
        if *from != self.caller && *from != self.contract_addr {
            return Ok(false);
        }
        if self.state.get_balance(from) < amount {
            return Ok(false);
        }
        self.state.get_or_create_account(from).sub_balance(amount);
        Ok(true)
    }

    // -- AMM -------------------------------------------------------------------

    fn swap_exact(
        &mut self,
        caller: &Address,
        pool_id: u64,
        amount_in: u64,
        is_a_to_b: bool,
    ) -> Result<u64, RuntimeError> {
        if self.state.get_balance(caller) < amount_in {
            return Err(RuntimeError::State(
                "insufficient balance for swap".into(),
            ));
        }
        let mut pool = self.load_amm_pool(pool_id)?;
        let amount_out = pool
            .swap(amount_in, is_a_to_b)
            .ok_or_else(|| RuntimeError::State("swap failed: insufficient liquidity".into()))?;
        self.state
            .get_or_create_account(caller)
            .sub_balance(amount_in);
        self.state
            .get_or_create_account(caller)
            .add_balance(amount_out);
        self.save_amm_pool(pool_id, &pool)?;
        Ok(amount_out)
    }

    fn add_liquidity(
        &mut self,
        caller: &Address,
        pool_id: u64,
        amount_a: u64,
        amount_b: u64,
    ) -> Result<u64, RuntimeError> {
        let total = amount_a.saturating_add(amount_b);
        if self.state.get_balance(caller) < total {
            return Err(RuntimeError::State(
                "insufficient balance for liquidity".into(),
            ));
        }
        let mut pool = self.load_amm_pool(pool_id)?;
        let lp_tokens = pool.add_liquidity(amount_a, amount_b);
        self.state
            .get_or_create_account(caller)
            .sub_balance(total);
        let existing_lp = self.get_lp_balance(caller, pool_id);
        self.set_lp_balance(caller, pool_id, existing_lp.saturating_add(lp_tokens));
        self.save_amm_pool(pool_id, &pool)?;
        Ok(lp_tokens)
    }

    fn remove_liquidity(
        &mut self,
        caller: &Address,
        pool_id: u64,
        lp_tokens: u64,
    ) -> Result<(u64, u64), RuntimeError> {
        let user_lp = self.get_lp_balance(caller, pool_id);
        if user_lp < lp_tokens {
            return Err(RuntimeError::State("insufficient LP tokens".into()));
        }
        let mut pool = self.load_amm_pool(pool_id)?;
        let (a, b) = pool.remove_liquidity(lp_tokens);
        self.set_lp_balance(caller, pool_id, user_lp - lp_tokens);
        self.state
            .get_or_create_account(caller)
            .add_balance(a.saturating_add(b));
        self.save_amm_pool(pool_id, &pool)?;
        Ok((a, b))
    }

    fn get_reserves(&self, pool_id: u64) -> Result<(u64, u64), RuntimeError> {
        let pool = self.load_amm_pool(pool_id)?;
        Ok((pool.reserve_a, pool.reserve_b))
    }

    // -- Lending ---------------------------------------------------------------

    fn deposit(
        &mut self,
        caller: &Address,
        pool_id: u64,
        amount: u64,
    ) -> Result<bool, RuntimeError> {
        if self.state.get_balance(caller) < amount {
            return Ok(false);
        }
        let mut pool = self.load_lending_pool(pool_id)?;
        self.state
            .get_or_create_account(caller)
            .sub_balance(amount);
        pool.total_deposits = pool.total_deposits.saturating_add(amount);
        let existing = self.get_user_deposit(caller, pool_id);
        self.set_user_deposit(caller, pool_id, existing.saturating_add(amount));
        self.save_lending_pool(pool_id, &pool)?;
        Ok(true)
    }

    fn withdraw(
        &mut self,
        caller: &Address,
        pool_id: u64,
        amount: u64,
    ) -> Result<bool, RuntimeError> {
        let user_dep = self.get_user_deposit(caller, pool_id);
        if user_dep < amount {
            return Ok(false);
        }
        let mut pool = self.load_lending_pool(pool_id)?;
        if pool.available_liquidity() < amount {
            return Ok(false);
        }
        pool.total_deposits = pool.total_deposits.saturating_sub(amount);
        self.set_user_deposit(caller, pool_id, user_dep - amount);
        self.state
            .get_or_create_account(caller)
            .add_balance(amount);
        self.save_lending_pool(pool_id, &pool)?;
        Ok(true)
    }

    fn borrow(
        &mut self,
        caller: &Address,
        pool_id: u64,
        amount: u64,
    ) -> Result<bool, RuntimeError> {
        let mut pool = self.load_lending_pool(pool_id)?;
        if pool.available_liquidity() < amount {
            return Ok(false);
        }
        let user_dep = self.get_user_deposit(caller, pool_id);
        if !pool.is_borrow_safe(amount, user_dep) {
            return Ok(false);
        }
        pool.total_borrows = pool.total_borrows.saturating_add(amount);
        let existing_borrow = self.get_user_borrow(caller, pool_id);
        self.set_user_borrow(caller, pool_id, existing_borrow.saturating_add(amount));
        self.state
            .get_or_create_account(caller)
            .add_balance(amount);
        self.save_lending_pool(pool_id, &pool)?;
        Ok(true)
    }

    fn repay(
        &mut self,
        caller: &Address,
        pool_id: u64,
        amount: u64,
    ) -> Result<bool, RuntimeError> {
        if self.state.get_balance(caller) < amount {
            return Ok(false);
        }
        let user_borrow = self.get_user_borrow(caller, pool_id);
        let repay_amount = amount.min(user_borrow);
        if repay_amount == 0 {
            return Ok(false);
        }
        let mut pool = self.load_lending_pool(pool_id)?;
        self.state
            .get_or_create_account(caller)
            .sub_balance(repay_amount);
        pool.total_borrows = pool.total_borrows.saturating_sub(repay_amount);
        self.set_user_borrow(caller, pool_id, user_borrow - repay_amount);
        self.save_lending_pool(pool_id, &pool)?;
        Ok(true)
    }
}
