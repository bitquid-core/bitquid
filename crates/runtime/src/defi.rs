use bitquid_core::Address;
use serde::{Deserialize, Serialize};

/// Constant Product AMM (x * y = k)
///
/// Built-in protocol-level AMM for token swaps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmmPool {
    pub token_a: Address,
    pub token_b: Address,
    pub reserve_a: u64,
    pub reserve_b: u64,
    pub total_lp_supply: u64,
    pub fee_bps: u16, // basis points (e.g. 30 = 0.3%)
}

impl AmmPool {
    pub fn new(token_a: Address, token_b: Address, fee_bps: u16) -> Self {
        assert!(fee_bps < 10_000, "fee_bps must be < 10000");
        Self {
            token_a,
            token_b,
            reserve_a: 0,
            reserve_b: 0,
            total_lp_supply: 0,
            fee_bps,
        }
    }

    /// Calculate output amount for a swap (constant product formula)
    pub fn get_amount_out(&self, amount_in: u64, is_a_to_b: bool) -> Option<u64> {
        let (reserve_in, reserve_out) = if is_a_to_b {
            (self.reserve_a as u128, self.reserve_b as u128)
        } else {
            (self.reserve_b as u128, self.reserve_a as u128)
        };

        if reserve_in == 0 || reserve_out == 0 || amount_in == 0 {
            return None;
        }

        if self.fee_bps >= 10_000 {
            return None;
        }

        let amount_in = amount_in as u128;
        let fee_numerator = 10_000u128 - self.fee_bps as u128;
        let amount_in_with_fee = amount_in * fee_numerator;
        let numerator = amount_in_with_fee * reserve_out;
        let denominator = reserve_in * 10_000 + amount_in_with_fee;

        Some((numerator / denominator) as u64)
    }

    /// Add liquidity to the pool. Returns LP tokens minted.
    pub fn add_liquidity(&mut self, amount_a: u64, amount_b: u64) -> u64 {
        if self.total_lp_supply == 0 {
            let lp = isqrt(amount_a as u128 * amount_b as u128) as u64;
            self.reserve_a = self.reserve_a.saturating_add(amount_a);
            self.reserve_b = self.reserve_b.saturating_add(amount_b);
            self.total_lp_supply = lp;
            lp
        } else {
            if self.reserve_a == 0 || self.reserve_b == 0 {
                return 0;
            }
            let lp_a =
                (amount_a as u128 * self.total_lp_supply as u128 / self.reserve_a as u128) as u64;
            let lp_b =
                (amount_b as u128 * self.total_lp_supply as u128 / self.reserve_b as u128) as u64;
            let lp = lp_a.min(lp_b);
            self.reserve_a = self.reserve_a.saturating_add(amount_a);
            self.reserve_b = self.reserve_b.saturating_add(amount_b);
            self.total_lp_supply = self.total_lp_supply.saturating_add(lp);
            lp
        }
    }

    /// Remove liquidity from the pool. Returns (amount_a, amount_b).
    pub fn remove_liquidity(&mut self, lp_tokens: u64) -> (u64, u64) {
        if self.total_lp_supply == 0 || lp_tokens == 0 {
            return (0, 0);
        }

        let lp_tokens = lp_tokens.min(self.total_lp_supply);

        let amount_a =
            (lp_tokens as u128 * self.reserve_a as u128 / self.total_lp_supply as u128) as u64;
        let amount_b =
            (lp_tokens as u128 * self.reserve_b as u128 / self.total_lp_supply as u128) as u64;

        self.reserve_a = self.reserve_a.saturating_sub(amount_a);
        self.reserve_b = self.reserve_b.saturating_sub(amount_b);
        self.total_lp_supply = self.total_lp_supply.saturating_sub(lp_tokens);

        (amount_a, amount_b)
    }

    /// Execute a swap
    pub fn swap(&mut self, amount_in: u64, is_a_to_b: bool) -> Option<u64> {
        let amount_out = self.get_amount_out(amount_in, is_a_to_b)?;

        if is_a_to_b {
            if self.reserve_b < amount_out {
                return None;
            }
            self.reserve_a = self.reserve_a.saturating_add(amount_in);
            self.reserve_b = self.reserve_b.saturating_sub(amount_out);
        } else {
            if self.reserve_a < amount_out {
                return None;
            }
            self.reserve_b = self.reserve_b.saturating_add(amount_in);
            self.reserve_a = self.reserve_a.saturating_sub(amount_out);
        }

        Some(amount_out)
    }

    /// Current price of token A in terms of token B
    pub fn price_a_in_b(&self) -> Option<f64> {
        if self.reserve_a == 0 {
            return None;
        }
        Some(self.reserve_b as f64 / self.reserve_a as f64)
    }
}

/// Simple lending pool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LendingPool {
    pub token: Address,
    pub total_deposits: u64,
    pub total_borrows: u64,
    /// Annual interest rate in basis points (e.g. 500 = 5%)
    pub interest_rate_bps: u16,
    /// Collateral ratio required in basis points (e.g. 15000 = 150%)
    pub collateral_ratio_bps: u16,
}

impl LendingPool {
    pub fn new(token: Address, interest_rate_bps: u16, collateral_ratio_bps: u16) -> Self {
        Self {
            token,
            total_deposits: 0,
            total_borrows: 0,
            interest_rate_bps,
            collateral_ratio_bps,
        }
    }

    /// Utilization rate in basis points
    pub fn utilization_bps(&self) -> u16 {
        if self.total_deposits == 0 {
            return 0;
        }
        ((self.total_borrows as u128 * 10_000) / self.total_deposits as u128) as u16
    }

    /// Check if a borrow is safe given collateral
    pub fn is_borrow_safe(&self, borrow_amount: u64, collateral_value: u64) -> bool {
        let required = (borrow_amount as u128 * self.collateral_ratio_bps as u128) / 10_000;
        collateral_value as u128 >= required
    }

    /// Available liquidity for borrowing
    pub fn available_liquidity(&self) -> u64 {
        self.total_deposits.saturating_sub(self.total_borrows)
    }
}

/// Integer square root (for initial LP token calculation)
fn isqrt(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amm_swap() {
        let mut pool = AmmPool::new(Address::ZERO, Address::ZERO, 30);
        pool.add_liquidity(1_000_000, 1_000_000);

        let out = pool.get_amount_out(10_000, true).unwrap();
        assert!(out > 0 && out < 10_000); // Should receive less due to slippage + fees
    }

    #[test]
    fn test_amm_add_remove_liquidity() {
        let mut pool = AmmPool::new(Address::ZERO, Address::ZERO, 30);
        let lp = pool.add_liquidity(1_000_000, 1_000_000);
        assert!(lp > 0);
        assert_eq!(pool.reserve_a, 1_000_000);

        let (a, b) = pool.remove_liquidity(lp);
        assert_eq!(a, 1_000_000);
        assert_eq!(b, 1_000_000);
    }

    #[test]
    fn test_lending_utilization() {
        let mut pool = LendingPool::new(Address::ZERO, 500, 15000);
        pool.total_deposits = 1_000_000;
        pool.total_borrows = 500_000;
        assert_eq!(pool.utilization_bps(), 5000); // 50%
    }

    #[test]
    fn test_lending_borrow_safety() {
        let pool = LendingPool::new(Address::ZERO, 500, 15000); // 150% collateral
        assert!(pool.is_borrow_safe(1000, 1500));  // exact 150%
        assert!(!pool.is_borrow_safe(1000, 1499)); // below 150%
        assert!(pool.is_borrow_safe(1000, 2000));  // over-collateralized
    }

    #[test]
    fn test_isqrt() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(9), 3);
        assert_eq!(isqrt(1_000_000), 1_000);
    }
}
