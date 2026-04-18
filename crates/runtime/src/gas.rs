use crate::error::RuntimeError;
use crate::opcodes::OpCode;

/// Gas costs for each operation
pub struct GasSchedule;

impl GasSchedule {
    pub fn cost(op: OpCode) -> u64 {
        match op {
            // Arithmetic: cheap
            OpCode::Add | OpCode::Sub => 3,
            OpCode::Mul => 5,
            OpCode::Div | OpCode::Mod => 5,

            // Comparison: cheap
            OpCode::Lt | OpCode::Gt | OpCode::Eq | OpCode::IsZero => 3,

            // Bitwise: cheap
            OpCode::And | OpCode::Or | OpCode::Xor | OpCode::Not => 3,
            OpCode::Shl | OpCode::Shr => 3,

            // Stack: very cheap
            OpCode::Push | OpCode::Pop | OpCode::Dup | OpCode::Swap => 2,

            // Memory: moderate
            OpCode::MLoad | OpCode::MStore => 6,
            OpCode::MSize => 2,

            // Storage: expensive (disk I/O)
            OpCode::SLoad => 200,
            OpCode::SStore => 5_000,

            // Control flow
            OpCode::Jump | OpCode::JumpIf => 8,
            OpCode::Halt => 0,
            OpCode::Revert => 0,

            // Environment: moderate
            OpCode::Caller | OpCode::CallValue | OpCode::Address => 2,
            OpCode::CallDataLoad | OpCode::CallDataSize => 3,
            OpCode::Balance => 400,
            OpCode::BlockHeight | OpCode::Timestamp => 2,

            // Token operations: moderate-expensive
            OpCode::Transfer => 9_000,
            OpCode::Approve => 5_000,
            OpCode::Mint => 10_000,
            OpCode::Burn => 10_000,

            // AMM: expensive (multiple state reads/writes)
            OpCode::SwapExact => 30_000,
            OpCode::AddLiquidity => 50_000,
            OpCode::RemoveLiquidity => 40_000,
            OpCode::GetReserves => 800,

            // Lending: expensive
            OpCode::Deposit => 30_000,
            OpCode::Withdraw => 30_000,
            OpCode::Borrow => 50_000,
            OpCode::Repay => 30_000,

            // Logging
            OpCode::Log => 375,
        }
    }
}

/// Gas metering for VM execution
pub struct GasMeter {
    limit: u64,
    used: u64,
}

impl GasMeter {
    pub fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    /// Consume gas for an operation. Returns error if out of gas.
    #[inline]
    pub fn consume(&mut self, amount: u64) -> Result<(), RuntimeError> {
        let new_used = self.used.saturating_add(amount);
        if new_used > self.limit {
            return Err(RuntimeError::OutOfGas {
                used: new_used,
                limit: self.limit,
            });
        }
        self.used = new_used;
        Ok(())
    }

    /// Consume gas for a specific opcode
    #[inline]
    pub fn consume_op(&mut self, op: OpCode) -> Result<(), RuntimeError> {
        self.consume(GasSchedule::cost(op))
    }

    /// Consume gas for memory expansion
    pub fn consume_memory(&mut self, current_size: usize, new_size: usize) -> Result<(), RuntimeError> {
        if new_size <= current_size {
            return Ok(());
        }
        let words = ((new_size - current_size) + 31) / 32;
        let cost = (words as u64) * 3;
        self.consume(cost)
    }

    pub fn gas_used(&self) -> u64 {
        self.used
    }

    pub fn gas_remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    pub fn gas_limit(&self) -> u64 {
        self.limit
    }

    /// Refund unused gas (partial refund)
    pub fn refund(&self) -> u64 {
        self.gas_remaining()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_consumption() {
        let mut meter = GasMeter::new(100);
        meter.consume(50).unwrap();
        assert_eq!(meter.gas_used(), 50);
        assert_eq!(meter.gas_remaining(), 50);
    }

    #[test]
    fn test_out_of_gas() {
        let mut meter = GasMeter::new(10);
        assert!(meter.consume(11).is_err());
    }

    #[test]
    fn test_op_gas() {
        let mut meter = GasMeter::new(1_000_000);
        meter.consume_op(OpCode::Add).unwrap();
        assert_eq!(meter.gas_used(), 3);
    }
}
