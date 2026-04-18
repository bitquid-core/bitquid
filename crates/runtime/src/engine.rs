use bitquid_core::{Address, Hash};

use crate::error::RuntimeError;
use crate::gas::GasMeter;
use crate::opcodes::OpCode;

const MAX_STACK_SIZE: usize = 1024;
const MAX_MEMORY_SIZE: usize = 1024 * 1024; // 1MB

/// Trait that the node must implement to let the VM interact with world state,
/// token ledger, AMM pools, and lending pools.
pub trait HostInterface {
    // ── persistent contract storage ──
    fn sload(&self, contract: &Address, key: &Hash) -> Result<[u8; 32], RuntimeError>;
    fn sstore(&mut self, contract: &Address, key: &Hash, value: [u8; 32]) -> Result<[u8; 32], RuntimeError>;

    // ── account state ──
    fn balance(&self, addr: &Address) -> Result<u64, RuntimeError>;
    fn transfer(&mut self, from: &Address, to: &Address, amount: u64) -> Result<bool, RuntimeError>;

    // ── token ops ──
    fn approve(&mut self, owner: &Address, spender: &Address, amount: u64) -> Result<bool, RuntimeError>;
    fn mint(&mut self, to: &Address, amount: u64) -> Result<bool, RuntimeError>;
    fn burn(&mut self, from: &Address, amount: u64) -> Result<bool, RuntimeError>;

    // ── AMM ──
    fn swap_exact(&mut self, caller: &Address, pool_id: u64, amount_in: u64, is_a_to_b: bool) -> Result<u64, RuntimeError>;
    fn add_liquidity(&mut self, caller: &Address, pool_id: u64, amount_a: u64, amount_b: u64) -> Result<u64, RuntimeError>;
    fn remove_liquidity(&mut self, caller: &Address, pool_id: u64, lp_tokens: u64) -> Result<(u64, u64), RuntimeError>;
    fn get_reserves(&self, pool_id: u64) -> Result<(u64, u64), RuntimeError>;

    // ── Lending ──
    fn deposit(&mut self, caller: &Address, pool_id: u64, amount: u64) -> Result<bool, RuntimeError>;
    fn withdraw(&mut self, caller: &Address, pool_id: u64, amount: u64) -> Result<bool, RuntimeError>;
    fn borrow(&mut self, caller: &Address, pool_id: u64, amount: u64) -> Result<bool, RuntimeError>;
    fn repay(&mut self, caller: &Address, pool_id: u64, amount: u64) -> Result<bool, RuntimeError>;
}

/// No-op host used when executing contracts that only need pure computation.
pub struct NullHost;

impl HostInterface for NullHost {
    fn sload(&self, _c: &Address, _k: &Hash) -> Result<[u8; 32], RuntimeError> { Ok([0u8; 32]) }
    fn sstore(&mut self, _c: &Address, _k: &Hash, old: [u8; 32]) -> Result<[u8; 32], RuntimeError> { Ok(old) }
    fn balance(&self, _a: &Address) -> Result<u64, RuntimeError> { Ok(0) }
    fn transfer(&mut self, _f: &Address, _t: &Address, _a: u64) -> Result<bool, RuntimeError> { Ok(false) }
    fn approve(&mut self, _o: &Address, _s: &Address, _a: u64) -> Result<bool, RuntimeError> { Ok(false) }
    fn mint(&mut self, _t: &Address, _a: u64) -> Result<bool, RuntimeError> { Ok(false) }
    fn burn(&mut self, _f: &Address, _a: u64) -> Result<bool, RuntimeError> { Ok(false) }
    fn swap_exact(&mut self, _c: &Address, _p: u64, _a: u64, _d: bool) -> Result<u64, RuntimeError> { Ok(0) }
    fn add_liquidity(&mut self, _c: &Address, _p: u64, _a: u64, _b: u64) -> Result<u64, RuntimeError> { Ok(0) }
    fn remove_liquidity(&mut self, _c: &Address, _p: u64, _l: u64) -> Result<(u64, u64), RuntimeError> { Ok((0, 0)) }
    fn get_reserves(&self, _p: u64) -> Result<(u64, u64), RuntimeError> { Ok((0, 0)) }
    fn deposit(&mut self, _c: &Address, _p: u64, _a: u64) -> Result<bool, RuntimeError> { Ok(false) }
    fn withdraw(&mut self, _c: &Address, _p: u64, _a: u64) -> Result<bool, RuntimeError> { Ok(false) }
    fn borrow(&mut self, _c: &Address, _p: u64, _a: u64) -> Result<bool, RuntimeError> { Ok(false) }
    fn repay(&mut self, _c: &Address, _p: u64, _a: u64) -> Result<bool, RuntimeError> { Ok(false) }
}

/// Execution context for a VM call
pub struct ExecutionContext {
    pub caller: Address,
    pub address: Address,
    pub value: u64,
    pub call_data: Vec<u8>,
    pub block_height: u64,
    pub timestamp: u64,
}

/// Execution result
#[derive(Debug)]
pub struct ExecutionResult {
    pub success: bool,
    pub gas_used: u64,
    pub return_data: Vec<u8>,
    pub logs: Vec<VmLog>,
    pub state_changes: Vec<StateChange>,
}

#[derive(Debug, Clone)]
pub struct VmLog {
    pub address: Address,
    pub topics: Vec<Hash>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StateChange {
    pub address: Address,
    pub key: Hash,
    pub old_value: Vec<u8>,
    pub new_value: Vec<u8>,
}

/// Lightweight stack-based virtual machine for DeFi contract execution
pub struct VmEngine {
    stack: Vec<u64>,
    memory: Vec<u8>,
    gas_meter: GasMeter,
    pc: usize,
    logs: Vec<VmLog>,
    state_changes: Vec<StateChange>,
    halted: bool,
    reverted: bool,
}

impl VmEngine {
    pub fn new(gas_limit: u64) -> Self {
        Self {
            stack: Vec::with_capacity(64),
            memory: Vec::new(),
            gas_meter: GasMeter::new(gas_limit),
            pc: 0,
            logs: Vec::new(),
            state_changes: Vec::new(),
            halted: false,
            reverted: false,
        }
    }

    /// Execute bytecode in the given context, backed by a real host interface.
    pub fn execute<H: HostInterface>(
        &mut self,
        bytecode: &[u8],
        ctx: &ExecutionContext,
        host: &mut H,
    ) -> Result<ExecutionResult, RuntimeError> {
        self.pc = 0;
        self.halted = false;
        self.reverted = false;

        while self.pc < bytecode.len() && !self.halted {
            let opcode_byte = bytecode[self.pc];
            let opcode = OpCode::from_byte(opcode_byte)
                .ok_or(RuntimeError::InvalidOpcode(opcode_byte))?;

            self.gas_meter.consume_op(opcode)?;
            self.pc += 1;

            match opcode {
                // ── Arithmetic ──
                OpCode::Add => {
                    let (a, b) = self.pop2()?;
                    self.push(a.wrapping_add(b))?;
                }
                OpCode::Sub => {
                    let (a, b) = self.pop2()?;
                    self.push(a.wrapping_sub(b))?;
                }
                OpCode::Mul => {
                    let (a, b) = self.pop2()?;
                    self.push(a.wrapping_mul(b))?;
                }
                OpCode::Div => {
                    let (a, b) = self.pop2()?;
                    if b == 0 {
                        return Err(RuntimeError::DivisionByZero);
                    }
                    self.push(a / b)?;
                }
                OpCode::Mod => {
                    let (a, b) = self.pop2()?;
                    if b == 0 {
                        return Err(RuntimeError::DivisionByZero);
                    }
                    self.push(a % b)?;
                }

                // ── Comparison ──
                OpCode::Lt => {
                    let (a, b) = self.pop2()?;
                    self.push(if a < b { 1 } else { 0 })?;
                }
                OpCode::Gt => {
                    let (a, b) = self.pop2()?;
                    self.push(if a > b { 1 } else { 0 })?;
                }
                OpCode::Eq => {
                    let (a, b) = self.pop2()?;
                    self.push(if a == b { 1 } else { 0 })?;
                }
                OpCode::IsZero => {
                    let a = self.pop1()?;
                    self.push(if a == 0 { 1 } else { 0 })?;
                }

                // ── Bitwise ──
                OpCode::And => {
                    let (a, b) = self.pop2()?;
                    self.push(a & b)?;
                }
                OpCode::Or => {
                    let (a, b) = self.pop2()?;
                    self.push(a | b)?;
                }
                OpCode::Xor => {
                    let (a, b) = self.pop2()?;
                    self.push(a ^ b)?;
                }
                OpCode::Not => {
                    let a = self.pop1()?;
                    self.push(!a)?;
                }
                OpCode::Shl => {
                    let (a, b) = self.pop2()?;
                    self.push(a << (b & 63))?;
                }
                OpCode::Shr => {
                    let (a, b) = self.pop2()?;
                    self.push(a >> (b & 63))?;
                }

                // ── Stack ──
                OpCode::Push => {
                    if self.pc + 8 > bytecode.len() {
                        return Err(RuntimeError::InvalidMemoryAccess {
                            offset: self.pc,
                            size: 8,
                        });
                    }
                    let value = u64::from_be_bytes(
                        bytecode[self.pc..self.pc + 8].try_into().unwrap(),
                    );
                    self.pc += 8;
                    self.push(value)?;
                }
                OpCode::Pop => {
                    self.pop1()?;
                }
                OpCode::Dup => {
                    let a = self.peek()?;
                    self.push(a)?;
                }
                OpCode::Swap => {
                    let len = self.stack.len();
                    if len < 2 {
                        return Err(RuntimeError::StackUnderflow);
                    }
                    self.stack.swap(len - 1, len - 2);
                }

                // ── Memory ──
                OpCode::MLoad => {
                    let offset = self.pop1()? as usize;
                    let end = offset.checked_add(8).ok_or(RuntimeError::InvalidMemoryAccess {
                        offset, size: 8,
                    })?;
                    if end > MAX_MEMORY_SIZE {
                        return Err(RuntimeError::InvalidMemoryAccess { offset, size: 8 });
                    }
                    if end > self.memory.len() {
                        self.gas_meter.consume_memory(self.memory.len(), end)?;
                        self.memory.resize(end, 0);
                    }
                    let value =
                        u64::from_be_bytes(self.memory[offset..end].try_into().unwrap());
                    self.push(value)?;
                }
                OpCode::MStore => {
                    let (offset, value) = self.pop2()?;
                    let offset = offset as usize;
                    let end = offset.checked_add(8).ok_or(RuntimeError::InvalidMemoryAccess {
                        offset, size: 8,
                    })?;
                    if end > MAX_MEMORY_SIZE {
                        return Err(RuntimeError::InvalidMemoryAccess { offset, size: 8 });
                    }
                    if end > self.memory.len() {
                        self.gas_meter.consume_memory(self.memory.len(), end)?;
                        self.memory.resize(end, 0);
                    }
                    self.memory[offset..end].copy_from_slice(&value.to_be_bytes());
                }
                OpCode::MSize => {
                    self.push(self.memory.len() as u64)?;
                }

                // ── Storage ──
                OpCode::SLoad => {
                    let key_u64 = self.pop1()?;
                    let mut key = [0u8; 32];
                    key[24..32].copy_from_slice(&key_u64.to_be_bytes());
                    let value = host.sload(&ctx.address, &key)?;
                    let result = u64::from_be_bytes(value[24..32].try_into().unwrap());
                    self.push(result)?;
                }
                OpCode::SStore => {
                    let (key_u64, val_u64) = self.pop2()?;
                    let mut key = [0u8; 32];
                    key[24..32].copy_from_slice(&key_u64.to_be_bytes());
                    let mut new_value = [0u8; 32];
                    new_value[24..32].copy_from_slice(&val_u64.to_be_bytes());
                    let old_value = host.sstore(&ctx.address, &key, new_value)?;
                    self.state_changes.push(StateChange {
                        address: ctx.address,
                        key,
                        old_value: old_value.to_vec(),
                        new_value: new_value.to_vec(),
                    });
                }

                // ── Control flow ──
                OpCode::Jump => {
                    let dest = self.pop1()? as usize;
                    if dest >= bytecode.len() {
                        return Err(RuntimeError::InvalidJump(dest));
                    }
                    self.pc = dest;
                }
                OpCode::JumpIf => {
                    let (dest, cond) = self.pop2()?;
                    if cond != 0 {
                        let dest = dest as usize;
                        if dest >= bytecode.len() {
                            return Err(RuntimeError::InvalidJump(dest));
                        }
                        self.pc = dest;
                    }
                }
                OpCode::Halt => {
                    self.halted = true;
                }
                OpCode::Revert => {
                    self.reverted = true;
                    self.halted = true;
                }

                // ── Environment ──
                OpCode::Caller => {
                    let bytes = &ctx.caller.0;
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&bytes[12..20]);
                    self.push(u64::from_be_bytes(buf))?;
                }
                OpCode::CallValue => {
                    self.push(ctx.value)?;
                }
                OpCode::CallDataLoad => {
                    let offset = self.pop1()? as usize;
                    let end = offset.checked_add(8).unwrap_or(usize::MAX);
                    if end <= ctx.call_data.len() {
                        let value = u64::from_be_bytes(
                            ctx.call_data[offset..end].try_into().unwrap(),
                        );
                        self.push(value)?;
                    } else {
                        self.push(0)?;
                    }
                }
                OpCode::CallDataSize => {
                    self.push(ctx.call_data.len() as u64)?;
                }
                OpCode::Address => {
                    let bytes = &ctx.address.0;
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&bytes[12..20]);
                    self.push(u64::from_be_bytes(buf))?;
                }
                OpCode::Balance => {
                    let addr_low = self.pop1()?;
                    let mut addr_bytes = [0u8; 20];
                    addr_bytes[12..20].copy_from_slice(&addr_low.to_be_bytes());
                    let addr = Address(addr_bytes);
                    let bal = host.balance(&addr)?;
                    self.push(bal)?;
                }
                OpCode::BlockHeight => {
                    self.push(ctx.block_height)?;
                }
                OpCode::Timestamp => {
                    self.push(ctx.timestamp)?;
                }

                // ── Token operations ──
                // All balance-mutating ops use ctx.address (the contract
                // itself) so that contracts can only spend their own funds,
                // never the caller's.
                OpCode::Transfer => {
                    let (to_low, amount) = self.pop2()?;
                    let mut to_bytes = [0u8; 20];
                    to_bytes[12..20].copy_from_slice(&to_low.to_be_bytes());
                    let to = Address(to_bytes);
                    let ok = host.transfer(&ctx.address, &to, amount)?;
                    self.push(if ok { 1 } else { 0 })?;
                }
                OpCode::Approve => {
                    let (spender_low, amount) = self.pop2()?;
                    let mut spender_bytes = [0u8; 20];
                    spender_bytes[12..20].copy_from_slice(&spender_low.to_be_bytes());
                    let spender = Address(spender_bytes);
                    let ok = host.approve(&ctx.caller, &spender, amount)?;
                    self.push(if ok { 1 } else { 0 })?;
                }
                OpCode::Mint => {
                    let (to_low, amount) = self.pop2()?;
                    let mut to_bytes = [0u8; 20];
                    to_bytes[12..20].copy_from_slice(&to_low.to_be_bytes());
                    let to = Address(to_bytes);
                    let ok = host.mint(&to, amount)?;
                    self.push(if ok { 1 } else { 0 })?;
                }
                OpCode::Burn => {
                    let (from_low, amount) = self.pop2()?;
                    let mut from_bytes = [0u8; 20];
                    from_bytes[12..20].copy_from_slice(&from_low.to_be_bytes());
                    let from = Address(from_bytes);
                    let ok = host.burn(&from, amount)?;
                    self.push(if ok { 1 } else { 0 })?;
                }

                // ── AMM operations ──
                OpCode::SwapExact => {
                    let pool_id = self.pop1()?;
                    let amount_in = self.pop1()?;
                    let direction = self.pop1()?;
                    let amount_out = host.swap_exact(&ctx.address, pool_id, amount_in, direction != 0)?;
                    self.push(amount_out)?;
                }
                OpCode::AddLiquidity => {
                    let pool_id = self.pop1()?;
                    let amount_a = self.pop1()?;
                    let amount_b = self.pop1()?;
                    let lp = host.add_liquidity(&ctx.address, pool_id, amount_a, amount_b)?;
                    self.push(lp)?;
                }
                OpCode::RemoveLiquidity => {
                    let pool_id = self.pop1()?;
                    let lp_tokens = self.pop1()?;
                    let (a, b) = host.remove_liquidity(&ctx.address, pool_id, lp_tokens)?;
                    self.push(a)?;
                    self.push(b)?;
                }
                OpCode::GetReserves => {
                    let pool_id = self.pop1()?;
                    let (ra, rb) = host.get_reserves(pool_id)?;
                    self.push(ra)?;
                    self.push(rb)?;
                }

                // ── Lending operations ──
                OpCode::Deposit => {
                    let pool_id = self.pop1()?;
                    let amount = self.pop1()?;
                    let ok = host.deposit(&ctx.address, pool_id, amount)?;
                    self.push(if ok { 1 } else { 0 })?;
                }
                OpCode::Withdraw => {
                    let pool_id = self.pop1()?;
                    let amount = self.pop1()?;
                    let ok = host.withdraw(&ctx.address, pool_id, amount)?;
                    self.push(if ok { 1 } else { 0 })?;
                }
                OpCode::Borrow => {
                    let pool_id = self.pop1()?;
                    let amount = self.pop1()?;
                    let ok = host.borrow(&ctx.address, pool_id, amount)?;
                    self.push(if ok { 1 } else { 0 })?;
                }
                OpCode::Repay => {
                    let pool_id = self.pop1()?;
                    let amount = self.pop1()?;
                    let ok = host.repay(&ctx.address, pool_id, amount)?;
                    self.push(if ok { 1 } else { 0 })?;
                }

                OpCode::Log => {
                    let data_len = self.pop1()? as usize;
                    let data = if data_len > 0 && data_len <= self.memory.len() {
                        self.memory[..data_len].to_vec()
                    } else {
                        vec![]
                    };
                    self.logs.push(VmLog {
                        address: ctx.address,
                        topics: vec![],
                        data,
                    });
                }
            }
        }

        Ok(ExecutionResult {
            success: !self.reverted,
            gas_used: self.gas_meter.gas_used(),
            return_data: self.return_data(),
            logs: self.logs.clone(),
            state_changes: self.state_changes.clone(),
        })
    }

    #[inline]
    fn push(&mut self, value: u64) -> Result<(), RuntimeError> {
        if self.stack.len() >= MAX_STACK_SIZE {
            return Err(RuntimeError::StackOverflow);
        }
        self.stack.push(value);
        Ok(())
    }

    #[inline]
    fn pop1(&mut self) -> Result<u64, RuntimeError> {
        self.stack.pop().ok_or(RuntimeError::StackUnderflow)
    }

    #[inline]
    fn pop2(&mut self) -> Result<(u64, u64), RuntimeError> {
        let b = self.pop1()?;
        let a = self.pop1()?;
        Ok((a, b))
    }

    #[inline]
    fn peek(&self) -> Result<u64, RuntimeError> {
        self.stack.last().copied().ok_or(RuntimeError::StackUnderflow)
    }

    fn return_data(&self) -> Vec<u8> {
        if let Some(&val) = self.stack.last() {
            val.to_be_bytes().to_vec()
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> ExecutionContext {
        ExecutionContext {
            caller: Address::ZERO,
            address: Address::ZERO,
            value: 0,
            call_data: vec![],
            block_height: 100,
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn test_add() {
        let mut vm = VmEngine::new(100_000);
        let mut host = NullHost;
        // PUSH 10, PUSH 20, ADD, HALT
        let bytecode = [
            0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, // PUSH 10
            0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, // PUSH 20
            0x01, // ADD
            0x62, // HALT
        ];
        let result = vm.execute(&bytecode, &make_ctx(), &mut host).unwrap();
        assert!(result.success);
        assert_eq!(result.return_data, 30u64.to_be_bytes());
    }

    #[test]
    fn test_out_of_gas() {
        let mut vm = VmEngine::new(1); // Only 1 gas
        let mut host = NullHost;
        let bytecode = [
            0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // PUSH 1
        ];
        let result = vm.execute(&bytecode, &make_ctx(), &mut host);
        assert!(result.is_err());
    }

    #[test]
    fn test_comparison() {
        let mut vm = VmEngine::new(100_000);
        let mut host = NullHost;
        // PUSH 5, PUSH 10, GT, HALT (5 > 10 = false = 0)
        let bytecode = [
            0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // PUSH 5
            0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, // PUSH 10
            0x11, // GT
            0x62, // HALT
        ];
        let result = vm.execute(&bytecode, &make_ctx(), &mut host).unwrap();
        assert_eq!(result.return_data, 0u64.to_be_bytes());
    }

    #[test]
    fn test_sload_sstore_via_host() {
        use std::collections::HashMap;

        struct TestHost {
            storage: HashMap<(Address, Hash), [u8; 32]>,
        }
        impl HostInterface for TestHost {
            fn sload(&self, c: &Address, k: &Hash) -> Result<[u8; 32], RuntimeError> {
                Ok(self.storage.get(&(*c, *k)).copied().unwrap_or([0u8; 32]))
            }
            fn sstore(&mut self, c: &Address, k: &Hash, v: [u8; 32]) -> Result<[u8; 32], RuntimeError> {
                let old = self.storage.insert((*c, *k), v).unwrap_or([0u8; 32]);
                Ok(old)
            }
            fn balance(&self, _: &Address) -> Result<u64, RuntimeError> { Ok(0) }
            fn transfer(&mut self, _: &Address, _: &Address, _: u64) -> Result<bool, RuntimeError> { Ok(false) }
            fn approve(&mut self, _: &Address, _: &Address, _: u64) -> Result<bool, RuntimeError> { Ok(false) }
            fn mint(&mut self, _: &Address, _: u64) -> Result<bool, RuntimeError> { Ok(false) }
            fn burn(&mut self, _: &Address, _: u64) -> Result<bool, RuntimeError> { Ok(false) }
            fn swap_exact(&mut self, _: &Address, _: u64, _: u64, _: bool) -> Result<u64, RuntimeError> { Ok(0) }
            fn add_liquidity(&mut self, _: &Address, _: u64, _: u64, _: u64) -> Result<u64, RuntimeError> { Ok(0) }
            fn remove_liquidity(&mut self, _: &Address, _: u64, _: u64) -> Result<(u64, u64), RuntimeError> { Ok((0, 0)) }
            fn get_reserves(&self, _: u64) -> Result<(u64, u64), RuntimeError> { Ok((0, 0)) }
            fn deposit(&mut self, _: &Address, _: u64, _: u64) -> Result<bool, RuntimeError> { Ok(false) }
            fn withdraw(&mut self, _: &Address, _: u64, _: u64) -> Result<bool, RuntimeError> { Ok(false) }
            fn borrow(&mut self, _: &Address, _: u64, _: u64) -> Result<bool, RuntimeError> { Ok(false) }
            fn repay(&mut self, _: &Address, _: u64, _: u64) -> Result<bool, RuntimeError> { Ok(false) }
        }

        let mut vm = VmEngine::new(1_000_000);
        let mut host = TestHost { storage: HashMap::new() };

        // PUSH key=1, PUSH value=42, SSTORE, PUSH key=1, SLOAD, HALT
        let bytecode = [
            0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // PUSH 1 (key)
            0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, // PUSH 42 (value)
            0x51, // SSTORE
            0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // PUSH 1 (key)
            0x50, // SLOAD
            0x62, // HALT
        ];
        let result = vm.execute(&bytecode, &make_ctx(), &mut host).unwrap();
        assert!(result.success);
        assert_eq!(result.return_data, 42u64.to_be_bytes());
        assert_eq!(result.state_changes.len(), 1);
    }
}
