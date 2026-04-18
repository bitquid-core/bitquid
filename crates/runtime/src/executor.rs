use bitquid_core::transaction::{Log, SignedTransaction, TransactionReceipt, TransactionType};
use bitquid_core::{Account, Address, ChainConfig, CoreError, WorldState};
use bitquid_crypto::blake3_hash;
use tracing::debug;

use crate::engine::{ExecutionContext, VmEngine};
use crate::host::StateHost;

const MAX_CONTRACT_SIZE: usize = 24 * 1024; // 24 KB (Spurious-Dragon-style limit)
const CONTRACT_DEPLOY_BASE_GAS: u64 = 32_000;
const CONTRACT_DEPLOY_PER_BYTE_GAS: u64 = 200;
const CONTRACT_CALL_BASE_GAS: u64 = 21_000;
const BASE_TX_GAS: u64 = 21_000;

/// Derive a deterministic contract address from (sender, nonce).
pub fn derive_contract_address(sender: &Address, nonce: u64) -> Address {
    let mut data = sender.0.to_vec();
    data.extend_from_slice(&nonce.to_be_bytes());
    let hash = blake3_hash(&data);
    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&hash[12..32]);
    Address(addr_bytes)
}

/// Unified transaction executor that handles **all** transaction types,
/// including smart-contract deployment and calls via the built-in VM.
///
/// Replaces the simpler `WorldState::apply_transaction` as the single entry
/// point used by the block producer.
pub struct BlockExecutor<'a> {
    state: &'a mut WorldState,
    chain_config: &'a ChainConfig,
    block_height: u64,
    block_timestamp: u64,
}

impl<'a> BlockExecutor<'a> {
    pub fn new(
        state: &'a mut WorldState,
        chain_config: &'a ChainConfig,
        block_height: u64,
        block_timestamp: u64,
    ) -> Self {
        Self {
            state,
            chain_config,
            block_height,
            block_timestamp,
        }
    }

    /// Execute a signed transaction, applying all state changes and returning
    /// a receipt.  On VM failure the world state is rolled back to its
    /// pre-execution snapshot while still charging gas.
    pub fn execute_transaction(
        &mut self,
        tx: &SignedTransaction,
        tx_index: u32,
    ) -> Result<TransactionReceipt, CoreError> {
        tx.verify()?;

        let sender = tx.sender();

        // --- common pre-checks -------------------------------------------
        let expected_nonce = self.state.get_nonce(&sender);
        if tx.nonce() != expected_nonce {
            return Err(CoreError::NonceMismatch {
                expected: expected_nonce,
                got: tx.nonce(),
            });
        }

        let total_cost = tx.total_cost();
        let balance = self.state.get_balance(&sender);
        if balance < total_cost {
            return Err(CoreError::InsufficientBalance {
                need: total_cost,
                have: balance,
            });
        }

        if tx.inner.gas_price < self.chain_config.min_gas_price {
            return Err(CoreError::InvalidTransaction(format!(
                "gas_price {} below minimum {}",
                tx.inner.gas_price,
                self.chain_config.min_gas_price,
            )));
        }

        if tx.inner.gas_limit < BASE_TX_GAS {
            return Err(CoreError::GasLimitExceeded {
                used: BASE_TX_GAS,
                limit: tx.inner.gas_limit,
            });
        }

        if tx.inner.data.len() > self.chain_config.max_tx_size {
            return Err(CoreError::InvalidTransaction(format!(
                "tx data {} bytes exceeds max {}",
                tx.inner.data.len(),
                self.chain_config.max_tx_size,
            )));
        }

        // --- dispatch by type --------------------------------------------
        let (success, gas_used, logs, return_data) = match tx.inner.tx_type {
            TransactionType::Transfer => {
                self.state
                    .execute_transfer(&sender, &tx.inner.to, tx.inner.value)?;
                (true, BASE_TX_GAS, vec![], vec![])
            }
            TransactionType::Stake => {
                self.state.execute_stake(&sender, tx.inner.value)?;
                (true, BASE_TX_GAS, vec![], vec![])
            }
            TransactionType::Unstake => {
                self.state.execute_unstake(&sender, tx.inner.value)?;
                (true, BASE_TX_GAS, vec![], vec![])
            }
            TransactionType::ContractCreate => self.execute_contract_create(tx)?,
            TransactionType::ContractCall => self.execute_contract_call(tx)?,
        };

        let gas_used = gas_used.min(tx.inner.gas_limit);

        // --- charge gas & bump nonce -------------------------------------
        {
            let gas_fee = gas_used.saturating_mul(tx.inner.gas_price);
            let sender_account = self.state.get_or_create_account(&sender);
            sender_account.sub_balance(gas_fee);
            sender_account.increment_nonce();
        }

        Ok(TransactionReceipt {
            tx_hash: tx.tx_hash(),
            block_height: self.block_height,
            index: tx_index,
            success,
            gas_used,
            logs,
            return_data,
        })
    }

    // ---------------------------------------------------------------------
    // ContractCreate — deploy new bytecode
    // ---------------------------------------------------------------------
    fn execute_contract_create(
        &mut self,
        tx: &SignedTransaction,
    ) -> Result<(bool, u64, Vec<Log>, Vec<u8>), CoreError> {
        let sender = tx.sender();
        let bytecode = &tx.inner.data;

        if bytecode.is_empty() {
            return Err(CoreError::InvalidTransaction(
                "empty contract bytecode".into(),
            ));
        }
        if bytecode.len() > MAX_CONTRACT_SIZE {
            return Err(CoreError::InvalidTransaction(format!(
                "contract too large: {} > {MAX_CONTRACT_SIZE}",
                bytecode.len()
            )));
        }

        let deploy_gas = CONTRACT_DEPLOY_BASE_GAS
            + (bytecode.len() as u64).saturating_mul(CONTRACT_DEPLOY_PER_BYTE_GAS);
        if deploy_gas > tx.inner.gas_limit {
            return Err(CoreError::GasLimitExceeded {
                used: deploy_gas,
                limit: tx.inner.gas_limit,
            });
        }

        let contract_addr = derive_contract_address(&sender, tx.nonce());

        if let Some(existing) = self.state.get_account(&contract_addr) {
            if existing.is_contract {
                return Err(CoreError::InvalidTransaction(
                    "contract address collision".into(),
                ));
            }
        }

        let contract_account = Account::new_contract(bytecode);
        self.state.set_account(contract_addr, contract_account);
        self.state.set_code(&contract_addr, bytecode.to_vec());

        if tx.inner.value > 0 {
            self.state
                .get_or_create_account(&sender)
                .sub_balance(tx.inner.value);
            self.state
                .get_or_create_account(&contract_addr)
                .add_balance(tx.inner.value);
        }

        debug!(
            "Contract deployed at {} by {}, size={}B, gas={}",
            contract_addr,
            sender,
            bytecode.len(),
            deploy_gas
        );

        Ok((true, deploy_gas, vec![], contract_addr.0.to_vec()))
    }

    // ---------------------------------------------------------------------
    // ContractCall — execute deployed bytecode via the VM
    // ---------------------------------------------------------------------
    fn execute_contract_call(
        &mut self,
        tx: &SignedTransaction,
    ) -> Result<(bool, u64, Vec<Log>, Vec<u8>), CoreError> {
        let sender = tx.sender();
        let contract_addr = tx.inner.to;

        let bytecode = self
            .state
            .get_code(&contract_addr)
            .ok_or_else(|| {
                CoreError::InvalidTransaction(format!(
                    "no contract at address {}",
                    contract_addr
                ))
            })?
            .to_vec();

        // Snapshot BEFORE any mutations so we can revert on failure
        let snapshot = self.state.snapshot();

        // Transfer value to contract
        if tx.inner.value > 0 {
            self.state
                .execute_transfer(&sender, &contract_addr, tx.inner.value)
                .map_err(|e| {
                    CoreError::InvalidStateTransition(format!("value transfer failed: {e}"))
                })?;
        }

        let vm_gas_limit = tx.inner.gas_limit.saturating_sub(CONTRACT_CALL_BASE_GAS);
        let ctx = ExecutionContext {
            caller: sender,
            address: contract_addr,
            value: tx.inner.value,
            call_data: tx.inner.data.clone(),
            block_height: self.block_height,
            timestamp: self.block_timestamp,
        };

        let mut vm = VmEngine::new(vm_gas_limit);
        let result = {
            let mut host = StateHost::new(&mut *self.state, sender, contract_addr);
            vm.execute(&bytecode, &ctx, &mut host)
        };

        match result {
            Ok(exec_result) => {
                let total_gas = CONTRACT_CALL_BASE_GAS.saturating_add(exec_result.gas_used);
                if exec_result.success {
                    let logs = exec_result
                        .logs
                        .into_iter()
                        .map(|vl| Log {
                            address: vl.address,
                            topics: vl.topics,
                            data: vl.data,
                        })
                        .collect();
                    Ok((true, total_gas, logs, exec_result.return_data))
                } else {
                    *self.state = snapshot;
                    Ok((false, total_gas, vec![], exec_result.return_data))
                }
            }
            Err(_) => {
                *self.state = snapshot;
                Ok((false, tx.inner.gas_limit, vec![], vec![]))
            }
        }
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bitquid_core::transaction::Transaction;
    use bitquid_core::{Account, ChainConfig};
    use bitquid_crypto::KeyPair;

    fn setup() -> (WorldState, ChainConfig, KeyPair) {
        let mut state = WorldState::new();
        let kp = KeyPair::generate();
        state.set_account(kp.address(), Account::new(1_000_000_000));
        (state, ChainConfig::dev(), kp)
    }

    fn simple_bytecode_push42_halt() -> Vec<u8> {
        // PUSH 42, HALT
        let mut bc = vec![0x30]; // PUSH
        bc.extend_from_slice(&42u64.to_be_bytes());
        bc.push(0x62); // HALT
        bc
    }

    fn sstore_sload_bytecode() -> Vec<u8> {
        // PUSH key=1, PUSH val=99, SSTORE, PUSH key=1, SLOAD, HALT
        let mut bc = Vec::new();
        bc.push(0x30);
        bc.extend_from_slice(&1u64.to_be_bytes()); // PUSH 1 (key)
        bc.push(0x30);
        bc.extend_from_slice(&99u64.to_be_bytes()); // PUSH 99 (val)
        bc.push(0x51); // SSTORE
        bc.push(0x30);
        bc.extend_from_slice(&1u64.to_be_bytes()); // PUSH 1 (key)
        bc.push(0x50); // SLOAD
        bc.push(0x62); // HALT
        bc
    }

    fn make_deploy_tx(kp: &KeyPair, bytecode: Vec<u8>, nonce: u64) -> SignedTransaction {
        let tx = Transaction {
            tx_type: TransactionType::ContractCreate,
            nonce,
            from: kp.address(),
            to: Address::ZERO,
            value: 0,
            data: bytecode,
            gas_limit: 10_000_000,
            gas_price: 1,
            chain_id: 1337,
        };
        tx.sign(kp)
    }

    fn make_call_tx(
        kp: &KeyPair,
        contract: Address,
        calldata: Vec<u8>,
        nonce: u64,
    ) -> SignedTransaction {
        let tx = Transaction {
            tx_type: TransactionType::ContractCall,
            nonce,
            from: kp.address(),
            to: contract,
            value: 0,
            data: calldata,
            gas_limit: 10_000_000,
            gas_price: 1,
            chain_id: 1337,
        };
        tx.sign(kp)
    }

    #[test]
    fn test_deploy_contract() {
        let (mut state, config, kp) = setup();
        let bytecode = simple_bytecode_push42_halt();
        let stx = make_deploy_tx(&kp, bytecode.clone(), 0);

        let expected_addr = derive_contract_address(&kp.address(), 0);

        let mut exec = BlockExecutor::new(&mut state, &config, 1, 1000);
        let receipt = exec.execute_transaction(&stx, 0).unwrap();

        assert!(receipt.success);
        assert_eq!(receipt.return_data, expected_addr.0.to_vec());

        assert!(state.get_account(&expected_addr).unwrap().is_contract);
        assert_eq!(state.get_code(&expected_addr).unwrap(), bytecode.as_slice());
    }

    #[test]
    fn test_deploy_and_call() {
        let (mut state, config, kp) = setup();
        let bytecode = simple_bytecode_push42_halt();
        let deploy_tx = make_deploy_tx(&kp, bytecode, 0);

        let contract_addr = derive_contract_address(&kp.address(), 0);

        let mut exec = BlockExecutor::new(&mut state, &config, 1, 1000);
        let deploy_receipt = exec.execute_transaction(&deploy_tx, 0).unwrap();
        assert!(deploy_receipt.success);

        let call_tx = make_call_tx(&kp, contract_addr, vec![], 1);
        let call_receipt = exec.execute_transaction(&call_tx, 1).unwrap();
        assert!(call_receipt.success);
        assert_eq!(call_receipt.return_data, 42u64.to_be_bytes().to_vec());
    }

    #[test]
    fn test_contract_with_storage() {
        let (mut state, config, kp) = setup();
        let bytecode = sstore_sload_bytecode();
        let deploy_tx = make_deploy_tx(&kp, bytecode, 0);
        let contract_addr = derive_contract_address(&kp.address(), 0);

        let mut exec = BlockExecutor::new(&mut state, &config, 1, 1000);
        exec.execute_transaction(&deploy_tx, 0).unwrap();

        let call_tx = make_call_tx(&kp, contract_addr, vec![], 1);
        let receipt = exec.execute_transaction(&call_tx, 1).unwrap();
        assert!(receipt.success);
        assert_eq!(receipt.return_data, 99u64.to_be_bytes().to_vec());
    }

    #[test]
    fn test_call_nonexistent_contract() {
        let (mut state, config, kp) = setup();
        let fake_addr =
            Address::from_hex("0x0000000000000000000000000000000000DEAD01").unwrap();
        let call_tx = make_call_tx(&kp, fake_addr, vec![], 0);

        let mut exec = BlockExecutor::new(&mut state, &config, 1, 1000);
        let err = exec.execute_transaction(&call_tx, 0);
        assert!(err.is_err());
    }

    #[test]
    fn test_deploy_too_large() {
        let (mut state, config, kp) = setup();
        let big = vec![0x62; MAX_CONTRACT_SIZE + 1]; // all HALT bytes
        let stx = make_deploy_tx(&kp, big, 0);

        let mut exec = BlockExecutor::new(&mut state, &config, 1, 1000);
        let err = exec.execute_transaction(&stx, 0);
        assert!(err.is_err());
    }

    #[test]
    fn test_out_of_gas_reverts_state() {
        let (mut state, config, kp) = setup();
        let bytecode = sstore_sload_bytecode();
        let deploy_tx = make_deploy_tx(&kp, bytecode, 0);
        let contract_addr = derive_contract_address(&kp.address(), 0);

        let mut exec = BlockExecutor::new(&mut state, &config, 1, 1000);
        exec.execute_transaction(&deploy_tx, 0).unwrap();

        // Call with extremely low gas limit — VM should run out of gas
        let tx = Transaction {
            tx_type: TransactionType::ContractCall,
            nonce: 1,
            from: kp.address(),
            to: contract_addr,
            value: 0,
            data: vec![],
            gas_limit: CONTRACT_CALL_BASE_GAS + 1, // barely any VM gas
            gas_price: 1,
            chain_id: 1337,
        };
        let call_tx = tx.sign(&kp);

        let receipt = exec.execute_transaction(&call_tx, 1).unwrap();
        assert!(!receipt.success, "out-of-gas call must fail");
    }

    #[test]
    fn test_transfer_still_works() {
        let (mut state, config, kp) = setup();
        let recipient =
            Address::from_hex("0x0000000000000000000000000000000000000002").unwrap();
        let tx = Transaction {
            tx_type: TransactionType::Transfer,
            nonce: 0,
            from: kp.address(),
            to: recipient,
            value: 5000,
            data: vec![],
            gas_limit: 21_000,
            gas_price: 1,
            chain_id: 1337,
        };
        let stx = tx.sign(&kp);

        let mut exec = BlockExecutor::new(&mut state, &config, 1, 1000);
        let receipt = exec.execute_transaction(&stx, 0).unwrap();
        assert!(receipt.success);
        assert_eq!(state.get_balance(&recipient), 5000);
    }

    #[test]
    fn test_deploy_with_value() {
        let (mut state, config, kp) = setup();
        let bytecode = simple_bytecode_push42_halt();
        let tx = Transaction {
            tx_type: TransactionType::ContractCreate,
            nonce: 0,
            from: kp.address(),
            to: Address::ZERO,
            value: 1000,
            data: bytecode,
            gas_limit: 10_000_000,
            gas_price: 1,
            chain_id: 1337,
        };
        let stx = tx.sign(&kp);
        let contract_addr = derive_contract_address(&kp.address(), 0);

        let mut exec = BlockExecutor::new(&mut state, &config, 1, 1000);
        let receipt = exec.execute_transaction(&stx, 0).unwrap();
        assert!(receipt.success);
        assert_eq!(state.get_balance(&contract_addr), 1000);
    }
}
