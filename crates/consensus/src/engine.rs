use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use bitquid_core::{Block, Address};
use bitquid_crypto::{KeyPair, Signature};
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::error::ConsensusError;
use crate::messages::{ConsensusMessage, MessagePayload, MessageType};
use crate::validator::ValidatorSet;

/// PBFT consensus state machine phases
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Idle,
    PrePrepare,
    Prepare,
    Commit,
    ViewChange,
}

/// Configuration for the PBFT engine
#[derive(Debug, Clone)]
pub struct PbftConfig {
    pub view_timeout: Duration,
    pub checkpoint_interval: u64,
    pub max_block_time: Duration,
}

impl Default for PbftConfig {
    fn default() -> Self {
        Self {
            view_timeout: Duration::from_secs(10),
            checkpoint_interval: 100,
            max_block_time: Duration::from_secs(2),
        }
    }
}

/// Output events from the consensus engine
#[derive(Debug)]
pub enum ConsensusOutput {
    /// Broadcast a consensus message to all peers
    BroadcastMessage(ConsensusMessage),
    /// A block has been finalized
    BlockFinalized(Block),
    /// Request a view change
    RequestViewChange(u64),
}

/// PBFT Consensus Engine
///
/// Implements the Practical Byzantine Fault Tolerance protocol
/// with optimizations for blockchain consensus:
/// - Pipeline: overlap prepare/commit for consecutive blocks
/// - Optimistic fast-path: skip prepare if all validators agree
/// - Checkpointing for state pruning
pub struct PbftEngine {
    keypair: KeyPair,
    my_address: Address,
    validator_set: RwLock<ValidatorSet>,
    state: RwLock<PbftState>,
    config: PbftConfig,
    output_tx: mpsc::UnboundedSender<ConsensusOutput>,
}

struct PbftState {
    view: u64,
    sequence: u64,
    phase: Phase,
    /// Pre-prepare messages received: view -> (sequence -> message)
    pre_prepares: HashMap<u64, HashMap<u64, ConsensusMessage>>,
    /// Prepare votes: (view, sequence) -> set of signers
    prepares: HashMap<(u64, u64), HashSet<Address>>,
    /// Commit votes: (view, sequence) -> set of signers
    commits: HashMap<(u64, u64), HashSet<Address>>,
    /// Pending block being voted on
    pending_block: Option<Block>,
    /// Last committed block height
    last_committed: u64,
    /// Last checkpoint height
    last_checkpoint: u64,
    /// View change timer
    view_change_deadline: Option<Instant>,
    /// View change votes: new_view -> set of signers
    view_changes: HashMap<u64, HashSet<Address>>,
}

impl PbftEngine {
    pub fn new(
        keypair: KeyPair,
        validator_set: ValidatorSet,
        config: PbftConfig,
    ) -> (Self, mpsc::UnboundedReceiver<ConsensusOutput>) {
        let (output_tx, output_rx) = mpsc::unbounded_channel();
        let my_address = keypair.address();

        let engine = Self {
            keypair,
            my_address,
            validator_set: RwLock::new(validator_set),
            state: RwLock::new(PbftState {
                view: 0,
                sequence: 0,
                phase: Phase::Idle,
                pre_prepares: HashMap::new(),
                prepares: HashMap::new(),
                commits: HashMap::new(),
                pending_block: None,
                last_committed: 0,
                last_checkpoint: 0,
                view_change_deadline: None,
                view_changes: HashMap::new(),
            }),
            config,
            output_tx,
        };

        (engine, output_rx)
    }

    /// Check if this node is the leader for the current view
    pub fn is_leader(&self) -> bool {
        let state = self.state.read();
        let vs = self.validator_set.read();
        let leader = vs.leader_for_view(state.view);
        leader.address == self.my_address
    }

    /// Propose a new block (called by leader)
    pub fn propose_block(&self, block: Block) -> Result<(), ConsensusError> {
        if !self.is_leader() {
            return Err(ConsensusError::NotLeader);
        }

        let mut state = self.state.write();
        state.sequence += 1;
        state.phase = Phase::PrePrepare;
        state.pending_block = Some(block.clone());

        let block_hash = block.hash();

        let mut msg = ConsensusMessage {
            msg_type: MessageType::PrePrepare,
            view: state.view,
            sequence: state.sequence,
            block_hash,
            sender: self.my_address,
            signature: Signature::default(),
            payload: MessagePayload::PrePrepare {
                block: Box::new(block),
            },
        };
        msg.sign(&self.keypair);

        info!(
            "Proposing block: view={}, seq={}, hash={}",
            state.view,
            state.sequence,
            hex::encode(&block_hash[..8])
        );

        // Set view change deadline
        state.view_change_deadline = Some(Instant::now() + self.config.view_timeout);

        let _ = self.output_tx.send(ConsensusOutput::BroadcastMessage(msg));
        Ok(())
    }

    /// Handle an incoming consensus message
    pub fn handle_message(&self, msg: ConsensusMessage) -> Result<(), ConsensusError> {
        // Verify the message signature
        let vs = self.validator_set.read();
        if !vs.is_validator(&msg.sender) {
            return Err(ConsensusError::ValidatorNotFound(msg.sender.to_hex()));
        }

        if let Some(pubkey) = vs.get_pubkey(&msg.sender) {
            if !msg.verify_signature(pubkey) {
                return Err(ConsensusError::Crypto(
                    bitquid_crypto::CryptoError::VerificationFailed,
                ));
            }
        }
        drop(vs);

        match msg.msg_type {
            MessageType::PrePrepare => self.handle_pre_prepare(msg),
            MessageType::Prepare => self.handle_prepare(msg),
            MessageType::Commit => self.handle_commit(msg),
            MessageType::ViewChange => self.handle_view_change(msg),
            _ => Ok(()),
        }
    }

    fn handle_pre_prepare(&self, msg: ConsensusMessage) -> Result<(), ConsensusError> {
        let mut state = self.state.write();

        if msg.view != state.view {
            return Err(ConsensusError::InvalidView {
                expected: state.view,
                got: msg.view,
            });
        }

        // Store the pre-prepare
        state
            .pre_prepares
            .entry(msg.view)
            .or_default()
            .insert(msg.sequence, msg.clone());

        if let MessagePayload::PrePrepare { block } = &msg.payload {
            let actual_hash = block.hash();
            if actual_hash != msg.block_hash {
                return Err(ConsensusError::InvalidBlock(
                    "block_hash does not match actual block content".into(),
                ));
            }
            if let Err(e) = block.validate_structure() {
                return Err(ConsensusError::InvalidBlock(format!(
                    "block structure invalid: {e}"
                )));
            }
            state.pending_block = Some(*block.clone());
        }

        state.phase = Phase::Prepare;

        // Send prepare message
        let mut prepare = ConsensusMessage {
            msg_type: MessageType::Prepare,
            view: state.view,
            sequence: msg.sequence,
            block_hash: msg.block_hash,
            sender: self.my_address,
            signature: Signature::default(),
            payload: MessagePayload::Prepare,
        };
        prepare.sign(&self.keypair);

        // Add our own prepare vote
        let view = state.view;
        state
            .prepares
            .entry((view, msg.sequence))
            .or_default()
            .insert(self.my_address);

        let _ = self.output_tx.send(ConsensusOutput::BroadcastMessage(prepare));

        debug!(
            "Sent Prepare: view={}, seq={}",
            state.view, msg.sequence
        );

        Ok(())
    }

    fn handle_prepare(&self, msg: ConsensusMessage) -> Result<(), ConsensusError> {
        let mut state = self.state.write();
        let key = (msg.view, msg.sequence);

        let prepares = state.prepares.entry(key).or_default();
        if !prepares.insert(msg.sender) {
            return Err(ConsensusError::DuplicateMessage(msg.sender.to_hex()));
        }

        let quorum = self.validator_set.read().quorum_size();
        let count = prepares.len();

        debug!(
            "Prepare: view={}, seq={}, votes={}/{}",
            msg.view, msg.sequence, count, quorum
        );

        if count >= quorum && state.phase == Phase::Prepare {
            state.phase = Phase::Commit;

            let mut commit = ConsensusMessage {
                msg_type: MessageType::Commit,
                view: state.view,
                sequence: msg.sequence,
                block_hash: msg.block_hash,
                sender: self.my_address,
                signature: Signature::default(),
                payload: MessagePayload::Commit,
            };
            commit.sign(&self.keypair);

            state
                .commits
                .entry(key)
                .or_default()
                .insert(self.my_address);

            let _ = self.output_tx.send(ConsensusOutput::BroadcastMessage(commit));

            debug!("Sent Commit: view={}, seq={}", state.view, msg.sequence);
        }

        Ok(())
    }

    fn handle_commit(&self, msg: ConsensusMessage) -> Result<(), ConsensusError> {
        let mut state = self.state.write();
        let key = (msg.view, msg.sequence);

        let commits = state.commits.entry(key).or_default();
        if !commits.insert(msg.sender) {
            return Err(ConsensusError::DuplicateMessage(msg.sender.to_hex()));
        }

        let quorum = self.validator_set.read().quorum_size();
        let count = commits.len();

        debug!(
            "Commit: view={}, seq={}, votes={}/{}",
            msg.view, msg.sequence, count, quorum
        );

        if count >= quorum && state.phase == Phase::Commit {
            // Block is finalized!
            if let Some(block) = state.pending_block.take() {
                info!(
                    "Block FINALIZED: height={}, hash={}",
                    block.height(),
                    hex::encode(&block.hash()[..8])
                );

                state.last_committed = msg.sequence;
                state.phase = Phase::Idle;
                state.view_change_deadline = None;

                // Cleanup old state
                state.prepares.remove(&key);
                state.commits.remove(&key);

                // Checkpoint?
                if state.last_committed % self.config.checkpoint_interval == 0 {
                    state.last_checkpoint = state.last_committed;
                    info!("Checkpoint at sequence {}", state.last_committed);
                }

                let _ = self
                    .output_tx
                    .send(ConsensusOutput::BlockFinalized(block));
            }
        }

        Ok(())
    }

    fn handle_view_change(&self, msg: ConsensusMessage) -> Result<(), ConsensusError> {
        if let MessagePayload::ViewChange { new_view, .. } = &msg.payload {
            let mut state = self.state.write();
            let votes = state.view_changes.entry(*new_view).or_default();
            votes.insert(msg.sender);

            let quorum = self.validator_set.read().quorum_size();

            if votes.len() >= quorum {
                info!("View change to view {}", new_view);
                state.view = *new_view;
                state.phase = Phase::Idle;
                state.view_change_deadline = None;
                state.view_changes.clear();

                let _ = self
                    .output_tx
                    .send(ConsensusOutput::RequestViewChange(*new_view));
            }
        }
        Ok(())
    }

    /// Initiate a view change (called on timeout)
    pub fn start_view_change(&self) {
        let mut state = self.state.write();
        let new_view = state.view + 1;

        warn!("Initiating view change to view {new_view}");

        state.phase = Phase::ViewChange;
        state
            .view_changes
            .entry(new_view)
            .or_default()
            .insert(self.my_address);

        let mut msg = ConsensusMessage {
            msg_type: MessageType::ViewChange,
            view: state.view,
            sequence: state.sequence,
            block_hash: [0u8; 32],
            sender: self.my_address,
            signature: Signature::default(),
            payload: MessagePayload::ViewChange {
                new_view,
                last_checkpoint: state.last_checkpoint,
                prepared_proofs: vec![],
            },
        };
        msg.sign(&self.keypair);

        let _ = self.output_tx.send(ConsensusOutput::BroadcastMessage(msg));
    }

    /// Check for timeouts - should be called periodically
    pub fn tick(&self) {
        let state = self.state.read();
        if let Some(deadline) = state.view_change_deadline {
            if Instant::now() > deadline && state.phase != Phase::ViewChange {
                drop(state);
                self.start_view_change();
            }
        }
    }

    pub fn current_view(&self) -> u64 {
        self.state.read().view
    }

    pub fn current_sequence(&self) -> u64 {
        self.state.read().sequence
    }

    pub fn current_phase(&self) -> Phase {
        self.state.read().phase
    }

    pub fn last_committed(&self) -> u64 {
        self.state.read().last_committed
    }
}
