use bitquid_core::{Block, Hash, Address};
use bitquid_crypto::Signature;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    PrePrepare,
    Prepare,
    Commit,
    ViewChange,
    NewView,
    Checkpoint,
}

/// PBFT consensus message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusMessage {
    pub msg_type: MessageType,
    pub view: u64,
    pub sequence: u64,
    pub block_hash: Hash,
    pub sender: Address,
    pub signature: Signature,
    pub payload: MessagePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePayload {
    PrePrepare {
        block: Box<Block>,
    },
    Prepare,
    Commit,
    ViewChange {
        new_view: u64,
        last_checkpoint: u64,
        /// Proof that the view change is valid (prepare certificates)
        prepared_proofs: Vec<PreparedProof>,
    },
    NewView {
        new_view: u64,
        view_change_proofs: Vec<ConsensusMessage>,
        pre_prepare: Box<ConsensusMessage>,
    },
    Checkpoint {
        height: u64,
        state_root: Hash,
    },
}

/// Proof that a block was prepared in a previous view
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedProof {
    pub view: u64,
    pub sequence: u64,
    pub block_hash: Hash,
    pub prepare_signatures: Vec<(Address, Signature)>,
}

impl ConsensusMessage {
    /// Compute the message digest for signing
    pub fn digest(&self) -> Hash {
        let mut msg_for_hash = self.clone();
        msg_for_hash.signature = Signature::default();
        let encoded = bincode::serialize(&msg_for_hash).expect("message serialization");
        bitquid_crypto::blake3_hash(&encoded)
    }

    pub fn sign(&mut self, keypair: &bitquid_crypto::KeyPair) {
        let digest = self.digest();
        self.signature = keypair.sign_hash(&digest);
    }

    pub fn verify_signature(&self, pubkey: &bitquid_crypto::PublicKey) -> bool {
        let digest = self.digest();
        self.signature.verify_prehashed(&digest, pubkey).is_ok()
    }
}
