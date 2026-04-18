use bitquid_core::block::Block;
use bitquid_core::transaction::SignedTransaction;
use bitquid_core::Hash;
use bitquid_crypto::Address;
use serde::{Deserialize, Serialize};

/// Protocol version (used in frame header as u16)
pub const PROTOCOL_VERSION: u16 = 1;

/// Magic bytes for the Bitquid-Fi network
pub const NETWORK_MAGIC: [u8; 4] = [0xBF, 0x51, 0xD0, 0x01];

/// Maximum message size (4 MB — sufficient for max block + overhead)
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

/// Message types sent over the P2P network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// Initial handshake
    Handshake(HandshakeData),
    HandshakeAck(HandshakeData),

    /// Ping/Pong for keepalive
    Ping(u64),
    Pong(u64),

    /// Transaction propagation
    NewTransaction(SignedTransaction),
    /// Request specific transactions by hash
    GetTransactions(Vec<Hash>),
    /// Response with transactions
    Transactions(Vec<SignedTransaction>),

    /// Block propagation
    NewBlock(Box<Block>),
    /// Request blocks by height range
    GetBlocks { start_height: u64, count: u32 },
    /// Response with blocks
    Blocks(Vec<Block>),
    /// Announce new block hash (header-first sync)
    BlockAnnounce { height: u64, hash: Hash },

    /// Consensus message relay
    ConsensusMessage(Vec<u8>),

    /// Peer discovery
    GetPeers,
    Peers(Vec<PeerAddr>),

    /// Disconnect notification
    Disconnect(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeData {
    pub protocol_version: u32,
    pub chain_id: u32,
    pub network_magic: [u8; 4],
    pub node_id: Address,
    pub best_height: u64,
    pub best_hash: Hash,
    pub listen_port: u16,
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAddr {
    pub addr: String,
    pub port: u16,
    pub node_id: Option<Address>,
}

/// Commands for the P2P network service
#[derive(Debug)]
pub enum NetworkCommand {
    /// Broadcast a message to all connected peers
    Broadcast(NetworkMessage),
    /// Send a message to a specific peer
    SendTo(Address, NetworkMessage),
    /// Connect to a new peer
    Connect(String),
    /// Disconnect a peer
    DisconnectPeer(Address),
    /// Ban a peer
    BanPeer(Address, String),
    /// Request peer list
    GetPeerCount,
}
