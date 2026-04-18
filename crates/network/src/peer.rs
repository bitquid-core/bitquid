use std::net::SocketAddr;
use std::time::Instant;

use bitquid_core::Address;
use dashmap::DashMap;
use tracing::{debug, warn};

use crate::error::NetworkError;

/// Information about a connected peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: Address,
    pub addr: SocketAddr,
    pub protocol_version: u32,
    pub best_height: u64,
    pub connected_at: Instant,
    pub last_seen: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub latency_ms: u32,
    pub is_inbound: bool,
    pub user_agent: String,
    pub score: i32,
}

impl PeerInfo {
    pub fn new(node_id: Address, addr: SocketAddr, is_inbound: bool) -> Self {
        let now = Instant::now();
        Self {
            node_id,
            addr,
            protocol_version: 0,
            best_height: 0,
            connected_at: now,
            last_seen: now,
            bytes_sent: 0,
            bytes_received: 0,
            latency_ms: 0,
            is_inbound,
            user_agent: String::new(),
            score: 100,
        }
    }

    pub fn uptime(&self) -> std::time::Duration {
        self.connected_at.elapsed()
    }
}

/// Manages all peer connections
pub struct PeerManager {
    peers: DashMap<Address, PeerInfo>,
    banned: DashMap<Address, (String, Instant)>,
    max_peers: usize,
    max_inbound: usize,
}

impl PeerManager {
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: DashMap::new(),
            banned: DashMap::new(),
            max_peers,
            max_inbound: max_peers / 2,
        }
    }

    pub fn add_peer(&self, info: PeerInfo) -> Result<(), NetworkError> {
        if self.is_banned(&info.node_id) {
            return Err(NetworkError::BannedPeer(info.node_id.to_hex()));
        }

        if self.peers.len() >= self.max_peers {
            return Err(NetworkError::MaxPeersReached(self.max_peers));
        }

        if info.is_inbound {
            let inbound_count = self.peers.iter().filter(|p| p.is_inbound).count();
            if inbound_count >= self.max_inbound {
                return Err(NetworkError::MaxPeersReached(self.max_inbound));
            }
        }

        debug!("Added peer {} at {}", info.node_id, info.addr);
        self.peers.insert(info.node_id, info);
        Ok(())
    }

    pub fn remove_peer(&self, node_id: &Address) -> Option<PeerInfo> {
        self.peers.remove(node_id).map(|(_, info)| info)
    }

    pub fn get_peer(&self, node_id: &Address) -> Option<PeerInfo> {
        self.peers.get(node_id).map(|p| p.clone())
    }

    pub fn update_peer<F>(&self, node_id: &Address, f: F)
    where
        F: FnOnce(&mut PeerInfo),
    {
        if let Some(mut peer) = self.peers.get_mut(node_id) {
            f(&mut peer);
        }
    }

    pub fn ban_peer(&self, node_id: &Address, reason: String) {
        warn!("Banning peer {}: {}", node_id, reason);
        self.peers.remove(node_id);
        self.banned.insert(*node_id, (reason, Instant::now()));
    }

    pub fn is_banned(&self, node_id: &Address) -> bool {
        self.banned.contains_key(node_id)
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn connected_peers(&self) -> Vec<PeerInfo> {
        self.peers.iter().map(|p| p.clone()).collect()
    }

    pub fn best_peer(&self) -> Option<PeerInfo> {
        self.peers
            .iter()
            .max_by_key(|p| p.best_height)
            .map(|p| p.clone())
    }

    /// Adjust peer score (positive = good, negative = bad)
    pub fn adjust_score(&self, node_id: &Address, delta: i32) {
        if let Some(mut peer) = self.peers.get_mut(node_id) {
            peer.score = (peer.score + delta).clamp(-1000, 1000);
            if peer.score < -100 {
                drop(peer);
                self.ban_peer(node_id, "score too low".into());
            }
        }
    }

    /// Get peers sorted by score (best first)
    pub fn peers_by_score(&self) -> Vec<PeerInfo> {
        let mut peers: Vec<PeerInfo> = self.peers.iter().map(|p| p.clone()).collect();
        peers.sort_by(|a, b| b.score.cmp(&a.score));
        peers
    }
}
