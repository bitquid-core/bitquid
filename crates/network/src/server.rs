use std::net::SocketAddr;
use std::sync::Arc;

use bitquid_core::Address;
use bitquid_crypto::KeyPair;
use dashmap::DashMap;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

// codec is used for standalone frame encoding but P2P now uses noise transport
use crate::error::NetworkError;
use crate::noise;
use crate::peer::{PeerInfo, PeerManager};
use crate::protocol::{HandshakeData, NetworkCommand, NetworkMessage, PROTOCOL_VERSION, NETWORK_MAGIC};
use crate::rate_limiter::{RateLimiter, RateLimitConfig, RateLimitResult};

type PeerWriter = (Arc<Mutex<OwnedWriteHalf>>, Arc<Mutex<noise::CipherState>>);
type PeerWriters = Arc<DashMap<Address, PeerWriter>>;

/// P2P network server
pub struct P2PServer {
    keypair: Arc<KeyPair>,
    peer_manager: Arc<PeerManager>,
    writers: PeerWriters,
    rate_limiter: Arc<RateLimiter>,
    listen_addr: SocketAddr,
    chain_id: u32,
    cmd_rx: mpsc::UnboundedReceiver<NetworkCommand>,
    msg_tx: mpsc::UnboundedSender<(Address, NetworkMessage)>,
}

/// Handle for interacting with the P2P server from other components
#[derive(Clone)]
pub struct P2PHandle {
    pub cmd_tx: mpsc::UnboundedSender<NetworkCommand>,
    pub peer_manager: Arc<PeerManager>,
}

impl P2PServer {
    pub fn new(
        keypair: KeyPair,
        listen_addr: SocketAddr,
        chain_id: u32,
        max_peers: usize,
    ) -> (Self, P2PHandle, mpsc::UnboundedReceiver<(Address, NetworkMessage)>) {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let peer_manager = Arc::new(PeerManager::new(max_peers));
        let writers: PeerWriters = Arc::new(DashMap::new());
        let rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::default()));

        let server = Self {
            keypair: Arc::new(keypair),
            peer_manager: peer_manager.clone(),
            writers: writers.clone(),
            rate_limiter,
            listen_addr,
            chain_id,
            cmd_rx,
            msg_tx,
        };

        let handle = P2PHandle {
            cmd_tx,
            peer_manager,
        };

        (server, handle, msg_rx)
    }

    pub async fn run(mut self) -> Result<(), NetworkError> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!("P2P server listening on {}", self.listen_addr);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let keypair = self.keypair.clone();
                            let peer_manager = self.peer_manager.clone();
                            let msg_tx = self.msg_tx.clone();
                            let chain_id = self.chain_id;
                            let writers = self.writers.clone();
                            let rl = self.rate_limiter.clone();

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_inbound(
                                    stream, addr, keypair, peer_manager, msg_tx, chain_id, writers, rl,
                                ).await {
                                    warn!("Inbound connection from {addr} failed: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept failed: {e}");
                        }
                    }
                }

                Some(cmd) = self.cmd_rx.recv() => {
                    self.handle_command(cmd).await;
                }

                else => break,
            }
        }

        info!("P2P server shutting down");
        Ok(())
    }

    async fn handle_inbound(
        mut stream: TcpStream,
        addr: SocketAddr,
        keypair: Arc<KeyPair>,
        peer_manager: Arc<PeerManager>,
        msg_tx: mpsc::UnboundedSender<(Address, NetworkMessage)>,
        chain_id: u32,
        writers: PeerWriters,
        rate_limiter: Arc<RateLimiter>,
    ) -> Result<(), NetworkError> {
        debug!("New inbound connection from {addr}");

        // 1) Post-quantum Noise handshake (responder side)
        let identity = bincode::serialize(&keypair.address())
            .map_err(|e| NetworkError::Serialization(e.to_string()))?;
        let transport = noise::handshake_responder(&mut stream, &identity).await?;
        let remote_identity: Address = bincode::deserialize(&transport.remote_identity)
            .map_err(|e| NetworkError::Serialization(e.to_string()))?;

        debug!("Noise handshake complete with {remote_identity}");

        // Split into encrypted send/recv ciphers
        let send_cipher = Arc::new(Mutex::new(transport.send_cipher));
        let recv_cipher = Arc::new(Mutex::new(transport.recv_cipher));

        let (mut read_half, mut write_half) = stream.into_split();

        // 2) Protocol handshake over encrypted channel
        {
            let mut rc = recv_cipher.lock().await;
            let plaintext = noise::read_encrypted(&mut read_half, &mut rc).await?;
            let msg: NetworkMessage = bincode::deserialize(&plaintext)
                .map_err(|e| NetworkError::Serialization(e.to_string()))?;
            match msg {
                NetworkMessage::Handshake(hs) => {
                    if hs.network_magic != NETWORK_MAGIC {
                        return Err(NetworkError::HandshakeFailed("wrong network".into()));
                    }
                    if hs.chain_id != chain_id {
                        return Err(NetworkError::HandshakeFailed("wrong chain_id".into()));
                    }
                }
                _ => return Err(NetworkError::HandshakeFailed("expected handshake".into())),
            }
        }
        {
            let our_handshake = HandshakeData {
                protocol_version: PROTOCOL_VERSION as u32,
                chain_id,
                network_magic: NETWORK_MAGIC,
                node_id: keypair.address(),
                best_height: 0,
                best_hash: [0u8; 32],
                listen_port: addr.port(),
                user_agent: "bitquid/0.1.0".into(),
            };
            let ack_bytes = bincode::serialize(&NetworkMessage::HandshakeAck(our_handshake))
                .map_err(|e| NetworkError::Serialization(e.to_string()))?;
            let mut sc = send_cipher.lock().await;
            noise::write_encrypted(&mut write_half, &mut sc, &ack_bytes).await?;
        }

        let write_half = Arc::new(Mutex::new(write_half));
        let peer = PeerInfo::new(remote_identity, addr, true);
        peer_manager.add_peer(peer)?;
        writers.insert(remote_identity, (write_half.clone(), send_cipher.clone()));

        info!(
            "Peer connected (encrypted): {} from {addr}",
            remote_identity,
        );

        // 3) Encrypted message loop
        loop {
            let plaintext = {
                let mut rc = recv_cipher.lock().await;
                match noise::read_encrypted(&mut read_half, &mut rc).await {
                    Ok(p) => p,
                    Err(_) => break,
                }
            };

            let msg: NetworkMessage = match bincode::deserialize(&plaintext) {
                Ok(m) => m,
                Err(e) => {
                    warn!("Protocol error from {}: {e}", remote_identity);
                    break;
                }
            };

            match rate_limiter.check(&remote_identity) {
                RateLimitResult::Allowed => {
                    let _ = msg_tx.send((remote_identity, msg));
                }
                RateLimitResult::Throttled => {
                    debug!("Rate-limited message from {}", remote_identity);
                }
                RateLimitResult::BanRecommended => {
                    warn!("Rate limit exceeded, banning {}", remote_identity);
                    peer_manager.ban_peer(&remote_identity, "rate limit exceeded".into());
                    break;
                }
            }

            peer_manager.update_peer(&remote_identity, |p| {
                p.last_seen = std::time::Instant::now();
            });
        }

        rate_limiter.remove_peer(&remote_identity);
        writers.remove(&remote_identity);
        peer_manager.remove_peer(&remote_identity);
        info!("Peer disconnected: {}", remote_identity);
        Ok(())
    }

    async fn handle_command(&self, cmd: NetworkCommand) {
        match cmd {
            NetworkCommand::Broadcast(msg) => {
                let payload = match bincode::serialize(&msg) {
                    Ok(e) => e,
                    Err(e) => {
                        error!("Failed to serialize broadcast message: {e}");
                        return;
                    }
                };
                let peer_ids: Vec<Address> =
                    self.writers.iter().map(|r| *r.key()).collect();
                debug!("Broadcasting message to {} peers", peer_ids.len());
                for peer_id in peer_ids {
                    if let Some(entry) = self.writers.get(&peer_id) {
                        let (wh, sc) = entry.value().clone();
                        let data = payload.clone();
                        let writers_ref = self.writers.clone();
                        let pm = self.peer_manager.clone();
                        tokio::spawn(async move {
                            let mut cipher = sc.lock().await;
                            let mut w = wh.lock().await;
                            if let Err(e) = noise::write_encrypted(&mut *w, &mut cipher, &data).await {
                                warn!("Failed to send to {peer_id}: {e}");
                                drop(w);
                                drop(cipher);
                                writers_ref.remove(&peer_id);
                                pm.remove_peer(&peer_id);
                            }
                        });
                    }
                }
            }
            NetworkCommand::SendTo(peer_id, msg) => {
                let payload = match bincode::serialize(&msg) {
                    Ok(e) => e,
                    Err(e) => {
                        error!("Failed to serialize message for {peer_id}: {e}");
                        return;
                    }
                };
                if let Some(entry) = self.writers.get(&peer_id) {
                    let (wh, sc) = entry.value().clone();
                    let writers_ref = self.writers.clone();
                    let pm = self.peer_manager.clone();
                    tokio::spawn(async move {
                        let mut cipher = sc.lock().await;
                        let mut w = wh.lock().await;
                        if let Err(e) = noise::write_encrypted(&mut *w, &mut cipher, &payload).await {
                            warn!("Failed to send to {peer_id}: {e}");
                            drop(w);
                            drop(cipher);
                            writers_ref.remove(&peer_id);
                            pm.remove_peer(&peer_id);
                        }
                    });
                } else {
                    warn!("SendTo: no writer for peer {peer_id}");
                }
            }
            NetworkCommand::Connect(addr) => {
                info!("Connecting to peer at {addr}");
                let keypair = self.keypair.clone();
                let pm = self.peer_manager.clone();
                let msg_tx = self.msg_tx.clone();
                let chain_id = self.chain_id;
                let writers = self.writers.clone();
                let rl = self.rate_limiter.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        Self::connect_outbound(&addr, keypair, pm, msg_tx, chain_id, writers, rl).await
                    {
                        warn!("Outbound connection to {addr} failed: {e}");
                    }
                });
            }
            NetworkCommand::DisconnectPeer(peer_id) => {
                info!("Disconnecting peer {peer_id}");
                if let Some((_, (wh, sc))) = self.writers.remove(&peer_id) {
                    let msg = bincode::serialize(&NetworkMessage::Disconnect(
                        "requested disconnect".into(),
                    ));
                    if let Ok(data) = msg {
                        let mut cipher = sc.lock().await;
                        let mut w = wh.lock().await;
                        let _ = noise::write_encrypted(&mut *w, &mut cipher, &data).await;
                        let _ = w.shutdown().await;
                    }
                }
                self.peer_manager.remove_peer(&peer_id);
            }
            NetworkCommand::BanPeer(peer_id, reason) => {
                info!("Banning peer {peer_id}: {reason}");
                if let Some((_, (wh, sc))) = self.writers.remove(&peer_id) {
                    let msg = bincode::serialize(&NetworkMessage::Disconnect(reason.clone()));
                    if let Ok(data) = msg {
                        let mut cipher = sc.lock().await;
                        let mut w = wh.lock().await;
                        let _ = noise::write_encrypted(&mut *w, &mut cipher, &data).await;
                        let _ = w.shutdown().await;
                    }
                }
                self.peer_manager.ban_peer(&peer_id, reason);
            }
            NetworkCommand::GetPeerCount => {
                debug!("Peer count: {}", self.peer_manager.peer_count());
            }
        }
    }

    async fn connect_outbound(
        addr: &str,
        keypair: Arc<KeyPair>,
        peer_manager: Arc<PeerManager>,
        msg_tx: mpsc::UnboundedSender<(Address, NetworkMessage)>,
        chain_id: u32,
        writers: PeerWriters,
        rate_limiter: Arc<RateLimiter>,
    ) -> Result<(), NetworkError> {
        let mut stream = TcpStream::connect(addr).await?;
        let socket_addr = stream.peer_addr()?;

        // 1) Post-quantum Noise handshake (initiator side)
        let identity = bincode::serialize(&keypair.address())
            .map_err(|e| NetworkError::Serialization(e.to_string()))?;
        let transport = noise::handshake_initiator(&mut stream, &identity).await?;
        let remote_identity: Address = bincode::deserialize(&transport.remote_identity)
            .map_err(|e| NetworkError::Serialization(e.to_string()))?;

        debug!("Noise handshake complete with {remote_identity}");

        let send_cipher = Arc::new(Mutex::new(transport.send_cipher));
        let recv_cipher = Arc::new(Mutex::new(transport.recv_cipher));

        let (mut read_half, mut write_half) = stream.into_split();

        // 2) Protocol handshake over encrypted channel
        let handshake = HandshakeData {
            protocol_version: PROTOCOL_VERSION as u32,
            chain_id,
            network_magic: NETWORK_MAGIC,
            node_id: keypair.address(),
            best_height: 0,
            best_hash: [0u8; 32],
            listen_port: 0,
            user_agent: "bitquid/0.1.0".into(),
        };
        {
            let hs_bytes = bincode::serialize(&NetworkMessage::Handshake(handshake))
                .map_err(|e| NetworkError::Serialization(e.to_string()))?;
            let mut sc = send_cipher.lock().await;
            noise::write_encrypted(&mut write_half, &mut sc, &hs_bytes).await?;
        }

        let remote = {
            let mut rc = recv_cipher.lock().await;
            let plaintext = noise::read_encrypted(&mut read_half, &mut rc).await?;
            let msg: NetworkMessage = bincode::deserialize(&plaintext)
                .map_err(|e| NetworkError::Serialization(e.to_string()))?;
            match msg {
                NetworkMessage::HandshakeAck(hs) => hs,
                _ => return Err(NetworkError::HandshakeFailed("expected ack".into())),
            }
        };

        let write_half = Arc::new(Mutex::new(write_half));
        let peer = PeerInfo::new(remote.node_id, socket_addr, false);
        peer_manager.add_peer(peer)?;
        writers.insert(remote.node_id, (write_half.clone(), send_cipher.clone()));

        info!("Outbound connected (encrypted) to {} at {addr}", remote.node_id);

        let remote_id = remote.node_id;
        let pm_clone = peer_manager.clone();
        let writers_clone = writers.clone();
        let rl = rate_limiter;
        tokio::spawn(async move {
            loop {
                let plaintext = {
                    let mut rc = recv_cipher.lock().await;
                    match noise::read_encrypted(&mut read_half, &mut rc).await {
                        Ok(p) => p,
                        Err(_) => break,
                    }
                };

                let msg: NetworkMessage = match bincode::deserialize(&plaintext) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!("Protocol error from outbound {}: {e}", remote_id);
                        break;
                    }
                };

                match rl.check(&remote_id) {
                    RateLimitResult::Allowed => {
                        let _ = msg_tx.send((remote_id, msg));
                    }
                    RateLimitResult::Throttled => {
                        debug!("Rate-limited outbound message from {}", remote_id);
                    }
                    RateLimitResult::BanRecommended => {
                        warn!("Rate limit exceeded, banning outbound {}", remote_id);
                        pm_clone.ban_peer(&remote_id, "rate limit exceeded".into());
                        break;
                    }
                }

                pm_clone.update_peer(&remote_id, |p| {
                    p.last_seen = std::time::Instant::now();
                });
            }

            rl.remove_peer(&remote_id);
            writers_clone.remove(&remote_id);
            pm_clone.remove_peer(&remote_id);
            info!("Outbound peer disconnected: {}", remote_id);
        });

        Ok(())
    }
}
