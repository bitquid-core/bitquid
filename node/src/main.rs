use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Bitquid-Fi: High-performance Bitcoin DeFi Sidechain
#[derive(Parser)]
#[command(
    name = "bitquid",
    version,
    about = "Bitquid-Fi — Ultra-fast Bitcoin DeFi Sidechain Node"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the node
    Run {
        /// Path to configuration file
        #[arg(short, long, default_value = "config/default.toml")]
        config: PathBuf,

        /// Data directory for blockchain storage
        #[arg(short, long, default_value = "data")]
        datadir: PathBuf,

        /// P2P listen address
        #[arg(long, default_value = "0.0.0.0:30303")]
        p2p_addr: String,

        /// RPC listen address
        #[arg(long, default_value = "127.0.0.1:8545")]
        rpc_addr: String,

        /// Run in development mode (single validator, no P2P)
        #[arg(long)]
        dev: bool,

        /// Path to genesis.json (ignored in --dev mode)
        #[arg(long)]
        genesis: Option<PathBuf>,
    },

    /// Initialize a new chain with genesis
    Init {
        /// Data directory
        #[arg(short, long, default_value = "data")]
        datadir: PathBuf,

        /// Use development genesis
        #[arg(long)]
        dev: bool,

        /// Path to genesis.json (ignored with --dev)
        #[arg(long)]
        genesis: Option<PathBuf>,
    },

    /// Export the genesis block
    ExportGenesis {
        /// Output file
        #[arg(short, long, default_value = "genesis.json")]
        output: PathBuf,
    },

    /// Show node status
    Status {
        /// RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },

    /// Generate a new keypair
    Keygen,
}

/// Node configuration loaded from TOML
#[derive(Debug, Serialize, Deserialize)]
struct NodeConfig {
    #[serde(default = "default_chain_id")]
    chain_id: u32,
    #[serde(default = "default_block_time")]
    block_time_ms: u64,
    #[serde(default = "default_gas_limit")]
    block_gas_limit: u64,
    #[serde(default)]
    bootstrap_peers: Vec<String>,
    #[serde(default = "default_max_peers")]
    max_peers: usize,
    #[serde(default)]
    validator_key: Option<String>,
    #[serde(default)]
    rpc_api_keys: Vec<String>,
    #[serde(default)]
    rpc_jwt_secret: Option<String>,
    #[serde(default)]
    rpc_cors_origins: Vec<String>,
}

fn default_chain_id() -> u32 { 1337 }
fn default_block_time() -> u64 { 2000 }
fn default_gas_limit() -> u64 { 100_000_000 }
fn default_max_peers() -> usize { 50 }

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            chain_id: default_chain_id(),
            block_time_ms: default_block_time(),
            block_gas_limit: default_gas_limit(),
            bootstrap_peers: vec![],
            max_peers: default_max_peers(),
            validator_key: None,
            rpc_api_keys: vec![],
            rpc_jwt_secret: None,
            rpc_cors_origins: vec![],
        }
    }
}

fn load_genesis(path: &PathBuf) -> Result<bitquid_core::GenesisConfig> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read genesis file: {}", path.display()))?;
    let genesis: bitquid_core::GenesisConfig = serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse genesis file: {}", path.display()))?;
    info!("Loaded genesis from {}", path.display());
    Ok(genesis)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,bitquid=debug".into()),
        )
        .with_target(true)
        .with_thread_ids(false)
        .init();

    match cli.command {
        Commands::Run {
            config,
            datadir,
            p2p_addr,
            rpc_addr,
            dev,
            genesis,
        } => {
            run_node(config, datadir, p2p_addr, rpc_addr, dev, genesis).await?;
        }
        Commands::Init { datadir, dev, genesis } => {
            init_chain(datadir, dev, genesis)?;
        }
        Commands::ExportGenesis { output } => {
            export_genesis(output)?;
        }
        Commands::Status { rpc } => {
            show_status(&rpc).await?;
        }
        Commands::Keygen => {
            keygen();
        }
    }

    Ok(())
}

async fn run_node(
    config_path: PathBuf,
    datadir: PathBuf,
    p2p_addr: String,
    rpc_addr: String,
    dev: bool,
    genesis_path: Option<PathBuf>,
) -> Result<()> {
    info!("╔══════════════════════════════════════════╗");
    info!("║     Bitquid-Fi Sidechain Node v0.1.0     ║");
    info!("║   Ultra-fast Bitcoin DeFi Sidechain       ║");
    info!("╚══════════════════════════════════════════╝");

    let node_config = if config_path.exists() {
        let contents = std::fs::read_to_string(&config_path)
            .context("failed to read config file")?;
        toml::from_str::<NodeConfig>(&contents)
            .context("failed to parse config")?
    } else if dev {
        info!("Using default development configuration");
        NodeConfig::default()
    } else {
        warn!("Config file not found at {}, using defaults", config_path.display());
        NodeConfig::default()
    };

    info!("Chain ID: {}", node_config.chain_id);
    info!("Block time: {}ms", node_config.block_time_ms);

    std::fs::create_dir_all(&datadir)?;
    let storage_path = datadir.join("chaindata");
    let storage = Arc::new(
        bitquid_storage::Storage::open(&storage_path)
            .context("failed to open storage")?,
    );
    info!("Storage opened at {}", storage_path.display());

    let genesis = if dev {
        bitquid_core::GenesisConfig::dev()
    } else if let Some(ref path) = genesis_path {
        load_genesis(path)?
    } else {
        let default_genesis_path = datadir.join("genesis.json");
        if default_genesis_path.exists() {
            load_genesis(&default_genesis_path)?
        } else {
            warn!("No genesis file specified, falling back to dev genesis");
            bitquid_core::GenesisConfig::dev()
        }
    };

    let (world_state, genesis_block) = genesis.build_state();

    if storage.latest_height() == 0 {
        if storage.get_block_by_height(0)?.is_none() {
            storage.put_block(&genesis_block)?;
            info!("Genesis block stored, hash={}", hex::encode(&genesis_block.hash()[..8]));
        }
    }

    let mempool = Arc::new(bitquid_mempool::Mempool::new(
        bitquid_mempool::MempoolConfig::default(),
    ));
    info!("Mempool initialized (max 50,000 txs)");

    let keypair = if let Some(key_hex) = &node_config.validator_key {
        let key_bytes = hex::decode(key_hex)?;
        let sk = bitquid_crypto::SecretKey::from_bytes(&key_bytes)?;
        bitquid_crypto::KeyPair::from_secret(sk)
    } else {
        let kp = bitquid_crypto::KeyPair::generate();
        info!("Generated ephemeral validator key: {}", kp.public);
        kp
    };

    info!("Node address: {}", keypair.address());

    let validator_set = bitquid_consensus::ValidatorSet::new(vec![
        bitquid_consensus::Validator {
            address: keypair.address(),
            public_key: keypair.public.clone(),
            stake: 100_000 * bitquid_core::ONE_BQF,
            is_active: true,
        },
    ]);

    let (consensus_engine, mut consensus_rx) = bitquid_consensus::PbftEngine::new(
        bitquid_crypto::KeyPair::from_secret(keypair.secret.clone()),
        validator_set,
        bitquid_consensus::engine::PbftConfig::default(),
    );
    let consensus_engine = Arc::new(consensus_engine);
    info!("PBFT consensus engine initialized");

    let world_state = Arc::new(RwLock::new(world_state));

    let rpc_addr: SocketAddr = rpc_addr.parse()?;
    let rpc_state = Arc::new(bitquid_rpc::AppState {
        storage: storage.clone(),
        mempool: mempool.clone(),
        world_state: world_state.clone(),
        chain_id: node_config.chain_id,
        version: "0.1.0".into(),
        min_gas_price: genesis.chain_config.min_gas_price,
    });

    let rpc_config = bitquid_rpc::RpcConfig {
        auth: bitquid_rpc::AuthConfig {
            api_keys: node_config.rpc_api_keys.clone(),
            jwt_secret: node_config.rpc_jwt_secret.clone(),
            exempt_paths: vec!["/health".into()],
        },
        cors_origins: node_config.rpc_cors_origins.clone(),
    };

    let _rpc_handle = tokio::spawn(async move {
        if let Err(e) = bitquid_rpc::start_rpc_server_with_config(rpc_addr, rpc_state, rpc_config).await {
            error!("RPC server error: {e}");
        }
    });
    info!("RPC server starting on {rpc_addr}");

    let p2p_addr_parsed: SocketAddr = p2p_addr.parse()?;
    let (p2p_server, p2p_handle, mut network_rx) = bitquid_network::P2PServer::new(
        bitquid_crypto::KeyPair::from_secret(keypair.secret.clone()),
        p2p_addr_parsed,
        node_config.chain_id,
        node_config.max_peers,
    );

    let p2p_handle_for_consensus = p2p_handle.clone();

    if !dev {
        let _p2p_task = tokio::spawn(async move {
            if let Err(e) = p2p_server.run().await {
                error!("P2P server error: {e}");
            }
        });
        info!("P2P server starting on {p2p_addr}");

        for peer in &node_config.bootstrap_peers {
            info!("Connecting to bootstrap peer: {peer}");
            let _ = p2p_handle
                .cmd_tx
                .send(bitquid_network::NetworkCommand::Connect(peer.clone()));
        }

        let consensus_for_p2p = consensus_engine.clone();
        let _network_handler = tokio::spawn(async move {
            while let Some((_peer_id, msg)) = network_rx.recv().await {
                match msg {
                    bitquid_network::NetworkMessage::ConsensusMessage(data) => {
                        match bincode::deserialize::<bitquid_consensus::ConsensusMessage>(&data) {
                            Ok(cmsg) => {
                                if let Err(e) = consensus_for_p2p.handle_message(cmsg) {
                                    warn!("Consensus message handling error: {e}");
                                }
                            }
                            Err(e) => {
                                warn!("Failed to deserialize consensus message: {e}");
                            }
                        }
                    }
                    _ => {}
                }
            }
        });
    }

    let block_time = Duration::from_millis(node_config.block_time_ms);
    let storage_clone = storage.clone();
    let mempool_clone = mempool.clone();
    let world_state_clone = world_state.clone();
    let consensus_clone = consensus_engine.clone();
    let chain_id = node_config.chain_id;
    let gas_limit = node_config.block_gas_limit;
    let block_signer = bitquid_crypto::KeyPair::from_secret(keypair.secret.clone());
    let chain_config = genesis.chain_config.clone();

    let _block_producer = tokio::spawn(async move {
        let mut interval = tokio::time::interval(block_time);
        loop {
            interval.tick().await;

            if !consensus_clone.is_leader() && !dev {
                consensus_clone.tick();
                continue;
            }

            let height = storage_clone.latest_height() + 1;
            let pending = mempool_clone.pending_transactions(
                bitquid_core::MAX_TXS_PER_BLOCK,
                gas_limit,
            );

            let tx_hashes: Vec<bitquid_core::Hash> =
                pending.iter().map(|tx| tx.tx_hash()).collect();
            let tx_root = bitquid_crypto::merkle::compute_merkle_root(&tx_hashes);

            let prev_hash = storage_clone
                .get_block_hash_by_height(height - 1)
                .ok()
                .flatten()
                .unwrap_or(bitquid_core::ZERO_HASH);

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let mut ws = world_state_clone.write().await;
            let mut gas_used = 0u64;
            let mut committed_txs = Vec::new();
            let mut receipts = Vec::new();

            {
                let mut executor = bitquid_runtime::BlockExecutor::new(
                    &mut *ws, &chain_config, height, now,
                );
                for (i, tx) in pending.iter().enumerate() {
                    match executor.execute_transaction(tx, i as u32) {
                        Ok(receipt) => {
                            gas_used += receipt.gas_used;
                            committed_txs.push(tx.clone());
                            receipts.push(receipt);
                        }
                        Err(e) => {
                            warn!("TX {} failed: {e}", hex::encode(&tx.tx_hash()[..8]));
                            mempool_clone.reject(tx.tx_hash());
                        }
                    }
                }
            }

            let total_minted = ws.total_minted();
            let block_reward = chain_config.block_reward_at_height(height, total_minted);
            if block_reward > 0 {
                let proposer = keypair.address();
                ws.get_or_create_account(&proposer).add_balance(block_reward);
                ws.add_minted(block_reward);
            }

            let state_root = ws.compute_state_root();
            drop(ws);

            let receipts_root = if receipts.is_empty() {
                bitquid_core::ZERO_HASH
            } else {
                let receipt_hashes: Vec<bitquid_core::Hash> = receipts
                    .iter()
                    .map(|r| bitquid_crypto::blake3_hash(&bincode::serialize(r).unwrap()))
                    .collect();
                bitquid_crypto::merkle::compute_merkle_root(&receipt_hashes)
            };

            let mut header = bitquid_core::BlockHeader {
                version: 1,
                chain_id,
                height,
                timestamp: now,
                prev_hash,
                state_root,
                transactions_root: tx_root,
                receipts_root,
                proposer: keypair.address(),
                tx_count: committed_txs.len() as u32,
                gas_used,
                gas_limit,
                extra_data: vec![],
                signature: bitquid_crypto::Signature::default(),
            };

            let header_hash = header.compute_hash();
            header.signature = block_signer.sign_hash(&header_hash);

            let block = bitquid_core::Block::new(header, committed_txs.clone());

            if let Err(e) = storage_clone.put_block(&block) {
                error!("Failed to store block #{height}: {e}");
                continue;
            }

            for receipt in &receipts {
                let _ = storage_clone.put_receipt(receipt);
            }

            let committed_hashes: Vec<_> = committed_txs.iter().map(|tx| tx.tx_hash()).collect();
            mempool_clone.remove_committed(&committed_hashes);

            if !committed_txs.is_empty() || height % 100 == 0 {
                info!(
                    "Block #{height} produced: txs={}, gas={gas_used}, state={}",
                    committed_txs.len(),
                    hex::encode(&state_root[..8])
                );
            }
        }
    });

    let p2p_handle_for_output = p2p_handle_for_consensus;
    let _consensus_handler = tokio::spawn(async move {
        while let Some(output) = consensus_rx.recv().await {
            match output {
                bitquid_consensus::engine::ConsensusOutput::BlockFinalized(block) => {
                    info!(
                        "Consensus: block #{} finalized",
                        block.height()
                    );
                }
                bitquid_consensus::engine::ConsensusOutput::BroadcastMessage(msg) => {
                    match bincode::serialize(&msg) {
                        Ok(data) => {
                            let _ = p2p_handle_for_output.cmd_tx.send(
                                bitquid_network::NetworkCommand::Broadcast(
                                    bitquid_network::NetworkMessage::ConsensusMessage(data),
                                ),
                            );
                        }
                        Err(e) => {
                            error!("Failed to serialize consensus message: {e}");
                        }
                    }
                }
                bitquid_consensus::engine::ConsensusOutput::RequestViewChange(view) => {
                    warn!("Consensus: view change to {view}");
                }
            }
        }
    });

    info!("══════════════════════════════════════════");
    info!("  Node is running. Press Ctrl+C to stop.  ");
    info!("══════════════════════════════════════════");

    signal::ctrl_c().await?;
    info!("Shutdown signal received, stopping...");

    storage.flush()?;
    info!("Storage flushed. Goodbye!");

    Ok(())
}

fn init_chain(datadir: PathBuf, dev: bool, genesis_path: Option<PathBuf>) -> Result<()> {
    info!("Initializing new chain...");

    std::fs::create_dir_all(&datadir)?;
    let storage_path = datadir.join("chaindata");

    let storage = bitquid_storage::Storage::open(&storage_path)?;

    let genesis = if dev {
        bitquid_core::GenesisConfig::dev()
    } else if let Some(ref path) = genesis_path {
        load_genesis(path)?
    } else {
        let default_genesis_path = datadir.join("genesis.json");
        if default_genesis_path.exists() {
            load_genesis(&default_genesis_path)?
        } else {
            info!("No genesis file found, using dev genesis");
            bitquid_core::GenesisConfig::dev()
        }
    };

    let (_, genesis_block) = genesis.build_state();
    storage.put_block(&genesis_block)?;
    storage.flush()?;

    info!("Genesis block created:");
    info!("  Hash: {}", hex::encode(genesis_block.hash()));
    info!("  Chain ID: {}", genesis.chain_config.chain_id);
    info!("  State root: {}", hex::encode(genesis_block.header.state_root));
    info!("Data directory: {}", datadir.display());
    info!("Chain initialization complete!");

    Ok(())
}

fn export_genesis(output: PathBuf) -> Result<()> {
    let genesis = bitquid_core::GenesisConfig::dev();
    let json = serde_json::to_string_pretty(&genesis)?;
    std::fs::write(&output, json)?;
    info!("Genesis exported to {}", output.display());
    Ok(())
}

async fn show_status(rpc: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    info!("Querying node status at {rpc}...");

    let url = rpc.strip_prefix("http://").unwrap_or(rpc);
    let stream = tokio::net::TcpStream::connect(url).await;

    match stream {
        Ok(mut stream) => {
            let body = r#"{"jsonrpc":"2.0","method":"bqf_blockNumber","params":[],"id":1}"#;
            let request = format!(
                "POST / HTTP/1.1\r\nHost: {url}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(request.as_bytes()).await?;

            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await?;
            let response = String::from_utf8_lossy(&buf[..n]);

            if let Some(json_start) = response.find('{') {
                let json_str = &response[json_start..];
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) {
                    println!("{}", serde_json::to_string_pretty(&value)?);
                } else {
                    println!("{json_str}");
                }
            } else {
                println!("{response}");
            }
        }
        Err(e) => {
            error!("Failed to connect to node at {rpc}: {e}");
        }
    }

    Ok(())
}

fn keygen() {
    let kp = bitquid_crypto::KeyPair::generate();
    eprintln!("╔═══ New Keypair Generated ═══╗");
    eprintln!("  Address:     {}", kp.address());
    eprintln!("  Public Key:  {}", kp.public);
    eprintln!("╚═════════════════════════════╝");
    eprintln!();
    eprintln!("WARNING: Secret key printed below. Clear terminal history after saving.");
    eprintln!("         NEVER share this key or commit it to version control.");
    eprintln!();
    println!("{}", hex::encode(kp.secret.to_bytes()));
}
