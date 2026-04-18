# Bitquid-Fi

A high-performance Bitcoin sidechain with native DeFi capabilities, built entirely in Rust.

Bitquid-Fi is a PBFT-based layer-2 sidechain that bridges Bitcoin with a fast-finality execution layer featuring an embedded DeFi runtime (AMM, lending, staking) — all compiled into a **single binary**.

## Features

- **PBFT Consensus** — Byzantine fault-tolerant consensus with 2-second block finality
- **Bitcoin Bridge** — Federated peg-in/peg-out with SPV proof verification and Bitcoin header chain tracking
- **Native DeFi Runtime** — Stack-based VM with gas metering and built-in host calls for AMM swaps, lending, borrowing, and staking
- **BQF Native Token** — 21,000,000 max supply with 4-year halving schedule (Bitcoin-style tokenomics)
- **P2P Networking** — Custom TCP protocol with Noise Protocol XX encryption, per-peer rate limiting, and peer management
- **JSON-RPC API** — Full HTTP JSON-RPC 2.0 interface with API key and JWT authentication support
- **Embedded Storage** — High-throughput sled database with block indexing, receipt storage, and historical pruning
- **Priority Mempool** — Gas-price ordered transaction pool with bloom filter rejection and configurable limits
- **Single Binary Deployment** — The entire node compiles to one executable (`bitquid`)
- **Web Wallet** — Standalone HTML wallet with in-browser key generation, AES-GCM encryption, and QR codes

## Architecture

```
bitquid-fi/
├── node/                  # Node binary (CLI + block producer + orchestration)
├── crates/
│   ├── crypto/            # BLAKE3/SHA-256 hashing, secp256k1 ECDSA, Merkle trees
│   ├── core/              # Blocks, transactions, accounts, WorldState, ChainConfig
│   ├── storage/           # sled persistence, indexes, pruning
│   ├── mempool/           # Priority queue, gas ordering, bloom filter
│   ├── consensus/         # PBFT engine, validators, message types
│   ├── network/           # P2P server, Noise encryption, rate limiter, codec
│   ├── bridge/            # Bitcoin SPV, peg-in/out, federation, header chain
│   ├── rpc/               # Axum HTTP server, JSON-RPC handlers, auth middleware
│   └── runtime/           # VM engine, opcodes, gas metering, DeFi host interface
├── config/
│   └── default.toml       # Node configuration template
└── wallet.html            # Standalone web wallet (single file)
```

## Prerequisites

- **Rust** 1.75+ (2021 edition)
- **Cargo** (included with Rust)

## Quick Start

### Build

```bash
cargo build --release
```

The compiled binary will be at `target/release/bitquid` (or `bitquid.exe` on Windows).

### Generate a Validator Key

```bash
./bitquid keygen
```

### Initialize the Data Directory

```bash
./bitquid init --data-dir ./data
```

### Run in Development Mode

```bash
./bitquid run --dev
```

Dev mode runs a single-validator node with relaxed consensus, no P2P requirement, and automatic block production.

### Run in Production

```bash
./bitquid run \
  --data-dir ./data \
  --config config/default.toml \
  --listen 0.0.0.0:30303 \
  --rpc-addr 0.0.0.0:8545
```

### Check Node Status

```bash
./bitquid status --rpc http://127.0.0.1:8545
```

### Export Genesis Block

```bash
./bitquid export-genesis --data-dir ./data
```

## Configuration

See [`config/default.toml`](config/default.toml) for all available options:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `chain_id` | `1337` | Chain identifier |
| `block_time_ms` | `2000` | Target block time in milliseconds |
| `block_gas_limit` | `100000000` | Maximum gas per block |
| `max_peers` | `50` | Maximum P2P connections |
| `bootstrap_peers` | `[]` | Initial peer addresses |
| `rpc_api_keys` | `[]` | Bearer token API keys for RPC auth |
| `rpc_jwt_secret` | `""` | HMAC-SHA256 secret for JWT auth |
| `rpc_cors_origins` | `[]` | Allowed CORS origins |

## JSON-RPC API

The node exposes a JSON-RPC 2.0 interface over HTTP.

| Method | Description |
|--------|-------------|
| `bqf_blockNumber` | Latest block height |
| `bqf_getBlockByNumber` | Block by height |
| `bqf_getBlockByHash` | Block by hash |
| `bqf_getBalance` | Account balance |
| `bqf_getAccount` | Full account state |
| `bqf_getTransactionReceipt` | Transaction receipt |
| `bqf_sendTransaction` | Submit a signed transaction |
| `bqf_chainId` | Chain identifier |
| `bqf_gasPrice` | Current gas price |
| `bqf_mempoolStatus` | Mempool statistics |

Health and status endpoints are also available at `GET /health` and `GET /status`.

### Authentication

RPC supports two authentication modes (configured in `default.toml`):

- **API Key** — Send `Authorization: Bearer <key>` header
- **JWT** — Send `Authorization: Bearer <jwt-token>` with HS256-signed tokens

## Transaction Types

| Type | Description |
|------|-------------|
| `Transfer` | Native BQF token transfer |
| `ContractCall` | Call a deployed contract |
| `ContractCreate` | Deploy a new contract |
| `PegIn` | Bitcoin → BQF bridge deposit (federation-authorized) |
| `PegOut` | BQF → Bitcoin bridge withdrawal |
| `Stake` | Stake BQF tokens |
| `Unstake` | Unstake BQF tokens |
| `Swap` | AMM token swap |
| `AddLiquidity` | Provide liquidity to AMM pool |
| `RemoveLiquidity` | Withdraw liquidity from AMM pool |
| `Lend` | Supply assets to lending pool |
| `Borrow` | Borrow from lending pool |

## Tokenomics

| Parameter | Value |
|-----------|-------|
| **Symbol** | BQF |
| **Decimals** | 8 |
| **Max Supply** | 21,000,000 BQF |
| **Initial Block Reward** | 50 BQF |
| **Halving Interval** | ~63,072,000 blocks (~4 years at 2s blocks) |
| **Block Time** | 2 seconds |

## Web Wallet

Open `wallet.html` in any modern browser. The wallet launches in a compact window and supports:

- Key generation and encrypted local storage (AES-GCM + PBKDF2)
- Send and receive BQF tokens
- QR code address display
- Transaction history
- Configurable RPC endpoint and API key

No server or dependencies required — everything runs in the browser.

## Security

- **P2P Encryption** — Noise Protocol XX handshake (ECDH + BLAKE3-based AEAD)
- **Per-Peer Rate Limiting** — Token bucket with automatic ban on abuse
- **RPC Authentication** — API key (constant-time comparison) and JWT (HS256)
- **PegIn Authorization** — Only federation member addresses can mint via PegIn
- **Supply Cap Enforcement** — Hard cap checked at every block reward issuance
- **Wallet Encryption** — Private keys encrypted with AES-256-GCM (100k PBKDF2 rounds)

## Development

### Run Tests

```bash
cargo test --workspace
```

### Check Without Building

```bash
cargo check --workspace
```

### Build Optimized Release

```bash
cargo build --release
```

The release profile uses `lto = "fat"`, single codegen unit, and symbol stripping for maximum performance and minimal binary size.

## License

MIT OR Apache-2.0
