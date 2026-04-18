# Bitquid-Fi

A high-performance standalone blockchain with post-quantum cryptography and native DeFi capabilities, built entirely in Rust.

Bitquid-Fi is a PBFT-based layer-1 chain with 2-second block finality, an embedded smart contract VM with built-in DeFi opcodes (AMM, lending, staking), and NIST post-quantum cryptographic primitives — all compiled into a **single binary**.

## Features

- **PBFT Consensus** — Byzantine fault-tolerant consensus with 2-second block finality
- **Post-Quantum Cryptography** — ML-DSA-65 (FIPS 204) signatures, ML-KEM-768 (FIPS 203) key exchange
- **Smart Contracts** — Stack-based VM with gas metering, persistent storage, and snapshot-based rollback
- **Native DeFi Opcodes** — Built-in VM opcodes for AMM swaps, liquidity provision, lending, and borrowing
- **BQF Native Token** — 21,000,000 max supply with 4-year halving schedule (Bitcoin-style tokenomics)
- **Encrypted P2P** — ML-KEM Noise handshake + ChaCha20-Poly1305 AEAD, per-peer rate limiting
- **JSON-RPC API** — Full HTTP JSON-RPC 2.0 interface with API key and JWT authentication
- **Embedded Storage** — High-throughput sled database with block indexing, receipt storage, and pruning
- **Priority Mempool** — Gas-price ordered transaction pool with bloom filter rejection
- **Single Binary** — The entire node compiles to one executable (`bitquid`)
- **Web Wallet** — Standalone HTML wallet with in-browser key generation and AES-GCM encryption

## Architecture

```
bitquid-fi/
├── node/                  # Node binary (CLI + block producer + orchestration)
├── crates/
│   ├── crypto/            # BLAKE3/SHA-256 hashing, ML-DSA-65 signatures, Merkle trees
│   ├── core/              # Blocks, transactions, accounts, WorldState, ChainConfig
│   ├── storage/           # sled persistence, indexes, pruning
│   ├── mempool/           # Priority queue, gas ordering, bloom filter
│   ├── consensus/         # PBFT engine, validators, message types
│   ├── network/           # P2P server, ML-KEM Noise encryption, rate limiter, codec
│   ├── rpc/               # Axum HTTP server, JSON-RPC handlers, auth middleware
│   └── runtime/           # VM engine, opcodes, gas metering, DeFi pools, BlockExecutor
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
| `bqf_getAccount` | Full account state (balance, nonce, staked, is_contract) |
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

| Type | ID | Description |
|------|----|-------------|
| `Transfer` | 0 | Native BQF token transfer |
| `ContractCall` | 1 | Call a deployed smart contract |
| `ContractCreate` | 2 | Deploy new contract bytecode (max 24 KB) |
| `Stake` | 5 | Stake BQF tokens for validation |
| `Unstake` | 6 | Unstake BQF tokens |

## Smart Contracts

Bitquid-Fi includes a fully integrated stack-based VM for smart contract execution.

### Capabilities

- **Deployment**: `ContractCreate` deploys bytecode; address = `blake3(sender || nonce)`
- **Execution**: `ContractCall` invokes deployed bytecode with gas metering
- **Storage**: Per-contract persistent key-value storage (SLoad/SStore)
- **Rollback**: Failed executions revert to a pre-call state snapshot
- **Memory**: Up to 1 MB per execution, bounded stack (1024 entries)

### Built-in DeFi Opcodes

Contracts have access to native DeFi operations via VM opcodes:

| Category | Opcodes |
|----------|---------|
| **AMM** | SwapExact, AddLiquidity, RemoveLiquidity, GetReserves |
| **Lending** | Deposit, Withdraw, Borrow, Repay |
| **Token** | Transfer, Approve, Burn |
| **Environment** | Caller, CallValue, Address, Balance, BlockHeight, Timestamp |

### Security Model

- Contracts can only spend their **own** balance (`ctx.address`), never the caller's
- `Mint` is disabled — only block rewards can create new BQF
- `Burn` is restricted to the caller's or contract's own balance
- Transaction signatures are verified at both the RPC and executor layers
- Minimum gas price and gas limit are enforced

## Tokenomics

| Parameter | Value |
|-----------|-------|
| **Symbol** | BQF |
| **Decimals** | 8 |
| **Max Supply** | 21,000,000 BQF |
| **Initial Block Reward** | 50 BQF |
| **Halving Interval** | ~63,115,200 blocks (~4 years at 2s blocks) |
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

### Cryptography

| Layer | Algorithm | Standard |
|-------|-----------|----------|
| **Signatures** | ML-DSA-65 (Dilithium) | FIPS 204 |
| **Key Exchange** | ML-KEM-768 (Kyber) | FIPS 203 |
| **P2P AEAD** | ChaCha20-Poly1305 | RFC 8439 |
| **Hashing** | BLAKE3 | — |
| **Wallet Encryption** | AES-256-GCM | — |

### Network

- **P2P Encryption** — ML-KEM Noise handshake with ChaCha20-Poly1305 transport
- **Per-Peer Rate Limiting** — Sliding-window token bucket with automatic ban on abuse
- **Protocol Versioning** — Version field in message frame header; mismatches are rejected
- **Message Size Limit** — 4 MB maximum per P2P message

### Node

- **RPC Authentication** — API key (constant-time comparison) and JWT (HS256)
- **Supply Cap Enforcement** — Hard cap checked at every block reward issuance
- **Defense-in-Depth** — Transaction signatures verified at both RPC ingress and block execution
- **Gas Enforcement** — Minimum gas price and gas limit validated at both RPC and executor
- **Safe Arithmetic** — All balance/stake/reserve operations use saturating or checked arithmetic

## Estimated Operating Cost

| Nodes | Use Case | Monthly Cost |
|-------|----------|--------------|
| 1 | Development / testing | ~$3.50–12 |
| 4 | PBFT f=1 (1 fault tolerance) | ~$14–24 |
| 7 | PBFT f=2 (2 fault tolerance) | ~$24–38 |

A single `bitquid` binary is all that is needed per server. No external database, runtime, or dependencies required.

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
