# stealth-core

Detects Bitcoin UTXO privacy vulnerabilities by analysing a wallet's transaction
history on a Bitcoin Core node via JSON-RPC.

The library connects to a running `bitcoind`, fetches the wallet's transaction
history and current UTXO set, then runs **12 independent vulnerability
detectors** through `TxGraph::detect_all()`. Results are returned as a
structured `Report` that serialises to JSON.

Primary public scanning API: `TxGraph::detect_all(...)`.

## Detected vulnerabilities

| #   | Vulnerability                           | Default severity |
| --- | --------------------------------------- | ---------------- |
| 1   | Address reuse                           | HIGH             |
| 2   | Common-input-ownership heuristic (CIOH) | HIGH – CRITICAL  |
| 3   | Dust UTXO reception                     | MEDIUM – HIGH    |
| 4   | Dust spent alongside normal inputs      | HIGH             |
| 5   | Identifiable change outputs             | MEDIUM           |
| 6   | UTXOs born from consolidation txs       | MEDIUM           |
| 7   | Mixed script types in inputs            | HIGH             |
| 8   | Cross-origin cluster merge              | HIGH             |
| 9   | UTXO age / lookback-depth spread        | LOW              |
| 10  | Exchange-origin batch withdrawal        | MEDIUM           |
| 11  | Tainted UTXO merge                      | HIGH             |
| 12  | Behavioural fingerprinting              | MEDIUM           |

## Prerequisites

- **Rust** >= 1.93.1
- **Bitcoin Core** (`bitcoind`) >= 0.29.0 — must be on your `PATH`

### Installing Bitcoin Core

```bash
# macOS (Homebrew)
brew install bitcoin

# Ubuntu / Debian
sudo apt install bitcoind

# Or download from https://bitcoincore.org/en/download/
```

Verify it is available:

```bash
bitcoind --version
```

## Usage

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
stealth-core = "0.1.0"
```

```rust
use corepc_client::client_sync::v29::Client;
use stealth_core::{TxGraph, VulnerabilityType};

// Connect to a wallet-loaded bitcoind
let client = Client::new("http://127.0.0.1:8332", "user", "pass").unwrap();

let mut graph = TxGraph::build(client).unwrap();
let report = graph.detect_all(None, None);

for finding in &report.findings {
    println!("{}: {}", finding.severity, finding.vulnerability_type);
}
```

## Running the tests

The integration tests spin up a temporary `bitcoind` in regtest mode
(via [`corepc-node`](https://crates.io/crates/corepc-node)).
No external setup is required — just ensure `bitcoind` is on your `PATH`.

```bash
# Run all tests (unit + 13 regtest integration tests)
cargo test -p stealth-core

# Run a single test with output
cargo test -p stealth-core detect_address_reuse -- --nocapture
```

> **Note:** The integration tests create ephemeral regtest nodes that are
> automatically cleaned up. Each test takes a few seconds due to block mining.

## Project structure

```
core/
├── Cargo.toml
├── src/
│   ├── lib.rs        # Crate root and re-exports
│   ├── types.rs      # Severity, VulnerabilityType, Finding, Report
│   ├── graph.rs      # TxGraph — builds wallet tx graph via RPC
│   └── detect.rs     # 12 vulnerability detectors + detect_all()
└── tests/
    └── integration.rs  # 13 regtest integration tests
```

## License

[CC0-1.0](../LICENSE)
