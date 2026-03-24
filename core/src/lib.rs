//! # stealth-core
//!
//! Detects Bitcoin UTXO privacy vulnerabilities by analysing a wallet's
//! transaction history on a Bitcoin Core node via RPC.
//!
//! The library connects to a running bitcoind using the
//! [`corepc_client`] crate, fetches the wallet's transaction history and
//! current UTXO set, and runs **17 independent vulnerability detectors**
//! through [`TxGraph::detect_all`].
//!
//! Primary public scanning API: [`TxGraph::detect_all`].
//!
//! Results are returned as a structured [`Report`] that can be serialised
//! to JSON.
//!
//! ## Detected vulnerabilities
//!
//! | # | Vulnerability | Default severity |
//! |---|---------------|------------------|
//! | 1 | Address reuse | HIGH |
//! | 2 | Common-input-ownership heuristic (CIOH) | HIGH – CRITICAL |
//! | 3 | Dust UTXO reception | MEDIUM – HIGH |
//! | 4 | Dust spent alongside normal inputs | HIGH |
//! | 5 | Identifiable change outputs | MEDIUM |
//! | 6 | UTXOs born from consolidation transactions | MEDIUM |
//! | 7 | Mixed script types in inputs | HIGH |
//! | 8 | Cross-origin cluster merge | HIGH |
//! | 9 | UTXO age / lookback-depth spread | LOW |
//! | 10 | Exchange-origin batch withdrawal | MEDIUM |
//! | 11 | Tainted UTXO merge | HIGH |
//! | 12 | Behavioural fingerprinting | MEDIUM |
//! | 13 | Dust attack detection | CRITICAL |
//! | 14 | Peel chain detection | HIGH – CRITICAL |
//! | 15 | Deterministic input→output links | HIGH |
//! | 16 | Unnecessary input (excess CIOH exposure) | MEDIUM |
//! | 17 | Toxic change consolidation | HIGH |

mod detect;
mod graph;
pub mod scanner;
mod types;

pub use graph::TxGraph;
pub use types::*;
