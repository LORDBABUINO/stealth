use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::config::AnalysisConfig;

/// What to scan.
#[derive(Debug, Clone)]
pub enum ScanTarget {
    Descriptor(String),
    Descriptors(Vec<String>),
    Utxos(Vec<UtxoInput>),
}

/// A raw UTXO to analyse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoInput {
    pub txid: String,
    pub vout: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_sats: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

/// Top-level settings for the analysis engine, combining detector config
/// with optional known-wallet hooks used by taint and exchange detectors.
#[derive(Debug, Clone)]
pub struct EngineSettings {
    pub config: AnalysisConfig,
    pub known_risky_txids: Option<HashSet<String>>,
    pub known_exchange_txids: Option<HashSet<String>>,
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            config: AnalysisConfig::default(),
            known_risky_txids: None,
            known_exchange_txids: None,
        }
    }
}
