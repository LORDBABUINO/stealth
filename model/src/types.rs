use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Severity levels for privacy vulnerability findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl core::fmt::Display for Severity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// The category of privacy vulnerability detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VulnerabilityType {
    AddressReuse,
    Cioh,
    Dust,
    DustSpending,
    ChangeDetection,
    Consolidation,
    ScriptTypeMixing,
    ClusterMerge,
    UtxoAgeSpread,
    DormantUtxos,
    ExchangeOrigin,
    TaintedUtxoMerge,
    DirectTaint,
    BehavioralFingerprint,
    DustAttack,
    PeelChain,
    DeterministicLink,
    UnnecessaryInput,
    ToxicChange,
}

impl core::fmt::Display for VulnerabilityType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", self));
        write!(f, "{s}")
    }
}

/// A single privacy vulnerability finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    #[serde(rename = "type")]
    pub vulnerability_type: VulnerabilityType,
    pub severity: Severity,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correction: Option<String>,
}

/// Aggregate statistics about the scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub transactions_analyzed: usize,
    pub addresses_derived: usize,
    pub utxos_current: usize,
}

/// Summary of the scan results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub findings: usize,
    pub warnings: usize,
    pub clean: bool,
}

/// The complete vulnerability scan report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub stats: Stats,
    pub findings: Vec<Finding>,
    pub warnings: Vec<Finding>,
    pub summary: Summary,
}

impl Report {
    /// Construct a report from collected findings and warnings.
    pub fn new(stats: Stats, findings: Vec<Finding>, warnings: Vec<Finding>) -> Self {
        let summary = Summary {
            findings: findings.len(),
            warnings: warnings.len(),
            clean: findings.is_empty() && warnings.is_empty(),
        };
        Report {
            stats,
            findings,
            warnings,
            summary,
        }
    }
}

/// Convert a BTC f64 value to satoshis.
pub fn btc_to_sats(btc: f64) -> u64 {
    (btc * 1e8).round() as u64
}

/// Metadata about a derived address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressInfo {
    /// The script type (e.g. "p2wpkh", "p2tr", "p2sh", "p2wsh", "p2pkh").
    pub script_type: String,
    /// Whether this is a change (internal) address.
    pub internal: bool,
    /// The derivation index.
    pub index: usize,
}

/// Information about a transaction input, resolved from the parent transaction.
#[derive(Debug, Clone)]
pub struct InputInfo {
    pub address: String,
    pub value_sats: u64,
    pub funding_txid: String,
    pub funding_vout: u32,
}

/// Information about a transaction output.
#[derive(Debug, Clone)]
pub struct OutputInfo {
    pub address: String,
    pub value_sats: u64,
    pub index: u64,
    pub script_type: String,
}

/// A wallet transaction entry (from `listtransactions`).
#[derive(Debug, Clone)]
pub struct WalletTx {
    pub txid: String,
    pub address: String,
    pub category: String,
    pub amount_sats: u64,
    pub confirmations: i64,
}
