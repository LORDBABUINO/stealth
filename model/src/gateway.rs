use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::descriptor::DescriptorNormalizer;
use crate::error::AnalysisError;

/// Abstraction over a blockchain data source (e.g. Bitcoin Core RPC).
///
/// Implementations provide descriptor normalization, address derivation,
/// wallet scanning, and transaction history retrieval. This trait decouples
/// domain logic from the concrete RPC transport, making it possible to
/// test with mocks.
pub trait BlockchainGateway {
    fn normalize_descriptor(&self, descriptor: &str) -> Result<String, AnalysisError>;
    fn derive_addresses(
        &self,
        descriptor: &ResolvedDescriptor,
    ) -> Result<Vec<String>, AnalysisError>;
    fn scan_descriptors(
        &self,
        descriptors: &[ResolvedDescriptor],
    ) -> Result<WalletHistory, AnalysisError>;
    fn list_wallet_descriptors(
        &self,
        wallet_name: &str,
    ) -> Result<Vec<ResolvedDescriptor>, AnalysisError>;
    fn scan_wallet(&self, wallet_name: &str) -> Result<WalletHistory, AnalysisError>;
    fn known_wallet_txids(&self, wallet_names: &[String])
        -> Result<HashSet<String>, AnalysisError>;
    fn get_transaction(&self, txid: &str) -> Result<DecodedTransaction, AnalysisError>;
}

/// Blanket implementation: any `BlockchainGateway` is also a
/// `DescriptorNormalizer`.
impl<T> DescriptorNormalizer for T
where
    T: BlockchainGateway + ?Sized,
{
    fn normalize(&self, descriptor: &str) -> Result<String, AnalysisError> {
        self.normalize_descriptor(descriptor)
    }
}

// ── Gateway model types ─────────────────────────────────────────────────────

/// A descriptor that has been normalized and resolved for import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDescriptor {
    pub desc: String,
    pub internal: bool,
    pub active: bool,
    pub range_end: u32,
}

/// Role of a descriptor chain (external receive vs internal change).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DescriptorChainRole {
    External,
    Internal,
}

/// Script/address type derived from a descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DescriptorType {
    P2wpkh,
    P2tr,
    P2shP2wpkh,
    P2pkh,
    Unknown,
}

impl DescriptorType {
    pub fn from_descriptor(descriptor: &str) -> Self {
        if descriptor.starts_with("wpkh(") {
            Self::P2wpkh
        } else if descriptor.starts_with("tr(") {
            Self::P2tr
        } else if descriptor.starts_with("sh(wpkh(") {
            Self::P2shP2wpkh
        } else if descriptor.starts_with("pkh(") {
            Self::P2pkh
        } else {
            Self::Unknown
        }
    }

    pub fn infer_from_address(address: &str) -> Self {
        if address.starts_with("bc1q")
            || address.starts_with("tb1q")
            || address.starts_with("bcrt1q")
        {
            Self::P2wpkh
        } else if address.starts_with("bc1p")
            || address.starts_with("tb1p")
            || address.starts_with("bcrt1p")
        {
            Self::P2tr
        } else if address.starts_with('2') || address.starts_with('3') {
            Self::P2shP2wpkh
        } else if address.starts_with('1') || address.starts_with('m') || address.starts_with('n') {
            Self::P2pkh
        } else {
            Self::Unknown
        }
    }

    pub fn as_script_name(self) -> &'static str {
        match self {
            Self::P2wpkh => "witness_v0_keyhash",
            Self::P2tr => "witness_v1_taproot",
            Self::P2shP2wpkh => "scripthash",
            Self::P2pkh => "pubkeyhash",
            Self::Unknown => "unknown",
        }
    }
}

/// A derived address with metadata about its origin descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedAddress {
    pub address: String,
    pub descriptor_type: DescriptorType,
    pub chain_role: DescriptorChainRole,
    pub derivation_index: u32,
}

/// Wallet transaction category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletTxCategory {
    Send,
    Receive,
    Unknown,
}

/// A wallet transaction entry (from `listtransactions`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalletTxEntry {
    pub txid: String,
    pub address: String,
    pub category: WalletTxCategory,
    pub amount_btc: f64,
    pub confirmations: u32,
    pub blockheight: u32,
}

/// An input reference within a decoded transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInputRef {
    #[serde(rename = "txid")]
    pub previous_txid: String,
    #[serde(rename = "vout")]
    pub previous_vout: u32,
    pub sequence: u32,
    pub coinbase: bool,
}

/// A transaction output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxOutput {
    pub n: u32,
    pub address: String,
    pub value_btc: f64,
    pub script_type: DescriptorType,
}

/// A fully decoded transaction with inputs and outputs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecodedTransaction {
    pub txid: String,
    pub vin: Vec<TxInputRef>,
    pub vout: Vec<TxOutput>,
    pub version: i32,
    pub locktime: u32,
    pub vsize: u32,
    pub confirmations: u32,
}

/// A current unspent transaction output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub address: String,
    pub amount_btc: f64,
    pub confirmations: u32,
    pub script_type: DescriptorType,
}

/// Complete wallet history with transactions and UTXOs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalletHistory {
    pub wallet_txs: Vec<WalletTxEntry>,
    pub utxos: Vec<Utxo>,
    pub transactions: HashMap<String, DecodedTransaction>,
}

/// A participant (input or output) in a transaction, enriched with
/// ownership information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionParticipant {
    pub address: String,
    pub value_btc: f64,
    pub value_sats: u64,
    pub script_type: DescriptorType,
    pub is_ours: bool,
    pub funding_txid: Option<String>,
    pub funding_vout: Option<u32>,
}
