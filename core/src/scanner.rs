use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use corepc_client::client_sync::{v29::Client, v29::ImportDescriptorsRequest, Auth};
use serde::{Deserialize, Serialize};

use crate::graph::{script_type_from_address, TxGraph, UtxoEntry};
use crate::types::*;

/// RPC connection configuration for a running bitcoind.
#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub url: String,
    pub auth: RpcAuth,
}

/// Authentication method for the bitcoind RPC.
#[derive(Debug, Clone)]
pub enum RpcAuth {
    UserPass { user: String, pass: String },
    CookieFile(PathBuf),
    None,
}

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

/// Errors that can occur during a scan.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("rpc connection failed: {0}")]
    RpcConnection(String),
    #[error("wallet creation failed: {0}")]
    WalletCreation(String),
    #[error("descriptor import failed: {0}")]
    DescriptorImport(String),
    #[error("scan execution failed: {0}")]
    Execution(String),
}

impl RpcConfig {
    fn connect(&self) -> Result<Client, ScanError> {
        match &self.auth {
            RpcAuth::None => Ok(Client::new(&self.url)),
            auth => {
                let core_auth = match auth {
                    RpcAuth::UserPass { user, pass } => Auth::UserPass(user.clone(), pass.clone()),
                    RpcAuth::CookieFile(path) => Auth::CookieFile(path.clone()),
                    RpcAuth::None => unreachable!(),
                };
                Client::new_with_auth(&self.url, core_auth)
                    .map_err(|e| ScanError::RpcConnection(e.to_string()))
            }
        }
    }

    fn connect_wallet(&self, wallet_name: &str) -> Result<Client, ScanError> {
        let wallet_url = format!("{}/wallet/{}", self.url.trim_end_matches('/'), wallet_name);
        match &self.auth {
            RpcAuth::None => Ok(Client::new(&wallet_url)),
            auth => {
                let core_auth = match auth {
                    RpcAuth::UserPass { user, pass } => Auth::UserPass(user.clone(), pass.clone()),
                    RpcAuth::CookieFile(path) => Auth::CookieFile(path.clone()),
                    RpcAuth::None => unreachable!(),
                };
                Client::new_with_auth(&wallet_url, core_auth)
                    .map_err(|e| ScanError::RpcConnection(e.to_string()))
            }
        }
    }
}

/// Run a full privacy scan against a bitcoind node.
pub fn scan(config: &RpcConfig, target: ScanTarget) -> Result<Report, ScanError> {
    match target {
        ScanTarget::Descriptor(d) => scan_descriptors(config, vec![d]),
        ScanTarget::Descriptors(ds) => scan_descriptors(config, ds),
        ScanTarget::Utxos(utxos) => scan_utxos(config, utxos),
    }
}

fn scan_descriptors(config: &RpcConfig, descriptors: Vec<String>) -> Result<Report, ScanError> {
    let base_client = config.connect()?;

    let wallet_name = format!(
        "stealth_scan_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );

    // Create a blank, watch-only descriptor wallet.
    // createwallet(name, disable_private_keys=true, blank=true)
    base_client
        .call::<serde_json::Value>(
            "createwallet",
            &[
                serde_json::Value::String(wallet_name.clone()),
                serde_json::Value::Bool(true),
                serde_json::Value::Bool(true),
            ],
        )
        .map_err(|e| ScanError::WalletCreation(e.to_string()))?;

    let wallet_client = config.connect_wallet(&wallet_name)?;

    // Import descriptors with timestamp=0 for full blockchain rescan.
    let requests: Vec<ImportDescriptorsRequest> = descriptors
        .iter()
        .map(|d| ImportDescriptorsRequest::new(d.as_str(), serde_json::json!(0)))
        .collect();

    let import_result = wallet_client.import_descriptors(&requests);
    if let Err(e) = import_result {
        let _ = base_client.unload_wallet(&wallet_name);
        return Err(ScanError::DescriptorImport(e.to_string()));
    }

    let result = TxGraph::build(wallet_client)
        .map_err(|e| ScanError::Execution(e.to_string()))
        .map(|mut graph| graph.detect_all(None, None));

    let _ = base_client.unload_wallet(&wallet_name);
    result
}

fn scan_utxos(config: &RpcConfig, utxos: Vec<UtxoInput>) -> Result<Report, ScanError> {
    let client = config.connect()?;

    let mut our_addrs = HashSet::new();
    let mut addr_map = HashMap::new();
    let mut utxo_entries = Vec::new();
    let mut our_txids = HashSet::new();
    let mut addr_txs: HashMap<String, Vec<WalletTx>> = HashMap::new();
    let mut tx_addrs: HashMap<String, HashSet<String>> = HashMap::new();

    for utxo in &utxos {
        our_txids.insert(utxo.txid.clone());

        // Resolve address: use provided or fetch from node.
        let address = if let Some(addr) = &utxo.address {
            addr.clone()
        } else {
            resolve_utxo_address(&client, &utxo.txid, utxo.vout)?
        };

        let value = utxo.value_sats.map(|s| s as f64 / 1e8).unwrap_or(0.0);

        if !address.is_empty() {
            our_addrs.insert(address.clone());
            addr_map
                .entry(address.clone())
                .or_insert_with(|| AddressInfo {
                    script_type: script_type_from_address(&address),
                    internal: false,
                    index: 0,
                });

            let wtx = WalletTx {
                txid: utxo.txid.clone(),
                address: address.clone(),
                category: "receive".to_string(),
                amount: value,
                confirmations: 0,
            };
            addr_txs.entry(address.clone()).or_default().push(wtx);
            tx_addrs
                .entry(utxo.txid.clone())
                .or_default()
                .insert(address.clone());
        }

        utxo_entries.push(UtxoEntry {
            txid: utxo.txid.clone(),
            vout: utxo.vout,
            address,
            amount: value,
            confirmations: 0,
        });
    }

    let mut graph = TxGraph {
        addr_map,
        our_addrs,
        utxos: utxo_entries,
        our_txids,
        addr_txs,
        tx_addrs,
        client,
        tx_cache: HashMap::new(),
        input_cache: HashMap::new(),
        output_cache: HashMap::new(),
    };

    Ok(graph.detect_all(None, None))
}

fn resolve_utxo_address(client: &Client, txid_str: &str, vout: u32) -> Result<String, ScanError> {
    let txid: bitcoin::Txid = txid_str
        .parse()
        .map_err(|e| ScanError::Execution(format!("invalid txid '{txid_str}': {e}")))?;
    let raw = client
        .get_raw_transaction_verbose(txid)
        .map_err(|e| ScanError::Execution(e.to_string()))?;
    let json = serde_json::to_value(&raw).unwrap_or_default();
    let addr = json
        .get("vout")
        .and_then(|v| v.as_array())
        .and_then(|a| a.get(vout as usize))
        .and_then(|v| v.pointer("/scriptPubKey/address"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(addr)
}
