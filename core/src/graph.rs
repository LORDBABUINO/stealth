use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use corepc_client::client_sync::{v29::Client, Result as RpcResult};

use crate::types::{AddressInfo, InputInfo, OutputInfo, WalletTx};

/// Indexed view of all transactions touching a wallet's address set.
///
/// The graph lazily fetches and caches raw transactions from the RPC node
/// as detectors request input/output data for specific txids.
#[derive(Debug)]
pub struct TxGraph {
    /// Map of our addresses → metadata.
    pub addr_map: HashMap<String, AddressInfo>,
    /// All our addresses (quick lookup).
    pub our_addrs: HashSet<String>,
    /// Current UTXOs from `listunspent`.
    pub utxos: Vec<UtxoEntry>,
    /// Transaction IDs that touch our wallet.
    pub our_txids: HashSet<String>,
    /// Per-address transaction entries.
    pub addr_txs: HashMap<String, Vec<WalletTx>>,
    /// Per-txid set of our addresses involved.
    pub tx_addrs: HashMap<String, HashSet<String>>,

    /// Client reference for lazy tx fetches.
    pub client: Client,
    /// Cached decoded transactions (txid → JSON value).
    pub tx_cache: HashMap<String, serde_json::Value>,
    /// Cached input addresses per txid.
    pub input_cache: HashMap<String, Vec<InputInfo>>,
    /// Cached output addresses per txid.
    pub output_cache: HashMap<String, Vec<OutputInfo>>,
}

/// A UTXO entry from `listunspent`.
#[derive(Debug, Clone)]
pub struct UtxoEntry {
    pub txid: String,
    pub vout: u32,
    pub address: String,
    pub amount: f64,
    pub confirmations: i64,
}

impl TxGraph {
    /// Build a `TxGraph` by querying the RPC client for the wallet's
    /// full transaction history and current UTXO set.
    pub fn build(client: Client) -> RpcResult<Self> {
        // Get all transactions (listsinceblock includes change addresses)
        let list_txs = client.list_since_block()?;
        let wallet_txs: Vec<WalletTx> = list_txs
            .transactions
            .iter()
            .map(|item| WalletTx {
                txid: item.txid.clone(),
                address: item.address.clone().unwrap_or_default(),
                category: format!("{:?}", item.category).to_lowercase(),
                amount: item.amount,
                confirmations: item.confirmations,
            })
            .collect();

        // Get all UTXOs
        let list_unspent = client.list_unspent()?;
        let utxos: Vec<UtxoEntry> = list_unspent
            .0
            .iter()
            .map(|item| UtxoEntry {
                txid: item.txid.clone(),
                vout: item.vout as u32,
                address: item.address.clone(),
                amount: item.amount,
                confirmations: item.confirmations,
            })
            .collect();

        // Build indices
        let mut our_txids = HashSet::new();
        let mut addr_txs: HashMap<String, Vec<WalletTx>> = HashMap::new();
        let mut tx_addrs: HashMap<String, HashSet<String>> = HashMap::new();

        for wtx in &wallet_txs {
            if !wtx.txid.is_empty() {
                our_txids.insert(wtx.txid.clone());
            }
            if !wtx.address.is_empty() && !wtx.txid.is_empty() {
                addr_txs
                    .entry(wtx.address.clone())
                    .or_default()
                    .push(wtx.clone());
                tx_addrs
                    .entry(wtx.txid.clone())
                    .or_default()
                    .insert(wtx.address.clone());
            }
        }

        // Derive address map from UTXOs (basic — full descriptor resolution
        // would require importdescriptors support).
        let mut our_addrs = HashSet::new();
        let mut addr_map = HashMap::new();
        for utxo in &utxos {
            our_addrs.insert(utxo.address.clone());
            addr_map
                .entry(utxo.address.clone())
                .or_insert_with(|| AddressInfo {
                    script_type: script_type_from_address(&utxo.address),
                    internal: false,
                    index: 0,
                });
        }
        // Also include addresses seen in transaction history.
        // Only "receive" entries are our addresses; "send" entries have the
        // counterparty's destination address.
        for wtx in &wallet_txs {
            if !wtx.address.is_empty() && wtx.category != "send" {
                our_addrs.insert(wtx.address.clone());
                addr_map
                    .entry(wtx.address.clone())
                    .or_insert_with(|| AddressInfo {
                        script_type: script_type_from_address(&wtx.address),
                        internal: false,
                        index: 0,
                    });
            }
        }
        // list_since_block/list_transactions omit change addresses.
        // list_address_groupings includes ALL used addresses (including change).
        if let Ok(groupings) = client.list_address_groupings() {
            let json = serde_json::to_value(&groupings).unwrap_or_default();
            if let Some(groups) = json.as_array() {
                for group in groups {
                    if let Some(items) = group.as_array() {
                        for item in items {
                            let addr = item
                                .as_array()
                                .and_then(|a| a.first())
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            if !addr.is_empty() {
                                our_addrs.insert(addr.to_string());
                                addr_map
                                    .entry(addr.to_string())
                                    .or_insert_with(|| AddressInfo {
                                        script_type: script_type_from_address(addr),
                                        internal: false,
                                        index: 0,
                                    });
                            }
                        }
                    }
                }
            }
        }

        // Populate `internal` and `index` from the HD key path reported
        // by `getaddressinfo`. BIP-44/49/84/86 paths look like:
        //   m/<purpose>'/<coin>'/<account>'/<change>/<index>
        // where <change> == 1 means internal (change) address.
        for addr_str in &our_addrs {
            if let Ok(address) = addr_str
                .parse::<bitcoin::Address<NetworkUnchecked>>()
                .map(|a| a.assume_checked())
            {
                if let Ok(info) = client.get_address_info(&address) {
                    if let Some(ref path) = info.hd_key_path {
                        let parts: Vec<&str> = path.split('/').collect();
                        // e.g. ["m", "84'", "1'", "0'", "1", "5"]
                        if parts.len() >= 2 {
                            let change_part = parts[parts.len() - 2];
                            let index_part = parts[parts.len() - 1];
                            let is_internal = change_part == "1";
                            let idx = index_part.parse::<usize>().unwrap_or(0);
                            if let Some(ai) = addr_map.get_mut(addr_str) {
                                ai.internal = is_internal;
                                ai.index = idx;
                            }
                        }
                    }
                }
            }
        }

        Ok(TxGraph {
            addr_map,
            our_addrs,
            utxos,
            our_txids,
            addr_txs,
            tx_addrs,
            client,
            tx_cache: HashMap::new(),
            input_cache: HashMap::new(),
            output_cache: HashMap::new(),
        })
    }

    /// Check whether an address belongs to our wallet.
    pub fn is_ours(&self, address: &str) -> bool {
        self.our_addrs.contains(address)
    }

    /// Get the script type for an address.
    pub fn script_type(&self, address: &str) -> String {
        self.addr_map
            .get(address)
            .map(|info| info.script_type.clone())
            .unwrap_or_else(|| script_type_from_address(address))
    }

    /// Fetch a decoded transaction as a JSON value (cached).
    pub fn fetch_tx(&mut self, txid: &str) -> Option<serde_json::Value> {
        if let Some(cached) = self.tx_cache.get(txid) {
            return Some(cached.clone());
        }
        let txid_parsed: bitcoin::Txid = txid.parse().ok()?;
        let raw = self.client.get_raw_transaction_verbose(txid_parsed).ok()?;
        let value = serde_json::to_value(&raw).ok()?;
        self.tx_cache.insert(txid.to_string(), value.clone());
        Some(value)
    }

    /// Get all input addresses for a transaction (cached).
    pub fn get_input_addresses(&mut self, txid: &str) -> Vec<InputInfo> {
        if let Some(cached) = self.input_cache.get(txid) {
            return cached.clone();
        }

        let tx = match self.fetch_tx(txid) {
            Some(tx) => tx,
            None => {
                self.input_cache.insert(txid.to_string(), vec![]);
                return vec![];
            }
        };

        let mut addrs = Vec::new();
        if let Some(inputs) = tx.get("vin").and_then(|v| v.as_array()) {
            for vin in inputs {
                if vin.get("coinbase").is_some() {
                    continue;
                }
                let parent_txid = match vin.get("txid").and_then(|v| v.as_str()) {
                    Some(t) => t.to_string(),
                    None => continue,
                };
                let vout = vin.get("vout").and_then(|v| v.as_u64()).unwrap_or(0);
                if let Some(parent) = self.fetch_tx(&parent_txid) {
                    if let Some(outputs) = parent.get("vout").and_then(|v| v.as_array()) {
                        if let Some(vout_data) = outputs.get(vout as usize) {
                            let addr = vout_data
                                .pointer("/scriptPubKey/address")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let value = vout_data
                                .get("value")
                                .and_then(|v| v.as_f64())
                                .unwrap_or(0.0);
                            addrs.push(InputInfo {
                                address: addr,
                                value,
                                funding_txid: parent_txid,
                                funding_vout: vout as u32,
                            });
                        }
                    }
                }
            }
        }

        self.input_cache.insert(txid.to_string(), addrs.clone());
        addrs
    }

    /// Get all output addresses for a transaction (cached).
    pub fn get_output_addresses(&mut self, txid: &str) -> Vec<OutputInfo> {
        if let Some(cached) = self.output_cache.get(txid) {
            return cached.clone();
        }

        let tx = match self.fetch_tx(txid) {
            Some(tx) => tx,
            None => {
                self.output_cache.insert(txid.to_string(), vec![]);
                return vec![];
            }
        };

        let mut addrs = Vec::new();
        if let Some(outputs) = tx.get("vout").and_then(|v| v.as_array()) {
            for vout in outputs {
                let addr = vout
                    .pointer("/scriptPubKey/address")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let value = vout.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let index = vout.get("n").and_then(|v| v.as_u64()).unwrap_or(0);
                let script_type = if !addr.is_empty() {
                    script_type_from_address(&addr)
                } else {
                    // Fallback: normalise the RPC type string.
                    let raw = vout
                        .pointer("/scriptPubKey/type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    normalize_rpc_script_type(raw).into()
                };
                addrs.push(OutputInfo {
                    address: addr,
                    value,
                    index,
                    script_type,
                });
            }
        }

        self.output_cache.insert(txid.to_string(), addrs.clone());
        addrs
    }

    /// Find a wallet transaction that spends the output `txid:vout`.
    ///
    /// Searches across all known wallet transaction IDs. Returns the
    /// spending txid if found.
    pub fn find_spending_tx(&mut self, txid: &str, vout: u32) -> Option<String> {
        let txids: Vec<String> = self.our_txids.iter().cloned().collect();
        for candidate in &txids {
            if candidate == txid {
                continue;
            }
            let tx = self.fetch_tx(candidate)?;
            if let Some(vins) = tx.get("vin").and_then(|v| v.as_array()) {
                for vin in vins {
                    let parent = vin.get("txid").and_then(|v| v.as_str()).unwrap_or("");
                    let v = vin.get("vout").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
                    if parent == txid && v == vout as u64 {
                        return Some(candidate.clone());
                    }
                }
            }
        }
        None
    }
}

/// Determine script type by actually decoding the address and inspecting
/// the resulting script.
///
/// Unlike the old prefix-based heuristic this handles all cases correctly:
///
/// * `bc1q` / `tb1q` / `bcrt1q` with a 20-byte program → **p2wpkh**
/// * `bc1q` / `tb1q` / `bcrt1q` with a 32-byte program → **p2wsh**
/// * `bc1p` / `tb1p` / `bcrt1p` → **p2tr**
/// * Base58 `1`/`m`/`n` (version 0x00/0x6f) → **p2pkh**
/// * Base58 `3`/`2` (version 0x05/0xc4) → **p2sh** (we *cannot* know if it
///   wraps p2wpkh, p2wsh, or bare multisig without the redeem script)
pub fn script_type_from_address(address: &str) -> String {
    // `assume_checked` skips network validation, allowing the function to
    // work for mainnet, testnet, signet and regtest addresses uniformly.
    if let Ok(addr) =
        Address::from_str(address).map(|a: Address<NetworkUnchecked>| a.assume_checked())
    {
        let script = addr.script_pubkey();
        if script.is_p2pkh() {
            return "p2pkh".into();
        } else if script.is_p2sh() {
            // Without the redeemScript (only available at spend time)
            // we cannot distinguish p2sh-p2wpkh from p2sh-p2wsh or
            // bare p2sh multisig.  Report as generic "p2sh".
            return "p2sh".into();
        } else if script.is_p2wpkh() {
            return "p2wpkh".into();
        } else if script.is_p2wsh() {
            return "p2wsh".into();
        } else if script.is_p2tr() {
            return "p2tr".into();
        }
    }

    "unknown".into()
}

/// Normalise the `scriptPubKey.type` string that Bitcoin Core returns in
/// `getrawtransaction` / `decoderawtransaction` to the canonical short names
/// used throughout stealth-core.
fn normalize_rpc_script_type(raw: &str) -> &str {
    match raw {
        "witness_v0_keyhash" => "p2wpkh",
        "witness_v0_scripthash" => "p2wsh",
        "witness_v1_taproot" => "p2tr",
        "pubkeyhash" => "p2pkh",
        "scripthash" => "p2sh",
        "pubkey" => "p2pk",
        "multisig" => "multisig",
        "nulldata" => "op_return",
        other => other,
    }
}
