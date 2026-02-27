#!/usr/bin/env python3
"""
detect.py
=========
Blockchain privacy vulnerability detector.

INPUT:  One or more output descriptors (or --wallet <name> to read them).
OUTPUT: Every privacy vulnerability found for that descriptor's address set.

The detector creates a temporary watch-only wallet, imports descriptors with
a full rescan, then analyses all historical transactions touching any derived
address. It never scans the entire chain — only transactions the wallet knows.

Usage:
    python3 detect.py --wallet alice
    python3 detect.py "wpkh([fp/84h/1h/0h]tpub.../0/*)#checksum" "wpkh([fp/84h/1h/0h]tpub.../1/*)#checksum"
    python3 detect.py --wallet alice --known-risky-wallets risky --known-exchange-wallets exchange
"""

import sys
import os
import json
import time
import hashlib
import argparse
from collections import defaultdict
from math import log2

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bitcoin_rpc import cli, get_tx

FINDINGS = []
WARNINGS = []

def section(title):
    print(f"[{title}]", file=sys.stderr)

def finding(msg):
    FINDINGS.append(msg)

def warn(msg):
    WARNINGS.append(msg)

def ok(msg):
    print(f"ok: {msg}", file=sys.stderr)

def info(msg):
    print(f"  {msg}", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. WALLET + ADDRESS RESOLUTION
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_descriptors(args):
    """Get the descriptor list from args: either --wallet or positional descriptors."""
    descs = []
    if args.wallet:
        result = cli("listdescriptors", wallet=args.wallet)
        for d in result["descriptors"]:
            descs.append({
                "desc": d["desc"],
                "internal": d.get("internal", False),
                "active": d.get("active", True),
                "range_end": d.get("range", [0, 999])[1] if isinstance(d.get("range"), list) else d.get("range", 999),
            })
    else:
        for raw in args.descriptors:
            base = raw.split("#")[0]
            if "/0/*" in base:
                candidates = [(base, False), (base.replace("/0/*", "/1/*"), True)]
            elif "/1/*" in base:
                candidates = [(base.replace("/1/*", "/0/*"), False), (base, True)]
            else:
                candidates = [(base, False)]
            for desc, internal in candidates:
                try:
                    normalized = cli("getdescriptorinfo", desc)["descriptor"]
                except Exception:
                    normalized = desc
                descs.append({
                    "desc": normalized,
                    "internal": internal,
                    "active": True,
                    "range_end": 999,
                })
    return descs


def derive_all_addresses(descriptors):
    """Derive addresses from all descriptors, return {address -> (desc_type, internal, index)}."""
    addr_map = {}  # address -> metadata
    for dinfo in descriptors:
        desc = dinfo["desc"]
        rng = min(dinfo["range_end"], 999)
        # Detect descriptor type
        dtype = "unknown"
        if desc.startswith("wpkh("): dtype = "p2wpkh"
        elif desc.startswith("tr("): dtype = "p2tr"
        elif desc.startswith("sh(wpkh("): dtype = "p2sh-p2wpkh"
        elif desc.startswith("pkh("): dtype = "p2pkh"

        try:
            addrs = cli("deriveaddresses", desc, f"[0,{rng}]")
            if addrs:
                for i, a in enumerate(addrs):
                    addr_map[a] = {
                        "type": dtype,
                        "internal": dinfo["internal"],
                        "index": i,
                    }
        except Exception as e:
            info(f"Could not derive from {desc[:40]}…: {e}")
    return addr_map


def build_scan_wallet(descriptors, wallet_name="_detect_scan"):
    """Create a temporary watch-only wallet with descriptors, do full rescan."""
    # Clean up if exists
    try:
        cli("unloadwallet", wallet_name)
    except Exception:
        pass

    try:
        cli("createwallet", wallet_name, "true", "true", "", "false", "true")
    except Exception:
        try:
            cli("loadwallet", wallet_name)
        except Exception:
            pass

    import_batch = []
    for d in descriptors:
        import_batch.append({
            "desc": d["desc"],
            "timestamp": 0,  # full rescan
            "internal": d["internal"],
            "active": d["active"],
            "range": [0, d["range_end"]],
        })

    result = cli("importdescriptors", json.dumps(import_batch), wallet=wallet_name)
    # Check results
    for r in (result or []):
        if not r.get("success"):
            info(f"Import warning: {r.get('error', {}).get('message', 'unknown')}")

    return wallet_name


def get_all_transactions(wallet_name, count=10000):
    """Get full transaction history for the wallet."""
    txs = cli("listtransactions", "*", count, 0, "true", wallet=wallet_name)
    return txs or []


def get_all_utxos(wallet_name):
    """Get all UTXOs (confirmed and unconfirmed)."""
    return cli("listunspent", 0, 9999999, wallet=wallet_name) or []


# ═══════════════════════════════════════════════════════════════════════════════
# 2. TRANSACTION GRAPH BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

class TxGraph:
    """Indexed view of all transactions touching our address set."""

    def __init__(self, addr_map, wallet_txs, utxos):
        self.addr_map = addr_map          # {address -> metadata}
        self.our_addrs = set(addr_map.keys())
        self.utxos = utxos                # current UTXOs
        self.tx_cache = {}                # txid -> decoded tx
        self.our_txids = set()            # txids we participate in

        # Index: address -> list of (txid, direction, value)
        self.addr_txs = defaultdict(list)  # address -> [{txid, direction, amount}]
        # Index: txid -> list of our addresses involved
        self.tx_addrs = defaultdict(set)

        # Build from wallet tx list
        for wtx in wallet_txs:
            txid = wtx.get("txid", "")
            addr = wtx.get("address", "")
            cat = wtx.get("category", "")  # send/receive
            amount = wtx.get("amount", 0)
            if txid:
                self.our_txids.add(txid)
            if addr and txid:
                self.addr_txs[addr].append({
                    "txid": txid, "category": cat, "amount": amount,
                    "confirmations": wtx.get("confirmations", 0),
                    "blockheight": wtx.get("blockheight", 0),
                })
                self.tx_addrs[txid].add(addr)

    def fetch_tx(self, txid):
        """Get decoded transaction (cached)."""
        if txid not in self.tx_cache:
            try:
                self.tx_cache[txid] = get_tx(txid)
            except Exception:
                return None
        return self.tx_cache[txid]

    def get_input_addresses(self, txid):
        """Get all input addresses for a transaction."""
        tx = self.fetch_tx(txid)
        if not tx:
            return []
        addrs = []
        for vin in tx.get("vin", []):
            if vin.get("coinbase"):
                continue
            parent = self.fetch_tx(vin["txid"])
            if parent:
                vout_data = parent["vout"][vin["vout"]]
                addr = vout_data.get("scriptPubKey", {}).get("address", "")
                value = vout_data.get("value", 0)
                addrs.append({"address": addr, "value": value, "txid": vin["txid"], "vout": vin["vout"]})
        return addrs

    def get_output_addresses(self, txid):
        """Get all output addresses for a transaction."""
        tx = self.fetch_tx(txid)
        if not tx:
            return []
        addrs = []
        for vout in tx.get("vout", []):
            addr = vout.get("scriptPubKey", {}).get("address", "")
            addrs.append({
                "address": addr,
                "value": vout["value"],
                "n": vout["n"],
                "type": vout.get("scriptPubKey", {}).get("type", "unknown"),
            })
        return addrs

    def is_ours(self, address):
        return address in self.our_addrs

    def get_script_type(self, address):
        """Return the script type metadata for one of our addresses."""
        meta = self.addr_map.get(address)
        if meta:
            return meta["type"]
        # Heuristic from prefix (supports mainnet, testnet/signet, regtest)
        if address.startswith(("tb1q", "bc1q", "bcrt1q")):
            return "p2wpkh"
        if address.startswith(("tb1p", "bc1p", "bcrt1p")):
            return "p2tr"
        if address.startswith(("2", "3")):
            return "p2sh-p2wpkh"
        return "unknown"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. VULNERABILITY DETECTORS
#
# Each detector receives the TxGraph and reports findings.
# ═══════════════════════════════════════════════════════════════════════════════

def detect_01_address_reuse(g: TxGraph):
    """Detect addresses that appear as recipients in multiple transactions."""
    section("1 · Address Reuse")
    reused = {}
    for addr in g.our_addrs:
        # Count distinct TXIDs where this address received funds
        receive_txids = set()
        for entry in g.addr_txs.get(addr, []):
            if entry["category"] == "receive":
                receive_txids.add(entry["txid"])
        if len(receive_txids) >= 2:
            reused[addr] = receive_txids

    if not reused:
        ok("No address reuse detected.")
        return

    for addr, txids in reused.items():
        meta = g.addr_map.get(addr, {})
        role = "change" if meta.get("internal") else "receive"
        tx_list = []
        for txid in sorted(txids):
            tx = g.fetch_tx(txid)
            tx_list.append({"txid": txid, "confirmations": tx.get("confirmations", 0) if tx else 0})
        finding({
            "type": "ADDRESS_REUSE",
            "severity": "HIGH",
            "description": f"Address {addr} ({role}) reused across {len(txids)} transactions",
            "details": {
                "address": addr,
                "role": role,
                "tx_count": len(txids),
                "txids": tx_list,
            },
        })


def detect_02_cioh(g: TxGraph):
    """Detect multi-input transactions (CIOH) and verify input ownership."""
    section("2 · Common Input Ownership Heuristic (CIOH)")
    found_any = False

    for txid in g.our_txids:
        tx = g.fetch_tx(txid)
        if not tx or len(tx.get("vin", [])) < 2:
            continue

        input_addrs = g.get_input_addresses(txid)
        if len(input_addrs) < 2:
            continue

        # Classify inputs: ours vs external
        our_inputs = [ia for ia in input_addrs if g.is_ours(ia["address"])]
        ext_inputs = [ia for ia in input_addrs if not g.is_ours(ia["address"])]
        total_inputs = len(input_addrs)
        n_ours = len(our_inputs)

        if n_ours < 2:
            # Only 1 of ours — CIOH doesn't expose us
            continue

        found_any = True
        n_outputs = len(tx.get("vout", []))
        ownership_pct = n_ours / total_inputs * 100

        severity = "CRITICAL" if n_ours == total_inputs else "HIGH"
        finding({
            "type": "CIOH",
            "severity": severity,
            "description": f"TX {txid} merges {n_ours}/{total_inputs} of your inputs ({round(ownership_pct)}% ownership)",
            "details": {
                "txid": txid,
                "total_inputs": total_inputs,
                "our_inputs": n_ours,
                "external_inputs": len(ext_inputs),
                "ownership_pct": round(ownership_pct),
                "our_addresses": [
                    {
                        "address": ia["address"],
                        "role": "change" if g.addr_map.get(ia["address"], {}).get("internal") else "receive",
                        "amount_btc": round(ia["value"], 8),
                    }
                    for ia in our_inputs
                ],
            },
        })

    if not found_any:
        ok("No multi-input transactions with ≥2 of your addresses detected.")


def detect_03_dust(g: TxGraph):
    """Detect dust UTXOs (current and historical)."""
    section("3 · Dust UTXO Detection")
    DUST_SATS = 1000
    STRICT_DUST = 546

    found = []
    for utxo in g.utxos:
        sats = int(round(utxo["amount"] * 1e8))
        if sats <= DUST_SATS and g.is_ours(utxo.get("address", "")):
            found.append(utxo)

    # Also check historical: any tx that sent dust to our addresses
    hist_dust = []
    for txid in g.our_txids:
        outputs = g.get_output_addresses(txid)
        for out in outputs:
            sats = int(round(out["value"] * 1e8))
            if sats <= DUST_SATS and g.is_ours(out["address"]):
                hist_dust.append({"txid": txid, "address": out["address"], "sats": sats})

    if not found and not hist_dust:
        ok("No dust UTXOs detected.")
        return

    if found:
        for u in found:
            sats = int(round(u["amount"] * 1e8))
            label = "STRICT_DUST" if sats <= STRICT_DUST else "dust-class"
            finding({
                "type": "DUST",
                "severity": "HIGH" if label == "STRICT_DUST" else "MEDIUM",
                "description": f"Dust UTXO at {u['address']} ({sats} sats, {label}, unspent)",
                "details": {
                    "status": "unspent",
                    "address": u["address"],
                    "sats": sats,
                    "label": label,
                    "txid": u["txid"],
                    "vout": u["vout"],
                },
            })

    # Deduplicate historical
    seen = set()
    unique_hist = []
    for h in hist_dust:
        key = (h["txid"], h["address"])
        if key not in seen:
            seen.add(key)
            unique_hist.append(h)

    if unique_hist:
        current_keys = {(u["txid"], u.get("address", "")) for u in found}
        for h in unique_hist:
            if (h["txid"], h["address"]) not in current_keys:
                finding({
                    "type": "DUST",
                    "severity": "LOW",
                    "description": f"Historical dust output at {h['address']} ({h['sats']} sats, already spent)",
                    "details": {
                        "status": "spent",
                        "address": h["address"],
                        "sats": h["sats"],
                        "txid": h["txid"],
                    },
                })


def detect_04_dust_spending(g: TxGraph):
    """Detect transactions that spend dust alongside normal inputs."""
    section("4 · Dust Spent with Normal Inputs")
    DUST_SATS = 1000
    found_any = False

    for txid in g.our_txids:
        input_addrs = g.get_input_addresses(txid)
        if not input_addrs or len(input_addrs) < 2:
            continue

        dust_inputs = []
        normal_inputs = []
        for ia in input_addrs:
            if not g.is_ours(ia["address"]):
                continue
            sats = int(round(ia["value"] * 1e8))
            if sats <= DUST_SATS:
                dust_inputs.append(ia)
            elif sats > 10000:  # > 10k sats = clearly normal
                normal_inputs.append(ia)

        if dust_inputs and normal_inputs:
            found_any = True
            finding({
                "type": "DUST_SPENDING",
                "severity": "HIGH",
                "description": f"TX {txid} spends {len(dust_inputs)} dust input(s) alongside {len(normal_inputs)} normal input(s)",
                "details": {
                    "txid": txid,
                    "dust_inputs": [{"address": d["address"], "sats": int(round(d["value"] * 1e8))} for d in dust_inputs],
                    "normal_inputs": [{"address": n["address"], "amount_btc": round(n["value"], 8)} for n in normal_inputs],
                },
            })

    if not found_any:
        ok("No dust spending mixed with normal inputs detected.")


def detect_05_change_detection(g: TxGraph):
    """Detect transactions where change output is easily distinguishable."""
    section("5 · Probable Change Output Detection")
    found_any = False

    for txid in g.our_txids:
        tx = g.fetch_tx(txid)
        if not tx:
            continue
        outputs = g.get_output_addresses(txid)
        input_addrs = g.get_input_addresses(txid)
        if not outputs or len(outputs) < 2:
            continue

        # We only care about sends (where at least 1 input is ours)
        our_in = [ia for ia in input_addrs if g.is_ours(ia["address"])]
        if not our_in:
            continue

        # Identify which outputs are ours (change) vs external (payment)
        our_outs = [o for o in outputs if g.is_ours(o["address"])]
        ext_outs = [o for o in outputs if not g.is_ours(o["address"])]

        if not our_outs or not ext_outs:
            continue  # can't distinguish change if all outputs are ours or all external

        # Check change-detection heuristics
        problems = []

        for change in our_outs:
            ch_sats = int(round(change["value"] * 1e8))
            ch_round = ch_sats % 100000 == 0 or ch_sats % 1000000 == 0

            for payment in ext_outs:
                pay_sats = int(round(payment["value"] * 1e8))
                pay_round = pay_sats % 100000 == 0 or pay_sats % 1000000 == 0

                # Heuristic 1: payment is round, change is not
                if pay_round and not ch_round:
                    problems.append(f"Round payment ({pay_sats} sats) vs non-round change ({ch_sats} sats)")

                # Heuristic 2: change has same script type as input
                in_types = set(g.get_script_type(ia["address"]) for ia in our_in)
                ch_type = g.get_script_type(change["address"])
                if ch_type in in_types and change["type"] != payment["type"]:
                    problems.append(
                        f"Change script type ({change['type']}) matches input type — different from payment ({payment['type']})"
                    )

                # Heuristic 3: change address is internal (derivation /1/*)
                ch_meta = g.addr_map.get(change["address"], {})
                if ch_meta.get("internal"):
                    problems.append("Change uses an internal (BIP-44 /1/*) derivation path — standard wallet change pattern")

        if problems:
            found_any = True
            finding({
                "type": "CHANGE_DETECTION",
                "severity": "MEDIUM",
                "description": f"TX {txid} has identifiable change output(s) ({len(problems)} heuristic(s) matched)",
                "details": {
                    "txid": txid,
                    "reasons": problems[:6],
                    "change_outputs": [{"address": co["address"], "amount_btc": round(co["value"], 8)} for co in our_outs],
                },
            })

    if not found_any:
        ok("No easily identifiable change outputs detected.")


def detect_06_consolidation_origin(g: TxGraph):
    """Detect UTXOs that originate from a prior consolidation transaction."""
    section("6 · UTXOs from Prior Consolidation")
    CONSOLIDATION_THRESHOLD = 3  # ≥3 inputs with ≤2 outputs = consolidation
    found_any = False

    for utxo in g.utxos:
        if not g.is_ours(utxo.get("address", "")):
            continue
        parent = g.fetch_tx(utxo["txid"])
        if not parent:
            continue
        n_in = len(parent.get("vin", []))
        n_out = len(parent.get("vout", []))
        if n_in >= CONSOLIDATION_THRESHOLD and n_out <= 2:
            found_any = True
            # Check how many of the consolidation inputs were ours
            parent_inputs = g.get_input_addresses(utxo["txid"])
            our_parent_in = [ia for ia in parent_inputs if g.is_ours(ia["address"])]
            finding({
                "type": "CONSOLIDATION",
                "severity": "MEDIUM",
                "description": f"UTXO {utxo['txid']}:{utxo['vout']} ({utxo['amount']:.8f} BTC) born from a {n_in}-input consolidation",
                "details": {
                    "txid": utxo["txid"],
                    "vout": utxo["vout"],
                    "amount_btc": round(utxo["amount"], 8),
                    "consolidation_inputs": n_in,
                    "consolidation_outputs": n_out,
                    "our_inputs_in_consolidation": len(our_parent_in),
                },
            })

    if not found_any:
        ok("No UTXOs from prior consolidation detected.")


def detect_07_script_type_mixing(g: TxGraph):
    """Detect transactions mixing different script types in inputs."""
    section("7 · Script Type Mixing in Inputs")
    found_any = False

    for txid in g.our_txids:
        input_addrs = g.get_input_addresses(txid)
        if len(input_addrs) < 2:
            continue

        our_in = [ia for ia in input_addrs if g.is_ours(ia["address"])]
        if len(our_in) < 2:
            continue

        types = set()
        for ia in input_addrs:
            types.add(g.get_script_type(ia["address"]))

        types.discard("unknown")
        if len(types) >= 2:
            found_any = True
            finding({
                "type": "SCRIPT_TYPE_MIXING",
                "severity": "HIGH",
                "description": f"TX {txid} mixes input script types: {sorted(types)}",
                "details": {
                    "txid": txid,
                    "script_types": sorted(types),
                    "inputs": [
                        {"address": ia["address"], "script_type": g.get_script_type(ia["address"]), "ours": g.is_ours(ia["address"])}
                        for ia in input_addrs
                    ],
                },
            })

    if not found_any:
        ok("No script type mixing detected.")


def detect_08_cluster_merge(g: TxGraph):
    """Detect transactions that merge UTXOs from different funding sources (clusters)."""
    section("8 · Cluster Merge (Cross-Origin Input Mixing)")
    found_any = False

    for txid in g.our_txids:
        input_addrs = g.get_input_addresses(txid)
        if len(input_addrs) < 2:
            continue

        our_in = [ia for ia in input_addrs if g.is_ours(ia["address"])]
        if len(our_in) < 2:
            continue

        # Trace each of our inputs one hop back to find their funding sources
        funding_sources = {}  # our_input_txid:vout -> set of grandparent source txids
        for ia in our_in:
            parent_tx = g.fetch_tx(ia["txid"])
            if not parent_tx:
                continue
            gp_sources = set()
            for p_vin in parent_tx.get("vin", []):
                if p_vin.get("coinbase"):
                    gp_sources.add("coinbase")
                else:
                    gp_sources.add(p_vin["txid"][:16])
            funding_sources[f"{ia['txid'][:16]}:{ia['vout']}"] = gp_sources

        # Check if funding sources differ
        all_sources = list(funding_sources.values())
        if len(all_sources) >= 2:
            # Are the source sets disjoint? (different clusters)
            merged_clusters = False
            for i in range(len(all_sources)):
                for j in range(i + 1, len(all_sources)):
                    if all_sources[i].isdisjoint(all_sources[j]):
                        merged_clusters = True

            if merged_clusters:
                found_any = True
                finding({
                    "type": "CLUSTER_MERGE",
                    "severity": "HIGH",
                    "description": f"TX {txid} merges UTXOs from {len(funding_sources)} different funding chains",
                    "details": {
                        "txid": txid,
                        "funding_sources": {k: sorted(v) for k, v in funding_sources.items()},
                    },
                })

    if not found_any:
        ok("No cross-origin cluster merges detected.")


def detect_09_lookback_depth(g: TxGraph):
    """Detect UTXOs with significantly different ages (dormancy patterns)."""
    section("9 · UTXO Age / Lookback Depth")

    if not g.utxos:
        ok("No UTXOs to analyze.")
        return

    our_utxos = [u for u in g.utxos if g.is_ours(u.get("address", ""))]
    if not our_utxos:
        ok("No UTXOs belonging to the descriptor.")
        return

    # Get confirmation counts
    aged = []
    for u in our_utxos:
        confs = u.get("confirmations", 0)
        aged.append({"utxo": u, "confirmations": confs})

    if len(aged) < 2:
        ok("Only one UTXO, no age comparison possible.")
        return

    aged.sort(key=lambda x: x["confirmations"], reverse=True)
    oldest = aged[0]
    newest = aged[-1]
    spread = oldest["confirmations"] - newest["confirmations"]

    if spread < 10:
        ok(f"UTXO age spread is small ({spread} blocks). No dormancy pattern.")
        return

    finding({
        "type": "UTXO_AGE_SPREAD",
        "severity": "LOW",
        "description": f"UTXO age spread of {spread} blocks between oldest and newest",
        "details": {
            "spread_blocks": spread,
            "oldest": {"txid": oldest["utxo"]["txid"], "confirmations": oldest["confirmations"], "amount_btc": round(oldest["utxo"]["amount"], 8)},
            "newest": {"txid": newest["utxo"]["txid"], "confirmations": newest["confirmations"], "amount_btc": round(newest["utxo"]["amount"], 8)},
        },
    })

    OLD_THRESHOLD = 100  # blocks
    old_utxos = [a for a in aged if a["confirmations"] >= OLD_THRESHOLD]
    if old_utxos:
        warn({
            "type": "DORMANT_UTXOS",
            "severity": "LOW",
            "description": f"{len(old_utxos)} UTXO(s) have ≥{OLD_THRESHOLD} confirmations (dormant/hoarded coins pattern)",
            "details": {
                "count": len(old_utxos),
                "threshold_blocks": OLD_THRESHOLD,
            },
        })


def detect_10_exchange_origin(g: TxGraph, known_exchange_wallets=None):
    """Detect UTXOs that likely originated from exchange batch withdrawals."""
    section("10 · Probable Exchange Origin")

    # Build set of known exchange txids if wallet names provided
    exchange_txids = set()
    if known_exchange_wallets:
        for ew in known_exchange_wallets:
            try:
                etxs = cli("listtransactions", "*", 10000, 0, "true", wallet=ew)
                for etx in (etxs or []):
                    if etx.get("txid"):
                        exchange_txids.add(etx["txid"])
            except Exception:
                pass

    BATCH_THRESHOLD = 5  # ≥5 outputs = likely batch withdrawal
    found_any = False

    for txid in g.our_txids:
        tx = g.fetch_tx(txid)
        if not tx:
            continue

        n_out = len(tx.get("vout", []))
        if n_out < BATCH_THRESHOLD:
            continue

        # Check: do we RECEIVE in this tx? (we're a recipient, not sender)
        our_inputs = [ia for ia in g.get_input_addresses(txid) if g.is_ours(ia["address"])]
        our_outputs = [o for o in g.get_output_addresses(txid) if g.is_ours(o["address"])]

        if our_inputs:
            # We're a sender in a many-output TX — that's OUR batch, not exchange
            continue

        if not our_outputs:
            continue

        # Heuristics for exchange batch
        signals = []

        # 1. High output count
        signals.append(f"High output count: {n_out}")

        # 2. Many unique addresses
        unique_addrs = set()
        for vout in tx["vout"]:
            a = vout.get("scriptPubKey", {}).get("address", "")
            if a:
                unique_addrs.add(a)
        if len(unique_addrs) >= BATCH_THRESHOLD:
            signals.append(f"{len(unique_addrs)} unique recipient addresses")

        # 3. Known exchange wallet
        if txid in exchange_txids:
            signals.append("TX matches known exchange wallet history")

        # 4. Large input relative to individual outputs
        input_addrs = g.get_input_addresses(txid)
        input_total = sum(ia["value"] for ia in input_addrs)
        output_vals = sorted(v.get("value", 0) for v in tx["vout"])
        if output_vals:
            median_out = output_vals[len(output_vals) // 2]
            if median_out > 0:
                ratio = input_total / median_out
                if ratio > 10:
                    signals.append(f"Input/median-output ratio: {ratio:.0f}x (hot wallet pattern)")

        if len(signals) >= 2:
            found_any = True
            finding({
                "type": "EXCHANGE_ORIGIN",
                "severity": "MEDIUM",
                "description": f"TX {txid} looks like an exchange batch withdrawal ({len(signals)} signal(s))",
                "details": {
                    "txid": txid,
                    "signals": signals,
                    "received_outputs": [{"address": o["address"], "amount_btc": round(o["value"], 8)} for o in our_outputs],
                },
            })

    if not found_any:
        ok("No exchange-origin batch patterns detected.")


def detect_11_tainted_utxos(g: TxGraph, known_risky_wallets=None):
    """Detect UTXOs that have taint from known risky sources."""
    section("11 · Tainted UTXOs / Risky Source Exposure")

    if not known_risky_wallets:
        info("No --known-risky-wallets provided. Skipping taint analysis.")
        info("(Provide wallet names to enable: --known-risky-wallets risky)")
        ok("Taint detection requires known-risky wallet metadata.")
        return

    # Build set of risky TXIDs
    risky_txids = set()
    for rw in known_risky_wallets:
        try:
            rtxs = cli("listtransactions", "*", 10000, 0, "true", wallet=rw)
            for rtx in (rtxs or []):
                if rtx.get("txid"):
                    risky_txids.add(rtx["txid"])
        except Exception:
            info(f"Could not read wallet '{rw}'")

    if not risky_txids:
        info("No transactions found in risky wallets.")
        return

    found_any = False

    for txid in g.our_txids:
        input_addrs = g.get_input_addresses(txid)
        our_in = [ia for ia in input_addrs if g.is_ours(ia["address"])]
        if not our_in or len(input_addrs) < 2:
            continue

        tainted = []
        clean = []
        for ia in input_addrs:
            # An input is tainted if its funding TX is in a risky wallet's history
            if ia["txid"] in risky_txids:
                tainted.append(ia)
            else:
                clean.append(ia)

        if tainted and clean:
            found_any = True
            taint_pct = len(tainted) / len(input_addrs) * 100
            finding({
                "type": "TAINTED_UTXO_MERGE",
                "severity": "HIGH",
                "description": f"TX {txid} merges {len(tainted)} tainted + {len(clean)} clean inputs ({round(taint_pct)}% taint)",
                "details": {
                    "txid": txid,
                    "tainted_inputs": [{"address": t["address"], "amount_btc": round(t["value"], 8), "source_txid": t["txid"]} for t in tainted],
                    "clean_inputs": [{"address": c["address"], "amount_btc": round(c["value"], 8)} for c in clean],
                    "taint_pct": round(taint_pct),
                },
            })

    # Also check: did we receive directly from a risky source?
    for txid in g.our_txids:
        if txid in risky_txids:
            our_outs = [o for o in g.get_output_addresses(txid) if g.is_ours(o["address"])]
            if our_outs:
                found_any = True
                warn({
                    "type": "DIRECT_TAINT",
                    "severity": "HIGH",
                    "description": f"TX {txid} is directly from a known risky source",
                    "details": {
                        "txid": txid,
                        "received_outputs": [{"address": o["address"], "amount_btc": round(o["value"], 8)} for o in our_outs],
                    },
                })

    if not found_any:
        ok("No tainted UTXO merges detected.")


def detect_12_behavioral_fingerprint(g: TxGraph):
    """
    Analyze the descriptor's transaction set for patterns that make the user
    identifiable through behavioral consistency.

    We evaluate OBJECTIVE, measurable features that chain analysis firms
    actually use to cluster and fingerprint wallets.
    """
    section("12 · Behavioral Fingerprint Analysis")

    # Collect send transactions (where we have inputs)
    send_txids = []
    for txid in g.our_txids:
        input_addrs = g.get_input_addresses(txid)
        our_in = [ia for ia in input_addrs if g.is_ours(ia["address"])]
        if our_in:
            send_txids.append(txid)

    if len(send_txids) < 3:
        ok(f"Only {len(send_txids)} send transactions — not enough data for fingerprinting.")
        return

    # ── Feature extraction ──
    output_counts = []
    payment_amounts_sats = []
    change_amounts_sats = []
    input_script_types = []
    output_script_types = []
    rbf_signals = []
    locktime_values = []
    fee_rates = []     # sat/vB
    n_inputs_list = []
    uses_round_amounts = 0
    total_payments = 0
    change_address_types_used = set()
    payment_address_types_used = set()
    version_numbers = set()

    for txid in send_txids:
        tx = g.fetch_tx(txid)
        if not tx:
            continue

        n_in = len(tx.get("vin", []))
        n_out = len(tx.get("vout", []))
        n_inputs_list.append(n_in)
        output_counts.append(n_out)

        # Version
        version_numbers.add(tx.get("version", 2))

        # Locktime
        locktime_values.append(tx.get("locktime", 0))

        # RBF signalling
        for vin in tx.get("vin", []):
            seq = vin.get("sequence", 0xffffffff)
            rbf_signals.append(seq < 0xfffffffe)

        # Input script types
        for ia in g.get_input_addresses(txid):
            if g.is_ours(ia["address"]):
                input_script_types.append(g.get_script_type(ia["address"]))

        # Output analysis
        outputs = g.get_output_addresses(txid)
        for out in outputs:
            sats = int(round(out["value"] * 1e8))
            if g.is_ours(out["address"]):
                # Change output
                change_amounts_sats.append(sats)
                change_address_types_used.add(out["type"])
            else:
                # Payment output
                payment_amounts_sats.append(sats)
                output_script_types.append(out["type"])
                payment_address_types_used.add(out["type"])
                total_payments += 1
                if sats > 0 and (sats % 100000 == 0 or sats % 1000000 == 0):
                    uses_round_amounts += 1

        # Fee rate
        if "vsize" in tx and tx["vsize"] > 0:
            # Compute fee from inputs - outputs
            in_total = sum(ia["value"] for ia in g.get_input_addresses(txid))
            out_total = sum(v.get("value", 0) for v in tx["vout"])
            fee_sats = int(round((in_total - out_total) * 1e8))
            if fee_sats > 0:
                fee_rates.append(fee_sats / tx["vsize"])

    # ── Analysis ──
    problems = []

    # 1. Round amount usage pattern
    if total_payments > 0:
        round_pct = uses_round_amounts / total_payments * 100
        if round_pct > 60:
            problems.append(
                f"Round payment amounts: {round_pct:.0f}% of payments are round numbers. "
                "This is a distinctive behavioral pattern that aids clustering."
            )

    # 2. Consistent output count (always 2 outputs = simple spend pattern)
    if output_counts:
        avg_outs = sum(output_counts) / len(output_counts)
        if all(c == output_counts[0] for c in output_counts) and len(output_counts) >= 3:
            problems.append(
                f"Uniform output count: all {len(output_counts)} send TXs have exactly "
                f"{output_counts[0]} outputs. Consistent structure aids fingerprinting."
            )

    # 3. Script type consistency or mixing
    input_types_set = set(input_script_types)
    if len(input_types_set) > 1:
        problems.append(
            f"Mixed input script types used across TXs: {input_types_set}. "
            "Mixing address families is rare and highly identifying."
        )
    elif len(input_types_set) == 1 and input_script_types:
        t = input_types_set.pop()
        if t == "p2pkh":
            problems.append(
                f"All inputs use legacy P2PKH — a very uncommon script type today. "
                "This alone narrows your anonymity set significantly."
            )

    # 4. RBF signaling consistency
    if rbf_signals:
        rbf_pct = sum(rbf_signals) / len(rbf_signals) * 100
        if rbf_pct == 100:
            problems.append(
                f"RBF always enabled: 100% of inputs signal replace-by-fee. "
                "While increasingly common, it's a distinguishing feature vs non-RBF wallets."
            )
        elif rbf_pct == 0:
            problems.append(
                "RBF never enabled: 0% of inputs signal replace-by-fee. "
                "This is uncommon in modern wallets and distinguishes your software."
            )

    # 5. Locktime pattern
    if locktime_values:
        nonzero_lt = [lt for lt in locktime_values if lt > 0]
        if len(nonzero_lt) == len(locktime_values) and len(locktime_values) >= 3:
            problems.append(
                "Anti-fee-sniping locktime always set — consistent with Bitcoin Core / Electrum. "
                "Absence or presence of this reveals your wallet software."
            )
        elif not nonzero_lt and len(locktime_values) >= 3:
            problems.append(
                "Locktime always 0 — no anti-fee-sniping. "
                "This distinguishes your wallet from Bitcoin Core / Electrum defaults."
            )

    # 6. Fee rate consistency
    if len(fee_rates) >= 3:
        avg_fee = sum(fee_rates) / len(fee_rates)
        if avg_fee > 0:
            variance = sum((f - avg_fee) ** 2 for f in fee_rates) / len(fee_rates)
            stddev = variance ** 0.5
            cv = stddev / avg_fee  # coefficient of variation
            if cv < 0.15:
                problems.append(
                    f"Very consistent fee rate: avg {avg_fee:.1f} sat/vB ± {stddev:.1f} "
                    f"(CV={cv:.2f}). Low variance suggests fixed-fee-rate wallet configuration."
                )

    # 7. Change address type pattern
    if change_address_types_used and payment_address_types_used:
        if change_address_types_used != payment_address_types_used:
            # This leaks which outputs are change
            problems.append(
                f"Change uses different script type ({change_address_types_used}) "
                f"than payments ({payment_address_types_used}) — trivially identifies change outputs."
            )

    # 8. Input count pattern (always 1 input = no consolidation; always many = distinctive)
    if n_inputs_list and len(n_inputs_list) >= 3:
        if all(n == 1 for n in n_inputs_list):
            pass  # normal, not distinctive
        elif all(n == n_inputs_list[0] for n in n_inputs_list) and n_inputs_list[0] > 1:
            problems.append(
                f"Always uses exactly {n_inputs_list[0]} inputs per TX — unusual and identifying."
            )

    # ── Report ──
    if not problems:
        ok(f"Analyzed {len(send_txids)} transactions. No strong behavioral fingerprints detected.")
        return

    finding({
        "type": "BEHAVIORAL_FINGERPRINT",
        "severity": "MEDIUM",
        "description": f"Behavioral fingerprint detected across {len(send_txids)} send transactions ({len(problems)} pattern(s))",
        "details": {
            "send_tx_count": len(send_txids),
            "patterns": problems,
        },
    })


# ═══════════════════════════════════════════════════════════════════════════════
# 4. MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Detect Bitcoin privacy vulnerabilities from output descriptors.",
        epilog="Examples:\n"
               "  python3 detect.py --wallet alice\n"
               '  python3 detect.py --wallet alice --known-risky-wallets risky\n'
               '  python3 detect.py "wpkh(tpub.../0/*)#chk" "wpkh(tpub.../1/*)#chk"\n',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("descriptors", nargs="*", help="Output descriptors to scan")
    parser.add_argument("--wallet", "-w", help="Read descriptors from an existing wallet")
    parser.add_argument("--known-risky-wallets", nargs="*", default=None,
                        help="Wallet names whose TXIDs are considered tainted")
    parser.add_argument("--known-exchange-wallets", nargs="*", default=None,
                        help="Wallet names whose TXIDs are considered exchange-origin")
    parser.add_argument("--keep-scan-wallet", action="store_true",
                        help="Don't delete the temporary scan wallet after running")
    args = parser.parse_args()

    if not args.wallet and not args.descriptors:
        parser.error("Provide either --wallet <name> or one or more descriptors.")

    # ── Step 1: Resolve descriptors ──
    section("Setup: Resolving Descriptors")
    descriptors = resolve_descriptors(args)
    info(f"Found {len(descriptors)} descriptors")
    for d in descriptors:
        dtype = d["desc"].split("(")[0]
        role = "internal/change" if d["internal"] else "external/receive"
        info(f"  {dtype:15} {role:20} range [0..{d['range_end']}]")

    # ── Step 2: Derive all addresses ──
    section("Setup: Deriving Addresses")
    addr_map = derive_all_addresses(descriptors)
    info(f"Derived {len(addr_map)} addresses across all descriptor types")

    # Count by type
    type_counts = defaultdict(int)
    for meta in addr_map.values():
        type_counts[meta["type"]] += 1
    for t, c in sorted(type_counts.items()):
        info(f"  {t}: {c} addresses")

    # ── Step 3: Build watch-only wallet ──
    section("Setup: Building Scan Wallet")
    scan_wallet = "_detect_scan"
    if args.wallet:
        # If they gave us a wallet, just use it directly — faster, no rescan needed
        scan_wallet = args.wallet
        info(f"Using existing wallet '{scan_wallet}' directly (no rescan needed)")
    else:
        scan_wallet = build_scan_wallet(descriptors)
        info(f"Created temporary watch-only wallet '{scan_wallet}' with full rescan")

    # ── Step 4: Gather transaction history ──
    section("Setup: Loading Transaction History")
    wallet_txs = get_all_transactions(scan_wallet)
    utxos = get_all_utxos(scan_wallet)
    info(f"Transaction history: {len(wallet_txs)} entries")
    info(f"Current UTXOs: {len(utxos)}")

    if not wallet_txs:
        print(json.dumps({"error": "No transactions found for these descriptors."}))
        return

    # ── Step 5: Build transaction graph ──
    g = TxGraph(addr_map, wallet_txs, utxos)
    info(f"Unique transaction IDs: {len(g.our_txids)}")

    # ── Step 6: Run all detectors ──
    detect_01_address_reuse(g)
    detect_02_cioh(g)
    detect_03_dust(g)
    detect_04_dust_spending(g)
    detect_05_change_detection(g)
    detect_06_consolidation_origin(g)
    detect_07_script_type_mixing(g)
    detect_08_cluster_merge(g)
    detect_09_lookback_depth(g)
    detect_10_exchange_origin(g, args.known_exchange_wallets)
    detect_11_tainted_utxos(g, args.known_risky_wallets)
    detect_12_behavioral_fingerprint(g)

    # ── JSON output ──
    report = {
        "stats": {
            "transactions_analyzed": len(g.our_txids),
            "addresses_derived": len(addr_map),
        },
        "findings": FINDINGS,
        "warnings": WARNINGS,
        "summary": {
            "findings": len(FINDINGS),
            "warnings": len(WARNINGS),
            "clean": len(FINDINGS) == 0 and len(WARNINGS) == 0,
        },
    }
    print(json.dumps(report, indent=2))

    # Cleanup
    if not args.wallet and not args.keep_scan_wallet:
        try:
            cli("unloadwallet", "_detect_scan")
        except Exception:
            pass


if __name__ == "__main__":
    main()
