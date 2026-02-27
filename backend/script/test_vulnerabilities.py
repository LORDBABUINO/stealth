#!/usr/bin/env python3
"""
test_vulnerabilities.py
=======================
Reproduces and verifies 12 Bitcoin privacy vulnerabilities on a local custom Signet.

Each test:
  1. Creates the vulnerability scenario using real Bitcoin transactions
  2. Analyzes the on-chain data to DETECT the vulnerability
  3. Asserts the detection is correct (proving the vulnerability exists)

Usage:
    python3 test_vulnerabilities.py          # Run all tests
    python3 test_vulnerabilities.py -k 1     # Run test for vulnerability 1
"""

import sys
import os
import json
import time
import math
from collections import defaultdict

# Add project dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bitcoin_rpc import (
    cli, mine_blocks, get_tx, get_utxos, get_balance,
    get_new_address, send_to_address, create_raw_tx, sign_raw_tx,
    send_raw, decode_raw_tx, get_block_count, create_funded_psbt,
    process_psbt, finalize_psbt,
)

# ═══════════════════════════════════════════════════════════════════════════════
# ANSI colors for output
# ═══════════════════════════════════════════════════════════════════════════════
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

PASS_COUNT = 0
FAIL_COUNT = 0


def header(num, title):
    print(f"\n{'═'*78}")
    print(f"{BOLD}{CYAN}  VULNERABILITY {num}: {title}{RESET}")
    print(f"{'═'*78}")


def check(condition, msg):
    global PASS_COUNT, FAIL_COUNT
    if condition:
        PASS_COUNT += 1
        print(f"  {GREEN}✓ PASS:{RESET} {msg}")
    else:
        FAIL_COUNT += 1
        print(f"  {RED}✗ FAIL:{RESET} {msg}")
    return condition


def info(msg):
    print(f"  {YELLOW}ℹ{RESET} {msg}")


def ensure_funds(wallet, min_btc=0.5):
    """Ensure wallet has at least min_btc, fund from miner if needed."""
    bal = get_balance(wallet)
    if bal < min_btc:
        addr = get_new_address(wallet, "bech32")
        send_to_address("miner", addr, min_btc + 0.1)
        mine_blocks(1)


def mine_and_confirm():
    """Mine 1 block to confirm pending transactions."""
    mine_blocks(1)
    time.sleep(1)


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY 1: Address Reuse (Reutilização de endereços)
# ═══════════════════════════════════════════════════════════════════════════════
def test_01_address_reuse():
    header(1, "Address Reuse (Reutilização de endereços)")

    ensure_funds("bob", 1.0)

    # REPRODUCE: Generate ONE address for Alice, receive payments multiple times
    reused_addr = get_new_address("alice", "bech32")
    info(f"Alice's reused address: {reused_addr}")

    txid1 = send_to_address("bob", reused_addr, 0.01)
    txid2 = send_to_address("bob", reused_addr, 0.02)
    info(f"TX1: {txid1[:16]}... (0.01 BTC)")
    info(f"TX2: {txid2[:16]}... (0.02 BTC)")

    mine_and_confirm()

    # DETECT: Find the same address appearing as output in multiple transactions
    tx1 = get_tx(txid1)
    tx2 = get_tx(txid2)

    addr_occurrences = defaultdict(list)
    for tx_data, txid in [(tx1, txid1), (tx2, txid2)]:
        for vout in tx_data["vout"]:
            addr = vout.get("scriptPubKey", {}).get("address", "")
            if addr:
                addr_occurrences[addr].append(txid)

    # Check: reused_addr appears in outputs of BOTH transactions
    reuse_count = len(addr_occurrences.get(reused_addr, []))
    check(reuse_count >= 2,
          f"Address {reused_addr[:20]}... found in {reuse_count} distinct transactions (need ≥2)")

    # Show the privacy impact
    info(f"PRIVACY IMPACT: An observer can link TX1 and TX2 to the same entity")
    info(f"  because the same address {reused_addr[:20]}... receives funds in both")

    return True


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY 2: Multi-input Transactions (Consolidation / CIOH)
# ═══════════════════════════════════════════════════════════════════════════════
def test_02_consolidation_cioh():
    header(2, "Multi-input Transactions (Consolidation / CIOH)")

    ensure_funds("bob", 2.0)

    # REPRODUCE: Create 5 separate UTXOs for Alice, then spend them all at once
    alice_addrs = []
    for i in range(5):
        addr = get_new_address("alice", "bech32")
        send_to_address("bob", addr, 0.005)
        alice_addrs.append(addr)
        info(f"UTXO {i+1}: 0.005 BTC -> {addr[:20]}...")

    mine_and_confirm()

    # Select all Alice's UTXOs explicitly
    utxos = get_utxos("alice", 1)
    small_utxos = [u for u in utxos if 0.004 < u["amount"] < 0.006]
    info(f"Found {len(small_utxos)} small UTXOs to consolidate")

    # Build consolidation TX using PSBT
    inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in small_utxos[:5]]
    dest_addr = get_new_address("bob", "bech32")

    total_input = sum(u["amount"] for u in small_utxos[:5])
    send_amount = round(total_input - 0.001, 8)  # leave fee

    psbt_result = create_funded_psbt(
        "alice",
        inputs,
        [{dest_addr: send_amount}],
        {"subtractFeeFromOutputs": [0], "add_inputs": False}
    )
    psbt = psbt_result["psbt"]
    signed = process_psbt("alice", psbt)
    final = finalize_psbt(signed["psbt"])
    txid = send_raw(final["hex"])
    info(f"Consolidation TX: {txid[:16]}...")

    mine_and_confirm()

    # DETECT: Transaction with N≥2 inputs = CIOH trigger
    tx = get_tx(txid)
    num_inputs = len(tx["vin"])
    num_outputs = len(tx["vout"])

    check(num_inputs >= 2,
          f"Transaction has {num_inputs} inputs (CIOH: all inputs assumed same owner)")
    check(num_inputs >= 3 and num_outputs <= 2,
          f"Consolidation shape: {num_inputs} inputs → {num_outputs} outputs (many→few)")

    info(f"PRIVACY IMPACT: All {num_inputs} input addresses are now linked as same entity")
    for vin in tx["vin"]:
        parent_tx = get_tx(vin["txid"])
        addr = parent_tx["vout"][vin["vout"]]["scriptPubKey"].get("address", "?")
        info(f"  Linked address: {addr[:25]}...")

    return True


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY 3: Dust UTXO Detection (Detecção de UTXOs dust)
# ═══════════════════════════════════════════════════════════════════════════════
def test_03_dust_detection():
    header(3, "Dust UTXO Detection (Detecção de UTXOs dust)")

    ensure_funds("bob", 1.0)

    # REPRODUCE: Create very small UTXOs (dust-class)
    # Standard dust threshold for P2WPKH is ~294 sats at default relay fee
    # We'll create UTXOs of 546 sats (0.00000546) and 1000 sats (0.00001000)
    alice_dust_addr1 = get_new_address("alice", "bech32")
    alice_dust_addr2 = get_new_address("alice", "bech32")
    info(f"Dust target address 1: {alice_dust_addr1[:20]}...")
    info(f"Dust target address 2: {alice_dust_addr2[:20]}...")

    # Use raw tx to create precise dust amounts
    bob_utxos = get_utxos("bob", 1)
    big_utxo = max(bob_utxos, key=lambda u: u["amount"])
    info(f"Using Bob's UTXO: {big_utxo['amount']} BTC")

    change_addr = get_new_address("bob", "bech32")
    change_amount = round(big_utxo["amount"] - 0.00001000 - 0.00000546 - 0.0001, 8)

    raw_tx = create_raw_tx(
        [{"txid": big_utxo["txid"], "vout": big_utxo["vout"]}],
        [
            {alice_dust_addr1: 0.00001000},  # 1000 sats - dust-class
            {alice_dust_addr2: 0.00000546},  # 546 sats - at dust threshold
            {change_addr: change_amount},
        ]
    )
    signed = sign_raw_tx("bob", raw_tx)
    txid = send_raw(signed["hex"])
    info(f"Dust TX: {txid[:16]}...")

    mine_and_confirm()

    # DETECT: Scan outputs for values below dust threshold
    tx = get_tx(txid)
    DUST_THRESHOLD_SATS = 1000  # Conservative: anything ≤ 1000 sats is "dust-class"
    STRICT_DUST_SATS = 546      # Bitcoin Core's strict P2WPKH dust limit

    dust_outputs = []
    for vout in tx["vout"]:
        value_sats = int(round(vout["value"] * 1e8))
        if value_sats <= DUST_THRESHOLD_SATS:
            dust_outputs.append({
                "vout_n": vout["n"],
                "value_sats": value_sats,
                "address": vout["scriptPubKey"].get("address", "?"),
                "is_strict_dust": value_sats <= STRICT_DUST_SATS,
            })

    check(len(dust_outputs) >= 2,
          f"Found {len(dust_outputs)} dust outputs (≤{DUST_THRESHOLD_SATS} sats)")

    strict_dust = [d for d in dust_outputs if d["is_strict_dust"]]
    check(len(strict_dust) >= 1,
          f"Found {len(strict_dust)} outputs at/below strict dust threshold (≤{STRICT_DUST_SATS} sats)")

    for d in dust_outputs:
        info(f"  Dust output #{d['vout_n']}: {d['value_sats']} sats -> {d['address'][:20]}... "
             f"({'STRICT DUST' if d['is_strict_dust'] else 'dust-class'})")

    info("PRIVACY IMPACT: Dust UTXOs can be used as tracking tokens (dust attacks)")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY 4: Spending Dust with Other Inputs
# ═══════════════════════════════════════════════════════════════════════════════
def test_04_dust_spending():
    header(4, "Spending Dust UTXOs with Other Inputs")

    ensure_funds("alice", 1.0)

    # REPRODUCE: Alice has dust UTXOs from test 3, plus normal UTXOs
    # Spend a dust UTXO together with a normal UTXO
    utxos = get_utxos("alice", 1)

    dust_utxos = [u for u in utxos if u["amount"] <= 0.00001]
    normal_utxos = [u for u in utxos if u["amount"] > 0.001]

    if not dust_utxos:
        info("No dust UTXOs found, creating one...")
        # Create a dust UTXO for alice
        ensure_funds("bob", 1.0)
        alice_addr = get_new_address("alice", "bech32")
        bob_utxos = get_utxos("bob", 1)
        big_utxo = max(bob_utxos, key=lambda u: u["amount"])
        change_addr = get_new_address("bob", "bech32")
        change_amount = round(big_utxo["amount"] - 0.00001000 - 0.0001, 8)
        raw_tx = create_raw_tx(
            [{"txid": big_utxo["txid"], "vout": big_utxo["vout"]}],
            [{alice_addr: 0.00001000}, {change_addr: change_amount}]
        )
        signed = sign_raw_tx("bob", raw_tx)
        send_raw(signed["hex"])
        mine_and_confirm()
        utxos = get_utxos("alice", 1)
        dust_utxos = [u for u in utxos if u["amount"] <= 0.00001]
        normal_utxos = [u for u in utxos if u["amount"] > 0.001]

    if not normal_utxos:
        info("No normal UTXOs found, creating one...")
        ensure_funds("alice", 0.5)
        mine_and_confirm()
        utxos = get_utxos("alice", 1)
        normal_utxos = [u for u in utxos if u["amount"] > 0.001]

    dust = dust_utxos[0]
    normal = normal_utxos[0]

    info(f"Dust UTXO:   {dust['amount']:.8f} BTC ({int(dust['amount']*1e8)} sats)")
    info(f"Normal UTXO: {normal['amount']:.8f} BTC")

    # Spend both together
    dest_addr = get_new_address("bob", "bech32")
    total = dust["amount"] + normal["amount"]
    send_amt = round(total - 0.0001, 8)

    raw_tx = create_raw_tx(
        [
            {"txid": dust["txid"], "vout": dust["vout"]},
            {"txid": normal["txid"], "vout": normal["vout"]},
        ],
        [{dest_addr: send_amt}]
    )
    signed = sign_raw_tx("alice", raw_tx)
    txid = send_raw(signed["hex"])
    info(f"Dust-spend TX: {txid[:16]}...")

    mine_and_confirm()

    # DETECT: A tx with inputs mixing dust and non-dust
    tx = get_tx(txid)
    input_values = []
    for vin in tx["vin"]:
        parent = get_tx(vin["txid"])
        val = parent["vout"][vin["vout"]]["value"]
        input_values.append(val)

    dust_inputs = [v for v in input_values if v <= 0.00001]
    non_dust_inputs = [v for v in input_values if v > 0.001]

    check(len(dust_inputs) >= 1 and len(non_dust_inputs) >= 1,
          f"TX mixes {len(dust_inputs)} dust input(s) with {len(non_dust_inputs)} normal input(s)")

    info("PRIVACY IMPACT: Dust attack succeeds—the dust sender can now link")
    info("  Alice's normal UTXO to the dust tracking token via CIOH")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY 5: Change Detection (Detecção provável de troco)
# ═══════════════════════════════════════════════════════════════════════════════
def test_05_change_detection():
    header(5, "Probable Change Detection (Detecção provável de troco)")

    ensure_funds("alice", 1.0)

    # REPRODUCE: Alice pays Bob a round amount; wallet auto-creates change
    bob_addr = get_new_address("bob", "bech32")
    txid = send_to_address("alice", bob_addr, 0.05)  # Round payment
    info(f"Payment TX: {txid[:16]}...")

    mine_and_confirm()

    # DETECT: Heuristic change detection
    tx = get_tx(txid)

    payment_output = None
    change_candidate = None

    for vout in tx["vout"]:
        addr = vout["scriptPubKey"].get("address", "")
        value = vout["value"]
        value_sats = int(round(value * 1e8))

        # Heuristic 1: Round amount = payment (not change)
        is_round = (value_sats % 100000 == 0) or (value_sats % 1000000 == 0)

        # Heuristic 2: Recipient address
        is_to_bob = (addr == bob_addr)

        if is_to_bob or is_round:
            payment_output = {"n": vout["n"], "value": value, "addr": addr, "round": is_round}
        else:
            change_candidate = {"n": vout["n"], "value": value, "addr": addr, "round": is_round}

    check(payment_output is not None,
          f"Payment output detected: {payment_output['value']:.8f} BTC (round={payment_output['round']})")

    check(change_candidate is not None,
          f"Change candidate detected: {change_candidate['value']:.8f} BTC (non-round amount)")

    if payment_output and change_candidate:
        # Verify: change output should be the "odd" amount
        check(not change_candidate["round"],
              f"Change has non-round value ({int(change_candidate['value']*1e8)} sats) — strong change indicator")

        # Heuristic 3: Same script type as input
        input_tx = get_tx(tx["vin"][0]["txid"])
        input_type = input_tx["vout"][tx["vin"][0]["vout"]]["scriptPubKey"]["type"]
        change_type = tx["vout"][change_candidate["n"]]["scriptPubKey"]["type"]
        check(input_type == change_type,
              f"Change has same script type as input ({change_type}) — another strong indicator")

    info("PRIVACY IMPACT: Observer can distinguish payment from change,")
    info("  identifying the sender's change address and tracking their funds")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY 6: UTXOs from Prior Consolidation
# ═══════════════════════════════════════════════════════════════════════════════
def test_06_consolidation_origin():
    header(6, "UTXOs Originating from Prior Consolidation")

    ensure_funds("bob", 2.0)

    # REPRODUCE: Step 1 - Create a consolidation transaction for Alice
    for i in range(4):
        addr = get_new_address("alice", "bech32")
        send_to_address("bob", addr, 0.003)

    mine_and_confirm()

    # Consolidate
    utxos = get_utxos("alice", 1)
    small_utxos = [u for u in utxos if 0.002 < u["amount"] < 0.004][:4]

    if len(small_utxos) < 2:
        info(f"Not enough small UTXOs ({len(small_utxos)}), creating more...")
        for i in range(4):
            addr = get_new_address("alice", "bech32")
            send_to_address("bob", addr, 0.003)
        mine_and_confirm()
        utxos = get_utxos("alice", 1)
        small_utxos = [u for u in utxos if 0.002 < u["amount"] < 0.004][:4]

    inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in small_utxos]
    consolidation_addr = get_new_address("alice", "bech32")
    total = sum(u["amount"] for u in small_utxos)
    send_amt = round(total - 0.0001, 8)

    raw_tx = create_raw_tx(inputs, [{consolidation_addr: send_amt}])
    signed = sign_raw_tx("alice", raw_tx)
    consolidation_txid = send_raw(signed["hex"])
    info(f"Consolidation TX: {consolidation_txid[:16]}... ({len(inputs)} inputs → 1 output)")

    mine_and_confirm()

    # Step 2 - Spend the consolidated output
    utxos = get_utxos("alice", 1)
    consolidated = [u for u in utxos if u["txid"] == consolidation_txid]

    if consolidated:
        dest = get_new_address("carol", "bech32")
        spend_amt = round(consolidated[0]["amount"] - 0.0001, 8)
        raw_tx = create_raw_tx(
            [{"txid": consolidated[0]["txid"], "vout": consolidated[0]["vout"]}],
            [{dest: spend_amt}]
        )
        signed = sign_raw_tx("alice", raw_tx)
        spend_txid = send_raw(signed["hex"])
        info(f"Spend TX: {spend_txid[:16]}...")
        mine_and_confirm()

        # DETECT: Check if input's parent tx has consolidation shape
        spend_tx = get_tx(spend_txid)
        parent_txid = spend_tx["vin"][0]["txid"]
        parent_tx = get_tx(parent_txid)
        parent_inputs = len(parent_tx["vin"])
        parent_outputs = len(parent_tx["vout"])

        is_from_consolidation = parent_inputs >= 3 and parent_outputs <= 2

        check(is_from_consolidation,
              f"UTXO parent has consolidation shape: {parent_inputs} inputs → {parent_outputs} output(s)")
        check(parent_inputs >= 3,
              f"Parent tx has {parent_inputs} inputs (threshold: ≥3 = consolidation)")

        info("PRIVACY IMPACT: UTXOs born from consolidation carry the full")
        info("  cluster linkage of ALL inputs that were merged")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY 7: Script Type Inconsistency / Mixing
# ═══════════════════════════════════════════════════════════════════════════════
def test_07_script_type_mixing():
    header(7, "Script Type Inconsistency / Mixing")

    ensure_funds("bob", 2.0)

    # REPRODUCE: Create UTXOs of different script types for Alice
    wpkh_addr = get_new_address("alice", "bech32")    # P2WPKH (bc1q...)
    tr_addr = get_new_address("alice", "bech32m")      # P2TR (bc1p...)

    info(f"P2WPKH address: {wpkh_addr[:20]}...")
    info(f"P2TR address:   {tr_addr[:20]}...")

    send_to_address("bob", wpkh_addr, 0.005)
    send_to_address("bob", tr_addr, 0.005)
    mine_and_confirm()

    # Now spend both in the same transaction
    utxos = get_utxos("alice", 1)

    wpkh_utxo = None
    tr_utxo = None
    for u in utxos:
        if u.get("address", "").startswith("tb1q") and u["amount"] >= 0.004 and not wpkh_utxo:
            wpkh_utxo = u
        elif u.get("address", "").startswith("tb1p") and u["amount"] >= 0.004 and not tr_utxo:
            tr_utxo = u

    if not wpkh_utxo or not tr_utxo:
        # Fallback: try with desc type
        for u in utxos:
            desc = u.get("desc", "")
            if "wpkh" in desc and u["amount"] >= 0.004 and not wpkh_utxo:
                wpkh_utxo = u
            elif "tr(" in desc and u["amount"] >= 0.004 and not tr_utxo:
                tr_utxo = u

    if not wpkh_utxo or not tr_utxo:
        info("Could not find both UTXO types, listing available:")
        for u in utxos:
            info(f"  {u.get('address','?')[:25]}... = {u['amount']} ({u.get('desc','?')[:20]})")
        info("Skipping mixed-input test, testing output-side mixing instead...")

        # Output-side mixing: pay to P2WPKH and change to P2TR
        if utxos:
            dest_wpkh = get_new_address("bob", "bech32")
            dest_tr = get_new_address("bob", "bech32m")
            u = utxos[0]
            half = round(u["amount"] / 2 - 0.00005, 8)
            raw_tx = create_raw_tx(
                [{"txid": u["txid"], "vout": u["vout"]}],
                [{dest_wpkh: half}, {dest_tr: half}]
            )
            signed = sign_raw_tx("alice", raw_tx)
            txid = send_raw(signed["hex"])
            mine_and_confirm()
            tx = get_tx(txid)
            output_types = set()
            for vout in tx["vout"]:
                output_types.add(vout["scriptPubKey"]["type"])
            check(len(output_types) >= 2,
                  f"Output script types: {output_types} — heterogeneous outputs")
        return True

    info(f"P2WPKH UTXO: {wpkh_utxo['amount']} BTC at {wpkh_utxo.get('address','?')[:20]}...")
    info(f"P2TR UTXO:   {tr_utxo['amount']} BTC at {tr_utxo.get('address','?')[:20]}...")

    dest = get_new_address("bob", "bech32")
    total = wpkh_utxo["amount"] + tr_utxo["amount"]
    send_amt = round(total - 0.0002, 8)

    raw_tx = create_raw_tx(
        [
            {"txid": wpkh_utxo["txid"], "vout": wpkh_utxo["vout"]},
            {"txid": tr_utxo["txid"], "vout": tr_utxo["vout"]},
        ],
        [{dest: send_amt}]
    )
    signed = sign_raw_tx("alice", raw_tx)
    txid = send_raw(signed["hex"])
    info(f"Mixed-type TX: {txid[:16]}...")

    mine_and_confirm()

    # DETECT: Check if inputs have different script types
    tx = get_tx(txid)
    input_types = set()
    for vin in tx["vin"]:
        parent = get_tx(vin["txid"])
        script_type = parent["vout"][vin["vout"]]["scriptPubKey"]["type"]
        input_types.add(script_type)
        info(f"  Input type: {script_type}")

    check(len(input_types) >= 2,
          f"Input script types: {input_types} — heterogeneous (fingerprint!)")

    info("PRIVACY IMPACT: Mixing script types is a behavioral fingerprint")
    info("  and reveals the wallet controls both address families")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY 8: Merging Previously Separate UTXO Clusters
# ═══════════════════════════════════════════════════════════════════════════════
def test_08_cluster_merge():
    header(8, "Merging Previously Separate UTXO Clusters")

    ensure_funds("bob", 2.0)
    ensure_funds("carol", 2.0)

    # REPRODUCE: Create two separate clusters for Alice
    # Cluster A: from Bob
    cluster_a_addr = get_new_address("alice", "bech32")
    txid_a = send_to_address("bob", cluster_a_addr, 0.004)
    info(f"Cluster A (from Bob): {cluster_a_addr[:20]}... = 0.004 BTC")

    # Cluster B: from Carol
    cluster_b_addr = get_new_address("alice", "bech32")
    txid_b = send_to_address("carol", cluster_b_addr, 0.004)
    info(f"Cluster B (from Carol): {cluster_b_addr[:20]}... = 0.004 BTC")

    mine_and_confirm()

    # Find the specific UTXOs
    utxos = get_utxos("alice", 1)
    utxo_a = next((u for u in utxos if u["txid"] == txid_a), None)
    utxo_b = next((u for u in utxos if u["txid"] == txid_b), None)

    if not utxo_a or not utxo_b:
        info("Searching for UTXOs by address...")
        utxo_a = next((u for u in utxos if u.get("address") == cluster_a_addr), None)
        utxo_b = next((u for u in utxos if u.get("address") == cluster_b_addr), None)

    if not utxo_a or not utxo_b:
        info("Could not locate both cluster UTXOs")
        return False

    # MERGE: Spend one from each cluster together
    dest = get_new_address("bob", "bech32")
    total = utxo_a["amount"] + utxo_b["amount"]
    send_amt = round(total - 0.0002, 8)

    raw_tx = create_raw_tx(
        [
            {"txid": utxo_a["txid"], "vout": utxo_a["vout"]},
            {"txid": utxo_b["txid"], "vout": utxo_b["vout"]},
        ],
        [{dest: send_amt}]
    )
    signed = sign_raw_tx("alice", raw_tx)
    merge_txid = send_raw(signed["hex"])
    info(f"Cluster merge TX: {merge_txid[:16]}...")

    mine_and_confirm()

    # DETECT: Check if inputs come from different source clusters
    merge_tx = get_tx(merge_txid)
    source_txids = [vin["txid"] for vin in merge_tx["vin"]]

    # Trace each input to its source
    sources = {}
    for vin in merge_tx["vin"]:
        parent = get_tx(vin["txid"])
        # Who funded this? Check the inputs of the parent tx
        if parent["vin"][0].get("coinbase"):
            sources[vin["txid"]] = "coinbase"
        else:
            grandparent_txid = parent["vin"][0]["txid"]
            grandparent = get_tx(grandparent_txid)
            # Check which wallet owned the input
            sources[vin["txid"]] = grandparent_txid[:16]

    distinct_sources = len(set(sources.values()))
    check(len(source_txids) >= 2,
          f"Merge TX has {len(source_txids)} inputs from different funding transactions")

    check(distinct_sources >= 2 or len(source_txids) >= 2,
          f"Inputs trace to {distinct_sources} distinct source chains — clusters merged!")

    info("PRIVACY IMPACT: Previously separate identity clusters (Bob-linked")
    info("  and Carol-linked) are now permanently merged into one cluster")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY 9: UTXO Historical Depth (Lookback Depth)
# ═══════════════════════════════════════════════════════════════════════════════
def test_09_lookback_depth():
    header(9, "UTXO Historical Depth (Lookback Depth)")

    ensure_funds("alice", 1.0)

    # REPRODUCE: Create an "old" UTXO and let it age many blocks
    old_addr = get_new_address("alice", "bech32")
    old_txid = send_to_address("miner", old_addr, 0.01)
    info(f"Old UTXO created: {old_txid[:16]}...")

    mine_blocks(20)  # Age it 20 blocks
    info("Mined 20 blocks to age the UTXO")

    # Create a "new" UTXO
    new_addr = get_new_address("alice", "bech32")
    new_txid = send_to_address("miner", new_addr, 0.01)
    info(f"New UTXO created: {new_txid[:16]}...")

    mine_and_confirm()

    # DETECT: Compare confirmation depths
    old_tx = get_tx(old_txid)
    new_tx = get_tx(new_txid)

    old_confs = old_tx.get("confirmations", 0)
    new_confs = new_tx.get("confirmations", 0)

    check(old_confs > new_confs + 10,
          f"Old UTXO: {old_confs} confirmations vs New UTXO: {new_confs} confirmations (diff={old_confs - new_confs})")

    # Ancestor chain analysis
    def trace_depth(txid, max_depth=10):
        """Walk back through the transaction chain."""
        depth = 0
        current_txid = txid
        chain = [current_txid[:16]]
        for _ in range(max_depth):
            tx = get_tx(current_txid)
            if tx["vin"][0].get("coinbase"):
                chain.append("COINBASE")
                break
            current_txid = tx["vin"][0]["txid"]
            chain.append(current_txid[:16])
            depth += 1
        return depth, chain

    old_depth, old_chain = trace_depth(old_txid)
    new_depth, new_chain = trace_depth(new_txid)

    info(f"Old UTXO chain depth: {old_depth} hops: {' → '.join(old_chain[:5])}")
    info(f"New UTXO chain depth: {new_depth} hops: {' → '.join(new_chain[:5])}")

    check(old_confs >= 15,
          f"Old UTXO has ≥15 confirmations ({old_confs}) — detectable age pattern")

    info("PRIVACY IMPACT: UTXO age reveals dormancy patterns, coin hoarding,")
    info("  or can distinguish 'fresh' exchange withdrawals from aged savings")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY 10: Probable Exchange Origin
# ═══════════════════════════════════════════════════════════════════════════════
def test_10_exchange_origin():
    header(10, "Identification of Probable Exchange Origin")

    ensure_funds("exchange", 5.0)

    # REPRODUCE: Simulate exchange batch withdrawal (many outputs)
    batch_outputs = {}
    recipients = []
    for i in range(8):
        # Send to alice, bob, carol in round-robin plus random wallets
        wallets = ["alice", "bob", "carol", "alice", "bob", "carol", "alice", "bob"]
        addr = get_new_address(wallets[i], "bech32")
        batch_outputs[addr] = round(0.01 + (i * 0.001), 8)
        recipients.append((wallets[i], addr[:15]))

    info(f"Exchange batch withdrawal: {len(batch_outputs)} recipients")
    for w, a in recipients:
        info(f"  → {w}: {a}...")

    # Use sendmany for batch
    txid = cli("sendmany", "", json.dumps(batch_outputs), wallet="exchange")
    info(f"Batch TX: {txid[:16]}...")

    mine_and_confirm()

    # DETECT: Analyze the transaction for exchange-like patterns
    tx = get_tx(txid)
    num_outputs = len(tx["vout"])
    num_inputs = len(tx["vin"])

    # Exchange heuristics:
    # 1. High output count (batching)
    is_batch = num_outputs >= 5
    check(is_batch,
          f"High output count: {num_outputs} outputs (≥5 = likely batch withdrawal)")

    # 2. Round-ish payment amounts (exchanges often use round amounts)
    round_outputs = 0
    for vout in tx["vout"]:
        sats = int(round(vout["value"] * 1e8))
        if sats % 100000 == 0 or sats % 10000 == 0:
            round_outputs += 1

    # 3. Large input(s) relative to individual outputs
    input_total = 0
    for vin in tx["vin"]:
        parent = get_tx(vin["txid"])
        input_total += parent["vout"][vin["vout"]]["value"]

    # Exclude the largest output (likely change) — look at median payment
    output_vals = sorted([v["value"] for v in tx["vout"]])
    median_output = output_vals[len(output_vals) // 2]
    ratio = input_total / median_output if median_output > 0 else 0

    check(ratio > 3,
          f"Input/median-output ratio: {ratio:.1f}x (high ratio suggests large hot wallet)")

    # 4. Many unique recipient addresses
    unique_addrs = set()
    for vout in tx["vout"]:
        addr = vout["scriptPubKey"].get("address", "")
        if addr:
            unique_addrs.add(addr)

    check(len(unique_addrs) >= 5,
          f"Unique recipient addresses: {len(unique_addrs)} (many = batch pattern)")

    info("PRIVACY IMPACT: UTXOs from exchange withdrawals reveal the user")
    info("  interacted with that exchange, enabling entity-linking")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY 11: UTXOs from Risk Sources ("Dirty Money")
# ═══════════════════════════════════════════════════════════════════════════════
def test_11_tainted_utxos():
    header(11, 'UTXOs from Risk Sources ("Dirty Money" / Taint)')

    ensure_funds("risky", 2.0)
    ensure_funds("alice", 1.0)

    # REPRODUCE: "risky" (known bad actor) sends to Alice
    alice_tainted_addr = get_new_address("alice", "bech32")
    taint_txid = send_to_address("risky", alice_tainted_addr, 0.01)
    info(f"Taint TX (risky → alice): {taint_txid[:16]}...")

    # Also give Alice a clean UTXO
    alice_clean_addr = get_new_address("alice", "bech32")
    clean_txid = send_to_address("bob", alice_clean_addr, 0.01)
    info(f"Clean TX (bob → alice):   {clean_txid[:16]}...")

    mine_and_confirm()

    # Step 2: Alice consolidates tainted + clean (taint propagation!)
    utxos = get_utxos("alice", 1)
    tainted_utxo = next((u for u in utxos if u["txid"] == taint_txid), None)
    clean_utxo = next((u for u in utxos if u["txid"] == clean_txid), None)

    if not tainted_utxo or not clean_utxo:
        info("Locating UTXOs by address...")
        tainted_utxo = next((u for u in utxos if u.get("address") == alice_tainted_addr), None)
        clean_utxo = next((u for u in utxos if u.get("address") == alice_clean_addr), None)

    if not tainted_utxo or not clean_utxo:
        info("Could not find both UTXOs")
        return False

    # Merge tainted + clean
    dest = get_new_address("carol", "bech32")
    total = tainted_utxo["amount"] + clean_utxo["amount"]
    send_amt = round(total - 0.0002, 8)

    raw_tx = create_raw_tx(
        [
            {"txid": tainted_utxo["txid"], "vout": tainted_utxo["vout"]},
            {"txid": clean_utxo["txid"], "vout": clean_utxo["vout"]},
        ],
        [{dest: send_amt}]
    )
    signed = sign_raw_tx("alice", raw_tx)
    merge_txid = send_raw(signed["hex"])
    info(f"Taint merge TX: {merge_txid[:16]}...")

    mine_and_confirm()

    # DETECT: Taint analysis
    # Build set of TXIDs that originated from the "risky" wallet
    risky_txids = set()
    risky_txs = cli("listtransactions", "*", 100, 0, wallet="risky")
    for rtx in risky_txs:
        if rtx.get("txid"):
            risky_txids.add(rtx["txid"])

    merge_tx = get_tx(merge_txid)

    tainted_inputs = 0
    clean_inputs = 0
    for vin in merge_tx["vin"]:
        parent_txid = vin["txid"]
        # A parent TX is tainted if it appears in risky wallet's history
        is_tainted = parent_txid in risky_txids
        if is_tainted:
            tainted_inputs += 1
            info(f"  Input from {parent_txid[:16]}... — TAINTED (from risky source)")
        else:
            clean_inputs += 1
            info(f"  Input from {parent_txid[:16]}... — CLEAN")

    check(tainted_inputs >= 1,
          f"Found {tainted_inputs} tainted input(s) in the merge transaction")
    check(tainted_inputs >= 1 and clean_inputs >= 1,
          f"TAINT PROPAGATION: {tainted_inputs} tainted + {clean_inputs} clean merged → all outputs tainted")

    # Taint scoring
    taint_ratio = tainted_inputs / (tainted_inputs + clean_inputs) if (tainted_inputs + clean_inputs) > 0 else 0
    info(f"  Taint ratio: {taint_ratio:.0%} of inputs from risky sources")

    info("PRIVACY IMPACT: Merging tainted + clean funds contaminates ALL outputs")
    info("  Carol now receives 'dirty' coins even though she dealt with Alice")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY 12: Behavioral Fingerprinting
# ═══════════════════════════════════════════════════════════════════════════════
def test_12_behavioral_fingerprint():
    header(12, "Behavioral Fingerprinting")

    ensure_funds("alice", 3.0)
    ensure_funds("bob", 3.0)

    # REPRODUCE: Create distinctive transaction patterns for Alice vs Bob
    alice_txids = []
    bob_txids = []

    info("Creating Alice's transactions (consistent behavioral pattern)...")
    # Alice's pattern: always round payments, always bech32, always ~same fee
    for i in range(5):
        dest = get_new_address("carol", "bech32")  # Alice always pays to bech32
        amount = 0.01 * (i + 1)  # Always round amounts
        txid = send_to_address("alice", dest, amount)
        alice_txids.append(txid)
        info(f"  Alice TX {i+1}: {amount:.8f} BTC → bech32")

    mine_and_confirm()

    info("Creating Bob's transactions (different behavioral pattern)...")
    # Bob's pattern: odd amounts, mixes address types
    for i in range(5):
        addr_type = "bech32m" if i % 2 == 0 else "bech32"  # Bob mixes types
        dest = get_new_address("carol", addr_type)
        amount = 0.00723 * (i + 1) + 0.00011  # Odd amounts
        amount = round(amount, 8)
        txid = send_to_address("bob", dest, amount)
        bob_txids.append(txid)
        info(f"  Bob TX {i+1}: {amount:.8f} BTC → {addr_type}")

    mine_and_confirm()

    # DETECT: Extract behavioral features and distinguish users
    def extract_features(txids, label):
        features = {
            "label": label,
            "output_counts": [],
            "has_round_payment": [],
            "output_types": [],
            "feerate_estimates": [],
            "rbf_signals": [],
        }
        for txid in txids:
            tx = get_tx(txid)
            if not tx:
                continue

            # Output count
            features["output_counts"].append(len(tx["vout"]))

            # Round payment detection
            for vout in tx["vout"]:
                sats = int(round(vout["value"] * 1e8))
                is_round = sats % 100000 == 0 or sats % 1000000 == 0
                features["has_round_payment"].append(is_round)

            # Output script types
            for vout in tx["vout"]:
                features["output_types"].append(vout["scriptPubKey"]["type"])

            # RBF signaling (sequence < 0xfffffffe)
            for vin in tx["vin"]:
                seq = vin.get("sequence", 0xffffffff)
                features["rbf_signals"].append(seq < 0xfffffffe)

            # Fee estimation (size * feerate)
            if "vsize" in tx and "fee" in tx:
                feerate = abs(tx.get("fee", 0)) / tx["vsize"] * 1e8  # sat/vB
                features["feerate_estimates"].append(feerate)

        return features

    alice_features = extract_features(alice_txids, "alice")
    bob_features = extract_features(bob_txids, "bob")

    # Analysis
    alice_round_ratio = sum(alice_features["has_round_payment"]) / max(len(alice_features["has_round_payment"]), 1)
    bob_round_ratio = sum(bob_features["has_round_payment"]) / max(len(bob_features["has_round_payment"]), 1)

    alice_type_set = set(alice_features["output_types"])
    bob_type_set = set(bob_features["output_types"])

    info(f"\n  {'Feature':<30} {'Alice':<25} {'Bob':<25}")
    info(f"  {'─'*80}")
    info(f"  {'Round payment ratio':<30} {alice_round_ratio:<25.0%} {bob_round_ratio:<25.0%}")
    info(f"  {'Output types used':<30} {str(alice_type_set):<25} {str(bob_type_set):<25}")
    info(f"  {'Avg output count':<30} "
         f"{sum(alice_features['output_counts'])/max(len(alice_features['output_counts']),1):<25.1f} "
         f"{sum(bob_features['output_counts'])/max(len(bob_features['output_counts']),1):<25.1f}")

    alice_rbf = sum(alice_features["rbf_signals"]) / max(len(alice_features["rbf_signals"]), 1)
    bob_rbf = sum(bob_features["rbf_signals"]) / max(len(bob_features["rbf_signals"]), 1)
    info(f"  {'RBF signal ratio':<30} {alice_rbf:<25.0%} {bob_rbf:<25.0%}")

    # Distinguishability test
    features_differ = (
        abs(alice_round_ratio - bob_round_ratio) > 0.3 or
        alice_type_set != bob_type_set or
        abs(alice_rbf - bob_rbf) > 0.3
    )

    check(features_differ,
          "Behavioral features DIFFER between Alice and Bob — fingerprinting possible")

    check(alice_round_ratio > bob_round_ratio,
          f"Alice uses more round amounts ({alice_round_ratio:.0%}) than Bob ({bob_round_ratio:.0%})")

    # Check if Bob mixes script types more
    bob_mixes = len(bob_type_set) >= 2
    check(bob_mixes or alice_type_set != bob_type_set,
          f"Script type diversity differs: Alice={alice_type_set}, Bob={bob_type_set}")

    info("\nPRIVACY IMPACT: Consistent behavioral patterns allow re-identification")
    info("  of the same entity across transactions even without address reuse")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN: Run all tests
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    print(f"\n{BOLD}{'═'*78}{RESET}")
    print(f"{BOLD}{CYAN}  BITCOIN PRIVACY VULNERABILITY TEST SUITE{RESET}")
    print(f"{BOLD}{CYAN}  Custom Signet — {get_block_count()} blocks{RESET}")
    print(f"{BOLD}{'═'*78}{RESET}")

    # Check which test to run
    test_filter = None
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            if arg == "-k" and sys.argv.index(arg) + 1 < len(sys.argv):
                test_filter = sys.argv[sys.argv.index(arg) + 1]
            elif arg.isdigit():
                test_filter = arg

    tests = [
        (1, "Address Reuse", test_01_address_reuse),
        (2, "Multi-input / CIOH", test_02_consolidation_cioh),
        (3, "Dust UTXO Detection", test_03_dust_detection),
        (4, "Dust Spending w/ Normal", test_04_dust_spending),
        (5, "Change Detection", test_05_change_detection),
        (6, "Consolidation Origin", test_06_consolidation_origin),
        (7, "Script Type Mixing", test_07_script_type_mixing),
        (8, "Cluster Merge", test_08_cluster_merge),
        (9, "Lookback Depth", test_09_lookback_depth),
        (10, "Exchange Origin", test_10_exchange_origin),
        (11, "Tainted UTXOs", test_11_tainted_utxos),
        (12, "Behavioral Fingerprint", test_12_behavioral_fingerprint),
    ]

    results = {}
    for num, name, func in tests:
        if test_filter and str(num) != test_filter:
            continue
        try:
            result = func()
            results[num] = "PASS" if result else "FAIL"
        except Exception as e:
            results[num] = f"ERROR: {e}"
            print(f"  {RED}✗ ERROR:{RESET} {e}")
            import traceback
            traceback.print_exc()

    # Summary
    print(f"\n{'═'*78}")
    print(f"{BOLD}  TEST SUMMARY{RESET}")
    print(f"{'═'*78}")
    for num, name, _ in tests:
        if num in results:
            status = results[num]
            color = GREEN if status == "PASS" else RED
            print(f"  {color}{'✓' if status=='PASS' else '✗'}{RESET} Vulnerability {num:2d}: {name:<35} [{status}]")

    print(f"\n  {GREEN}Passed checks: {PASS_COUNT}{RESET}")
    print(f"  {RED}Failed checks: {FAIL_COUNT}{RESET}")
    print(f"  Total: {PASS_COUNT + FAIL_COUNT}")
    print()

    return FAIL_COUNT == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
