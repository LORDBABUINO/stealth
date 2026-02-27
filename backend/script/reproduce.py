#!/usr/bin/env python3
"""
reproduce.py
============
Reproduces 12 Bitcoin privacy vulnerabilities on a local custom Signet.
Each run creates NEW on-chain transactions that exhibit the vulnerability.
No detection logic — that lives in detect.py.

Usage:
    python3 reproduce.py              # Create all 12 vulnerability scenarios
    python3 reproduce.py -k 3         # Create only vulnerability 3
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bitcoin_rpc import (
    cli, mine_blocks, get_tx, get_utxos, get_balance,
    get_new_address, send_to_address, create_raw_tx, sign_raw_tx,
    send_raw, get_block_count, create_funded_psbt,
    process_psbt, finalize_psbt,
)

# ═══════════════════════════════════════════════════════════════════════════════
# Formatting helpers
# ═══════════════════════════════════════════════════════════════════════════════
G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; B = "\033[1m"; R = "\033[0m"

def header(num, title):
    print(f"\n{'═'*78}")
    print(f"{B}{C}  REPRODUCE {num}: {title}{R}")
    print(f"{'═'*78}")

def ok(msg):
    print(f"  {G}✓{R} {msg}")

def info(msg):
    print(f"  {Y}ℹ{R} {msg}")

def ensure_funds(wallet, min_btc=0.5):
    bal = get_balance(wallet)
    if bal < min_btc:
        addr = get_new_address(wallet, "bech32")
        send_to_address("miner", addr, min_btc + 0.5)
        mine_blocks(1)

def mine_and_confirm():
    mine_blocks(1)
    time.sleep(0.5)

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Address Reuse
# ═══════════════════════════════════════════════════════════════════════════════
def reproduce_01():
    header(1, "Address Reuse")
    ensure_funds("bob", 1.0)
    reused_addr = get_new_address("alice", "bech32")
    txid1 = send_to_address("bob", reused_addr, 0.01)
    txid2 = send_to_address("bob", reused_addr, 0.02)
    mine_and_confirm()
    ok(f"Sent to same address {reused_addr} twice: TX {txid1[:16]}… and {txid2[:16]}…")

# ═══════════════════════════════════════════════════════════════════════════════
# 2. Multi-input / CIOH
# ═══════════════════════════════════════════════════════════════════════════════
def reproduce_02():
    header(2, "Multi-input / CIOH (Common Input Ownership Heuristic)")
    ensure_funds("bob", 2.0)
    for _ in range(5):
        addr = get_new_address("alice", "bech32")
        send_to_address("bob", addr, 0.005)
    mine_and_confirm()

    utxos = get_utxos("alice", 1)
    small = [u for u in utxos if 0.004 < u["amount"] < 0.006][:5]
    if len(small) < 2:
        info("Not enough small UTXOs, skipping consolidation step")
        return
    inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in small]
    dest = get_new_address("bob", "bech32")
    total = sum(u["amount"] for u in small)
    psbt_result = create_funded_psbt(
        "alice", inputs, [{dest: round(total - 0.001, 8)}],
        {"subtractFeeFromOutputs": [0], "add_inputs": False}
    )
    signed = process_psbt("alice", psbt_result["psbt"])
    final = finalize_psbt(signed["psbt"])
    txid = send_raw(final["hex"])
    mine_and_confirm()
    ok(f"Consolidated {len(small)} inputs in TX {txid[:16]}… (CIOH trigger)")

# ═══════════════════════════════════════════════════════════════════════════════
# 3. Dust UTXO Detection
# ═══════════════════════════════════════════════════════════════════════════════
def reproduce_03():
    header(3, "Dust UTXO Detection")
    ensure_funds("bob", 1.0)
    dust1 = get_new_address("alice", "bech32")
    dust2 = get_new_address("alice", "bech32")
    bob_utxos = get_utxos("bob", 1)
    big = max(bob_utxos, key=lambda u: u["amount"])
    change = get_new_address("bob", "bech32")
    change_amt = round(big["amount"] - 0.00001000 - 0.00000546 - 0.0001, 8)
    raw = create_raw_tx(
        [{"txid": big["txid"], "vout": big["vout"]}],
        [{dust1: 0.00001000}, {dust2: 0.00000546}, {change: change_amt}]
    )
    signed = sign_raw_tx("bob", raw)
    txid = send_raw(signed["hex"])
    mine_and_confirm()
    ok(f"Created 1000-sat and 546-sat dust outputs to Alice in TX {txid[:16]}…")

# ═══════════════════════════════════════════════════════════════════════════════
# 4. Spending Dust with Normal Inputs
# ═══════════════════════════════════════════════════════════════════════════════
def reproduce_04():
    header(4, "Spending Dust with Normal Inputs")
    ensure_funds("alice", 0.5)
    utxos = get_utxos("alice", 1)
    dust_utxos = [u for u in utxos if u["amount"] <= 0.00001]
    normal_utxos = [u for u in utxos if u["amount"] > 0.001]

    if not dust_utxos:
        info("No dust UTXOs, creating one first…")
        ensure_funds("bob", 1.0)
        a = get_new_address("alice", "bech32")
        bu = get_utxos("bob", 1)
        big = max(bu, key=lambda u: u["amount"])
        ch = get_new_address("bob", "bech32")
        raw = create_raw_tx(
            [{"txid": big["txid"], "vout": big["vout"]}],
            [{a: 0.00001000}, {ch: round(big["amount"] - 0.00001 - 0.0001, 8)}]
        )
        signed = sign_raw_tx("bob", raw)
        send_raw(signed["hex"])
        mine_and_confirm()
        utxos = get_utxos("alice", 1)
        dust_utxos = [u for u in utxos if u["amount"] <= 0.00001]
        normal_utxos = [u for u in utxos if u["amount"] > 0.001]

    if not normal_utxos:
        ensure_funds("alice", 0.5)
        mine_and_confirm()
        utxos = get_utxos("alice", 1)
        normal_utxos = [u for u in utxos if u["amount"] > 0.001]

    dust = dust_utxos[0]
    normal = normal_utxos[0]
    dest = get_new_address("bob", "bech32")
    total = dust["amount"] + normal["amount"]
    raw = create_raw_tx(
        [{"txid": dust["txid"], "vout": dust["vout"]},
         {"txid": normal["txid"], "vout": normal["vout"]}],
        [{dest: round(total - 0.0001, 8)}]
    )
    signed = sign_raw_tx("alice", raw)
    txid = send_raw(signed["hex"])
    mine_and_confirm()
    ok(f"Spent dust ({int(dust['amount']*1e8)} sats) + normal ({normal['amount']:.8f}) together in TX {txid[:16]}…")

# ═══════════════════════════════════════════════════════════════════════════════
# 5. Change Detection
# ═══════════════════════════════════════════════════════════════════════════════
def reproduce_05():
    header(5, "Change Detection — Round Payment")
    ensure_funds("alice", 1.0)
    bob_addr = get_new_address("bob", "bech32")
    txid = send_to_address("alice", bob_addr, 0.05)
    mine_and_confirm()
    ok(f"Alice paid Bob 0.05 BTC (round amount) in TX {txid[:16]}… — change output is obvious")

# ═══════════════════════════════════════════════════════════════════════════════
# 6. Consolidation Origin
# ═══════════════════════════════════════════════════════════════════════════════
def reproduce_06():
    header(6, "Consolidation Origin")
    ensure_funds("bob", 2.0)
    for _ in range(4):
        addr = get_new_address("alice", "bech32")
        send_to_address("bob", addr, 0.003)
    mine_and_confirm()

    utxos = get_utxos("alice", 1)
    small = [u for u in utxos if 0.002 < u["amount"] < 0.004][:4]
    if len(small) < 3:
        info(f"Only {len(small)} small UTXOs, creating more…")
        for _ in range(4):
            addr = get_new_address("alice", "bech32")
            send_to_address("bob", addr, 0.003)
        mine_and_confirm()
        utxos = get_utxos("alice", 1)
        small = [u for u in utxos if 0.002 < u["amount"] < 0.004][:4]

    inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in small]
    consol_addr = get_new_address("alice", "bech32")
    total = sum(u["amount"] for u in small)
    raw = create_raw_tx(inputs, [{consol_addr: round(total - 0.0001, 8)}])
    signed = sign_raw_tx("alice", raw)
    consol_txid = send_raw(signed["hex"])
    mine_and_confirm()
    ok(f"Consolidated {len(small)} UTXOs → 1 in TX {consol_txid[:16]}…")

    # Now spend the consolidated output
    utxos = get_utxos("alice", 1)
    cu = [u for u in utxos if u["txid"] == consol_txid]
    if cu:
        dest = get_new_address("carol", "bech32")
        raw = create_raw_tx(
            [{"txid": cu[0]["txid"], "vout": cu[0]["vout"]}],
            [{dest: round(cu[0]["amount"] - 0.0001, 8)}]
        )
        signed = sign_raw_tx("alice", raw)
        txid2 = send_raw(signed["hex"])
        mine_and_confirm()
        ok(f"Spent consolidated UTXO in TX {txid2[:16]}… — carries full cluster history")

# ═══════════════════════════════════════════════════════════════════════════════
# 7. Script Type Mixing
# ═══════════════════════════════════════════════════════════════════════════════
def reproduce_07():
    header(7, "Script Type Mixing")
    ensure_funds("bob", 2.0)
    wpkh = get_new_address("alice", "bech32")
    tr = get_new_address("alice", "bech32m")
    send_to_address("bob", wpkh, 0.005)
    send_to_address("bob", tr, 0.005)
    mine_and_confirm()

    utxos = get_utxos("alice", 1)
    def is_wpkh(addr):
        return addr and not addr.startswith(("tb1p","bc1p","bcrt1p")) and addr.startswith(("tb1q","bc1q","bcrt1q"))
    def is_tr(addr):
        return addr and addr.startswith(("tb1p","bc1p","bcrt1p"))
    wu = next((u for u in utxos if is_wpkh(u.get("address","")) and u["amount"] >= 0.004), None)
    tu = next((u for u in utxos if is_tr(u.get("address","")) and u["amount"] >= 0.004), None)
    if not wu or not tu:
        info("Could not find both UTXO types")
        return
    dest = get_new_address("bob", "bech32")
    total = wu["amount"] + tu["amount"]
    raw = create_raw_tx(
        [{"txid": wu["txid"], "vout": wu["vout"]},
         {"txid": tu["txid"], "vout": tu["vout"]}],
        [{dest: round(total - 0.0002, 8)}]
    )
    signed = sign_raw_tx("alice", raw)
    txid = send_raw(signed["hex"])
    mine_and_confirm()
    ok(f"Mixed P2WPKH + P2TR inputs in TX {txid[:16]}… — script type fingerprint")

# ═══════════════════════════════════════════════════════════════════════════════
# 8. Cluster Merge
# ═══════════════════════════════════════════════════════════════════════════════
def reproduce_08():
    header(8, "Cluster Merge")
    ensure_funds("bob", 2.0)
    ensure_funds("carol", 2.0)
    a_addr = get_new_address("alice", "bech32")
    b_addr = get_new_address("alice", "bech32")
    txid_a = send_to_address("bob", a_addr, 0.004)
    txid_b = send_to_address("carol", b_addr, 0.004)
    mine_and_confirm()

    utxos = get_utxos("alice", 1)
    ua = next((u for u in utxos if u["txid"] == txid_a), None)
    ub = next((u for u in utxos if u["txid"] == txid_b), None)
    if not ua: ua = next((u for u in utxos if u.get("address") == a_addr), None)
    if not ub: ub = next((u for u in utxos if u.get("address") == b_addr), None)
    if not ua or not ub:
        info("Could not find both cluster UTXOs")
        return
    dest = get_new_address("bob", "bech32")
    total = ua["amount"] + ub["amount"]
    raw = create_raw_tx(
        [{"txid": ua["txid"], "vout": ua["vout"]},
         {"txid": ub["txid"], "vout": ub["vout"]}],
        [{dest: round(total - 0.0002, 8)}]
    )
    signed = sign_raw_tx("alice", raw)
    txid = send_raw(signed["hex"])
    mine_and_confirm()
    ok(f"Merged Bob-cluster and Carol-cluster UTXOs in TX {txid[:16]}…")

# ═══════════════════════════════════════════════════════════════════════════════
# 9. Lookback Depth
# ═══════════════════════════════════════════════════════════════════════════════
def reproduce_09():
    header(9, "Lookback Depth / UTXO Age")
    old_addr = get_new_address("alice", "bech32")
    send_to_address("miner", old_addr, 0.01)
    mine_blocks(20)
    new_addr = get_new_address("alice", "bech32")
    send_to_address("miner", new_addr, 0.01)
    mine_and_confirm()
    ok(f"Created old UTXO (20+ blocks ago) and new UTXO (just now) for Alice")

# ═══════════════════════════════════════════════════════════════════════════════
# 10. Exchange Origin
# ═══════════════════════════════════════════════════════════════════════════════
def reproduce_10():
    header(10, "Exchange Origin — Batch Withdrawal")
    ensure_funds("exchange", 5.0)
    batch = {}
    wallets = ["alice", "bob", "carol", "alice", "bob", "carol", "alice", "bob"]
    for i in range(8):
        addr = get_new_address(wallets[i], "bech32")
        batch[addr] = round(0.01 + i * 0.001, 8)
    txid = cli("sendmany", "", json.dumps(batch), wallet="exchange")
    mine_and_confirm()
    ok(f"Exchange batch withdrawal to 8 recipients in TX {txid[:16]}…")

# ═══════════════════════════════════════════════════════════════════════════════
# 11. Tainted UTXOs
# ═══════════════════════════════════════════════════════════════════════════════
def reproduce_11():
    header(11, "Tainted UTXOs / Dirty Money")
    ensure_funds("risky", 2.0)
    ensure_funds("bob", 1.0)
    ta = get_new_address("alice", "bech32")
    taint_txid = send_to_address("risky", ta, 0.01)
    ca = get_new_address("alice", "bech32")
    clean_txid = send_to_address("bob", ca, 0.01)
    mine_and_confirm()

    utxos = get_utxos("alice", 1)
    tu = next((u for u in utxos if u["txid"] == taint_txid), None)
    cu = next((u for u in utxos if u["txid"] == clean_txid), None)
    if not tu: tu = next((u for u in utxos if u.get("address") == ta), None)
    if not cu: cu = next((u for u in utxos if u.get("address") == ca), None)
    if not tu or not cu:
        info("Could not locate tainted + clean UTXOs")
        return
    dest = get_new_address("carol", "bech32")
    total = tu["amount"] + cu["amount"]
    raw = create_raw_tx(
        [{"txid": tu["txid"], "vout": tu["vout"]},
         {"txid": cu["txid"], "vout": cu["vout"]}],
        [{dest: round(total - 0.0002, 8)}]
    )
    signed = sign_raw_tx("alice", raw)
    txid = send_raw(signed["hex"])
    mine_and_confirm()
    ok(f"Merged tainted + clean UTXOs in TX {txid[:16]}… — taint propagation")

# ═══════════════════════════════════════════════════════════════════════════════
# 12. Behavioral Fingerprinting
# ═══════════════════════════════════════════════════════════════════════════════
def reproduce_12():
    header(12, "Behavioral Fingerprinting")
    ensure_funds("alice", 3.0)
    ensure_funds("bob", 3.0)

    info("Alice's pattern: round amounts, always bech32…")
    for i in range(5):
        dest = get_new_address("carol", "bech32")
        send_to_address("alice", dest, 0.01 * (i + 1))

    mine_and_confirm()

    info("Bob's pattern: odd amounts, mixed address types…")
    for i in range(5):
        atype = "bech32m" if i % 2 == 0 else "bech32"
        dest = get_new_address("carol", atype)
        send_to_address("bob", dest, round(0.00723 * (i + 1) + 0.00011, 8))

    mine_and_confirm()
    ok("Created distinguishable behavioral patterns for Alice and Bob")


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════
ALL = [
    (1, "Address Reuse", reproduce_01),
    (2, "Multi-input / CIOH", reproduce_02),
    (3, "Dust UTXO Detection", reproduce_03),
    (4, "Dust Spending w/ Normal", reproduce_04),
    (5, "Change Detection", reproduce_05),
    (6, "Consolidation Origin", reproduce_06),
    (7, "Script Type Mixing", reproduce_07),
    (8, "Cluster Merge", reproduce_08),
    (9, "Lookback Depth", reproduce_09),
    (10, "Exchange Origin", reproduce_10),
    (11, "Tainted UTXOs", reproduce_11),
    (12, "Behavioral Fingerprint", reproduce_12),
]

def main():
    filt = None
    if "-k" in sys.argv:
        idx = sys.argv.index("-k")
        if idx + 1 < len(sys.argv):
            filt = sys.argv[idx + 1]

    print(f"\n{B}{'═'*78}{R}")
    print(f"{B}{C}  REPRODUCE — Bitcoin Privacy Vulnerabilities{R}")
    print(f"{B}{C}  Custom Signet — {get_block_count()} blocks{R}")
    print(f"{B}{'═'*78}{R}")

    for num, name, fn in ALL:
        if filt and str(num) != filt:
            continue
        try:
            fn()
        except Exception as e:
            print(f"  \033[91m✗ ERROR in {name}: {e}\033[0m")
            import traceback; traceback.print_exc()

    print(f"\n{B}{'═'*78}{R}")
    print(f"  {G}Done. All vulnerability scenarios have been created on-chain.{R}")
    print(f"  Now run: python3 detect.py <descriptor>")
    print(f"{B}{'═'*78}{R}\n")

if __name__ == "__main__":
    main()
