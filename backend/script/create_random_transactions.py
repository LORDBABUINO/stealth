#!/usr/bin/env python3
"""
create_random_transactions.py
==============================
Creates n varied, realistic-looking Bitcoin transactions involving Alice's wallet
on regtest. Each run is seeded with fresh entropy (block height + wall clock) so
the on-chain history grows organically and never looks the same twice.

Address types used:
  • bech32       (P2WPKH)      — bcrt1q…
  • bech32m      (P2TR)        — bcrt1p…
  • p2sh-segwit  (P2SH-P2WPKH) — 2…   (regtest)
  • legacy       (P2PKH)       — m…   (regtest)

Transaction archetypes (weighted random selection):
  01. simple_payment            Alice pays a peer, natural change
  02. multi_output              Alice batch-pays multiple recipients in one TX
  03. consolidation             Alice sweeps many small UTXOs → one
  04. self_transfer             Alice rotates to her own fresh address
  05. utxo_split                Alice fans one large UTXO out into several
  06. receive_from_peer         Peer spontaneously sends Alice funds
  07. exchange_withdrawal       Exchange batch-withdraws to Alice + others
  08. chain_hop                 Alice→Bob, then Bob→Carol (multi-hop chain)
  09. mixed_type_spend          Spend P2WPKH + P2TR inputs in one TX
  10. round_amount_payment      Deliberately round consumer-style payment
  11. psbt_coinjoin             Alice+Bob cooperate via PSBT (PayJoin-like)
  12. cold_to_hot               Taproot "cold" → P2WPKH "hot" sweep
  13. lightning_channel_like    Exact-msat-aligned channel-open sizing
  14. high_freq_small           Burst of rapid tiny payments (merchant pattern)
  15. receive_multiple_senders  Several wallets simultaneously send Alice funds

Usage:
    python3 create_random_transactions.py 20
    python3 create_random_transactions.py 50 --no-mine-final
    python3 create_random_transactions.py 10 --seed 42
"""

import sys
import os
import json
import time
import random
import argparse
import hashlib
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bitcoin_rpc import (
    cli, mine_blocks, get_utxos, get_balance,
    get_new_address, send_to_address, create_raw_tx, sign_raw_tx,
    send_raw, get_block_count, create_funded_psbt,
    process_psbt, finalize_psbt,
)

# ─── Colours ──────────────────────────────────────────────────────────────────
G   = "\033[92m"
Y   = "\033[93m"
R   = "\033[91m"
B   = "\033[1m"
C   = "\033[96m"
DIM = "\033[2m"
RST = "\033[0m"

def ok(msg):   print(f"  {G}✓{RST} {msg}")
def info(msg): print(f"  {Y}ℹ{RST} {msg}")
def warn(msg): print(f"  {R}⚠{RST} {msg}")
def hdr(msg):  print(f"\n  {B}{C}▸ {msg}{RST}")

# ─── Constants ────────────────────────────────────────────────────────────────
ALICE        = "alice"
SIDE_WALLETS = ["bob", "carol", "exchange", "miner"]
ALL_WALLETS  = [ALICE] + SIDE_WALLETS + ["risky"]

# Every address-type label that Bitcoin Core's getnewaddress accepts
ADDR_TYPES   = ["bech32", "bech32m", "p2sh-segwit", "legacy"]

FEE_RESERVE  = 0.00025   # BTC per input/output to leave for fees
DUST_LIMIT   = 0.00000546

# ─── Entropy / RNG ───────────────────────────────────────────────────────────
def reseed() -> int:
    """Seed random from chain height + nanosecond wall clock.  Returns seed."""
    h    = get_block_count()
    raw  = f"{h}{time.time_ns()}{os.getpid()}"
    seed = int(hashlib.sha256(raw.encode()).hexdigest(), 16) % (2**32)
    random.seed(seed)
    info(f"RNG seeded from block {h} + wall-clock  (seed={seed})")
    return seed


# ─── Amount helpers ───────────────────────────────────────────────────────────
def rand_btc(lo: float = 0.0005, hi: float = 0.05) -> float:
    """Random BTC amount; occasionally semi-rounded to mimic human behaviour."""
    v = random.uniform(lo, hi)
    r = random.random()
    if r < 0.15:
        v = round(v, 2)           # e.g. 0.03
    elif r < 0.30:
        v = round(v, 4)           # e.g. 0.0312
    else:
        v = round(v, 8)
    return max(lo, min(hi, v))


def round_btc() -> float:
    """A consumer-style round amount."""
    return random.choice([
        0.001, 0.002, 0.005, 0.01, 0.02, 0.025, 0.05, 0.1,
        0.0025, 0.0075, 0.015,
    ])


def rand_addr_type() -> str:
    return random.choice(ADDR_TYPES)


def rand_peer(exclude=None) -> str:
    pool = [w for w in SIDE_WALLETS if w != exclude]
    return random.choice(pool)


# ─── Funding / block helpers ──────────────────────────────────────────────────
def ensure_funded(wallet: str, min_btc: float = 0.5) -> None:
    bal = get_balance(wallet)
    if bal < min_btc:
        addr = get_new_address(wallet, "bech32")
        top_up = min_btc + random.uniform(0.5, 2.0)
        send_to_address("miner", addr, round(top_up, 8))
        info(f"Topped up {wallet} with {top_up:.4f} BTC from miner")


def maybe_mine(force: bool = False) -> None:
    """Mine 1-3 blocks with 40 % probability (or always when forced)."""
    if force or random.random() < 0.40:
        n         = random.randint(1, 3)
        maddr     = get_new_address("miner", "bech32")
        cli("generatetoaddress", n, maddr)
        ok(f"Mined {n} block(s)  (height={get_block_count()})")
        time.sleep(0.15)


def mine_confirm(n: int = 1) -> None:
    maddr = get_new_address("miner", "bech32")
    cli("generatetoaddress", n, maddr)
    time.sleep(0.15)


# ─── Transaction archetypes ───────────────────────────────────────────────────

def tx_simple_payment() -> str:
    """Alice pays a random peer a random amount — wallet produces change."""
    hdr("Simple Payment")
    ensure_funded(ALICE, 0.5)
    peer      = rand_peer()
    addr_type = rand_addr_type()
    dest      = get_new_address(peer, addr_type)
    amt       = rand_btc(0.001, 0.08)
    if get_balance(ALICE) < amt + FEE_RESERVE * 2:
        ensure_funded(ALICE, 1.0)
    txid = send_to_address(ALICE, dest, amt)
    maybe_mine()
    ok(f"Alice → {peer} ({addr_type})  {amt:.8f} BTC  TX={txid[:16]}…")
    return txid


def tx_multi_output() -> str:
    """Alice batch-pays 2-5 recipients in one sendmany transaction."""
    hdr("Multi-Output Batch Payment")
    ensure_funded(ALICE, 1.5)
    n_recv = random.randint(2, 5)
    batch  = {}
    total  = 0.0
    for _ in range(n_recv):
        addr  = get_new_address(rand_peer(), rand_addr_type())
        amt   = rand_btc(0.001, 0.025)
        batch[addr] = amt
        total += amt
    if get_balance(ALICE) < total + FEE_RESERVE * 4:
        ensure_funded(ALICE, total + 1.5)
    txid = cli("sendmany", "", json.dumps(batch), wallet=ALICE)
    maybe_mine()
    ok(f"Alice batch → {n_recv} recipients  TX={txid[:16]}…")
    return txid


def tx_consolidation() -> str | None:
    """Alice sweeps several small UTXOs into one output (wallet hygiene)."""
    hdr("UTXO Consolidation")
    # First scatter several small UTXOs to Alice via different sender wallets
    n_scatter = random.randint(3, 7)
    for _ in range(n_scatter):
        sender = rand_peer()
        ensure_funded(sender, 0.3)
        addr = get_new_address(ALICE, random.choice(["bech32", "bech32m"]))
        send_to_address(sender, addr, rand_btc(0.003, 0.015))
    mine_confirm(1)

    utxos = get_utxos(ALICE, 1)
    small = [u for u in utxos if 0.001 < u["amount"] < 0.02]
    if len(small) < 2:
        info("Not enough small UTXOs for consolidation, skipping")
        return None

    to_merge = small[: random.randint(2, min(len(small), 7))]
    dest     = get_new_address(ALICE, "bech32")
    total    = sum(u["amount"] for u in to_merge)
    fee      = FEE_RESERVE * len(to_merge)
    net      = round(total - fee, 8)
    if net <= DUST_LIMIT:
        info("Net after fee too small, skipping")
        return None

    inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in to_merge]
    raw    = create_raw_tx(inputs, [{dest: net}])
    signed = sign_raw_tx(ALICE, raw)
    txid   = send_raw(signed["hex"])
    maybe_mine()
    ok(f"Consolidated {len(to_merge)} UTXOs → 1  TX={txid[:16]}…")
    return txid


def tx_self_transfer() -> str:
    """Alice rotates coins to her own fresh address (key rotation / cold→warm)."""
    hdr("Self-Transfer")
    ensure_funded(ALICE, 0.3)
    addr_type = rand_addr_type()
    dest      = get_new_address(ALICE, addr_type)
    amt       = rand_btc(0.01, 0.2)
    if get_balance(ALICE) < amt + FEE_RESERVE * 2:
        ensure_funded(ALICE, amt + 0.5)
    txid = send_to_address(ALICE, dest, amt)
    maybe_mine()
    ok(f"Alice self → {addr_type}  {amt:.8f} BTC  TX={txid[:16]}…")
    return txid


def tx_utxo_split() -> str | None:
    """Alice fans one large UTXO out into 2-5 smaller outputs (own addresses)."""
    hdr("UTXO Split / Fan-out")
    ensure_funded(ALICE, 1.0)
    utxos = get_utxos(ALICE, 1)
    big   = [u for u in utxos if u["amount"] > 0.25]
    if not big:
        send_to_address("miner", get_new_address(ALICE, "bech32"), 1.5)
        mine_confirm(1)
        utxos = get_utxos(ALICE, 1)
        big   = [u for u in utxos if u["amount"] > 0.25]
    if not big:
        info("No large UTXO available for split, skipping")
        return None

    source  = random.choice(big)
    n_out   = random.randint(2, 5)
    budget  = source["amount"] - FEE_RESERVE * (n_out + 1)
    if budget <= 0:
        info("Budget after fee too small, skipping")
        return None

    # Give each output a random share of the budget
    shares  = [random.random() for _ in range(n_out)]
    total_s = sum(shares)
    outputs = []
    for share in shares:
        amt   = round(budget * share / total_s, 8)
        amt   = max(0.0001, amt)
        atype = random.choice(["bech32", "bech32m"])
        addr  = get_new_address(ALICE, atype)
        outputs.append({addr: amt})

    raw    = create_raw_tx(
        [{"txid": source["txid"], "vout": source["vout"]}],
        outputs
    )
    signed = sign_raw_tx(ALICE, raw)
    txid   = send_raw(signed["hex"])
    maybe_mine()
    ok(f"Split 1 UTXO → {n_out} outputs  TX={txid[:16]}…")
    return txid


def tx_receive_from_peer() -> str:
    """A peer spontaneously sends Alice funds — she just receives."""
    hdr("Receive from Peer")
    peer = rand_peer()
    ensure_funded(peer, 0.3)
    addr_type  = rand_addr_type()
    alice_addr = get_new_address(ALICE, addr_type)
    amt        = rand_btc(0.005, 0.12)
    txid       = send_to_address(peer, alice_addr, amt)
    maybe_mine()
    ok(f"{peer} → Alice ({addr_type})  {amt:.8f} BTC  TX={txid[:16]}…")
    return txid


def tx_exchange_withdrawal() -> str:
    """Exchange batch-withdraws to Alice and several other wallets at once."""
    hdr("Exchange Batch Withdrawal")
    ensure_funded("exchange", 3.0)
    recipients = [ALICE] + random.sample([w for w in SIDE_WALLETS if w != "exchange"],
                                         random.randint(2, 3))
    batch = {}
    for w in recipients:
        addr        = get_new_address(w, "bech32")   # exchanges use bech32
        batch[addr] = rand_btc(0.005, 0.06)
    txid = cli("sendmany", "", json.dumps(batch), wallet="exchange")
    maybe_mine()
    ok(f"Exchange batch → {len(recipients)} wallets incl. Alice  TX={txid[:16]}…")
    return txid


def tx_chain_hop() -> tuple[str, str]:
    """Alice pays Bob; Bob immediately forwards part to Carol (multi-hop)."""
    hdr("Chain Hop  Alice → Bob → Carol")
    ensure_funded(ALICE, 0.3)
    ensure_funded("bob",  0.2)
    hop_amt    = rand_btc(0.008, 0.06)
    bob_addr   = get_new_address("bob",   rand_addr_type())
    txid1      = send_to_address(ALICE, bob_addr, hop_amt)
    mine_confirm(1)                      # Bob needs confirmed UTXO to spend

    fwd_amt    = round(hop_amt * random.uniform(0.4, 0.85), 8)
    carol_addr = get_new_address("carol", rand_addr_type())
    txid2      = send_to_address("bob", carol_addr, fwd_amt)
    maybe_mine()
    ok(f"Alice→Bob TX={txid1[:16]}…  Bob→Carol TX={txid2[:16]}…")
    return txid1, txid2


def tx_mixed_type_spend() -> str | None:
    """Spend a P2WPKH UTXO and a P2TR UTXO together in one transaction."""
    hdr("Mixed Script-Type Spend (P2WPKH + P2TR)")
    wpkh_addr = get_new_address(ALICE, "bech32")
    tr_addr   = get_new_address(ALICE, "bech32m")
    fund_amt  = rand_btc(0.06, 0.2)
    send_to_address("miner", wpkh_addr, fund_amt)
    send_to_address("miner", tr_addr,   fund_amt)
    mine_confirm(1)

    utxos = get_utxos(ALICE, 1)
    wu = next((u for u in utxos if u.get("address") == wpkh_addr), None)
    tu = next((u for u in utxos if u.get("address") == tr_addr),   None)
    if not wu or not tu:
        info("Could not locate both script-type UTXOs, skipping")
        return None

    dest  = get_new_address(rand_peer(), rand_addr_type())
    total = wu["amount"] + tu["amount"] - FEE_RESERVE * 2
    raw   = create_raw_tx(
        [{"txid": wu["txid"], "vout": wu["vout"]},
         {"txid": tu["txid"], "vout": tu["vout"]}],
        [{dest: round(total, 8)}]
    )
    signed = sign_raw_tx(ALICE, raw)
    txid   = send_raw(signed["hex"])
    maybe_mine()
    ok(f"Mixed P2WPKH+P2TR spend  TX={txid[:16]}…")
    return txid


def tx_round_amount_payment() -> str:
    """Alice makes a suspiciously round-amount payment — normal consumer habit."""
    hdr("Round-Amount Payment")
    ensure_funded(ALICE, 0.5)
    peer = rand_peer()
    amt  = round_btc()
    if get_balance(ALICE) < amt + FEE_RESERVE * 2:
        ensure_funded(ALICE, amt + 0.5)
    dest = get_new_address(peer, rand_addr_type())
    txid = send_to_address(ALICE, dest, amt)
    maybe_mine()
    ok(f"Alice round {amt} BTC → {peer}  TX={txid[:16]}…")
    return txid


def tx_psbt_coinjoin() -> str | None:
    """Alice + Bob cooperate via PSBT (PayJoin / collaborative TX)."""
    hdr("PSBT Cooperative TX (PayJoin-like)")
    ensure_funded(ALICE, 0.5)
    ensure_funded("bob",  0.5)

    carol_dest = get_new_address("carol", rand_addr_type())
    alice_chg  = get_new_address(ALICE,  rand_addr_type())
    bob_chg    = get_new_address("bob",  rand_addr_type())

    alice_pay = rand_btc(0.01, 0.08)
    alice_ret = rand_btc(0.005, 0.02)
    bob_ret   = rand_btc(0.005, 0.02)

    outputs = [
        {carol_dest: alice_pay},
        {alice_chg:  alice_ret},
        {bob_chg:    bob_ret},
    ]
    try:
        psbt_res = create_funded_psbt(ALICE, [], outputs, {"fee_rate": 2})
        signed_a = process_psbt(ALICE, psbt_res["psbt"])
        signed_b = process_psbt("bob",  signed_a["psbt"])
        final    = finalize_psbt(signed_b["psbt"])
        if not final.get("complete"):
            info("PSBT incomplete, falling back to simple payment")
            return tx_simple_payment()
        txid = send_raw(final["hex"])
        maybe_mine()
        ok(f"Cooperative PSBT Alice+Bob  TX={txid[:16]}…")
        return txid
    except Exception as e:
        info(f"PSBT failed ({e}), falling back to simple payment")
        return tx_simple_payment()


def tx_cold_to_hot() -> str | None:
    """Sweep Taproot 'cold' address → P2WPKH 'hot' address (cold storage move)."""
    hdr("Cold→Hot  Taproot → P2WPKH")
    cold_addr = get_new_address(ALICE, "bech32m")
    fund_amt  = rand_btc(0.15, 0.6)
    send_to_address("miner", cold_addr, fund_amt)
    mine_confirm(1)

    utxos     = get_utxos(ALICE, 1)
    cold_utxo = next((u for u in utxos if u.get("address") == cold_addr), None)
    if not cold_utxo:
        info("Cold UTXO not found, skipping")
        return None

    hot_addr = get_new_address(ALICE, "bech32")
    net      = round(cold_utxo["amount"] - FEE_RESERVE, 8)
    raw      = create_raw_tx(
        [{"txid": cold_utxo["txid"], "vout": cold_utxo["vout"]}],
        [{hot_addr: net}]
    )
    signed = sign_raw_tx(ALICE, raw)
    txid   = send_raw(signed["hex"])
    maybe_mine()
    ok(f"Cold(P2TR)→Hot(P2WPKH)  {fund_amt:.8f} BTC  TX={txid[:16]}…")
    return txid


def tx_lightning_channel_like() -> str:
    """Fund a precise msat-aligned amount (simulates LN channel-open output)."""
    hdr("Lightning Channel-Open-Like")
    ensure_funded(ALICE, 0.5)
    # Real LN channel capacities are multiples of 1 000 sats
    cap_sats = random.choice([
        50_000, 100_000, 200_000, 250_000, 500_000,
        1_000_000, 2_000_000, 3_000_000, 5_000_000,
    ])
    cap_btc  = round(cap_sats / 1e8, 8)
    peer     = rand_peer()
    dest     = get_new_address(peer, "bech32")   # LN always opens P2WPKH/P2WSH
    if get_balance(ALICE) < cap_btc + FEE_RESERVE * 2:
        ensure_funded(ALICE, cap_btc + 0.5)
    txid = send_to_address(ALICE, dest, cap_btc)
    maybe_mine()
    ok(f"Channel-open-like {cap_sats:,} sats → {peer}  TX={txid[:16]}…")
    return txid


def tx_high_freq_small() -> list[str]:
    """Burst of rapid tiny payments — simulates a micro-payment merchant."""
    hdr("High-Frequency Small Payments")
    ensure_funded(ALICE, 0.5)
    n    = random.randint(3, 9)
    txids = []
    for _ in range(n):
        if get_balance(ALICE) < 0.001 + FEE_RESERVE:
            ensure_funded(ALICE, 0.5)
        peer  = rand_peer()
        dest  = get_new_address(peer, "bech32")
        amt   = rand_btc(0.0001, 0.003)
        txid  = send_to_address(ALICE, dest, amt)
        txids.append(txid)
        time.sleep(random.uniform(0.03, 0.12))   # mimic real timing jitter
    maybe_mine()
    ok(f"Alice fired {n} small payments  last={txids[-1][:16]}…")
    return txids


def tx_receive_multiple_senders() -> None:
    """Multiple wallets independently send Alice funds within the same block."""
    hdr("Receive from Multiple Senders")
    senders = random.sample(SIDE_WALLETS, random.randint(2, len(SIDE_WALLETS)))
    for sender in senders:
        ensure_funded(sender, 0.2)
        alice_addr = get_new_address(ALICE, rand_addr_type())
        amt        = rand_btc(0.005, 0.05)
        txid       = send_to_address(sender, alice_addr, amt)
        ok(f"  {sender} → Alice  {amt:.8f} BTC  TX={txid[:16]}…")
    maybe_mine()


def tx_legacy_address_receive() -> str:
    """A peer sends Alice funds via a legacy P2PKH address (old-school wallet)."""
    hdr("Legacy P2PKH Receive")
    peer = rand_peer()
    ensure_funded(peer, 0.3)
    legacy_addr = get_new_address(ALICE, "legacy")
    amt         = rand_btc(0.002, 0.05)
    txid        = send_to_address(peer, legacy_addr, amt)
    maybe_mine()
    ok(f"{peer} → Alice (legacy)  {amt:.8f} BTC  TX={txid[:16]}…")
    return txid


def tx_p2sh_wrapped_receive() -> str:
    """Receive into a P2SH-wrapped segwit address (older mobile wallets)."""
    hdr("P2SH-Wrapped Segwit Receive")
    peer = rand_peer()
    ensure_funded(peer, 0.3)
    p2sh_addr = get_new_address(ALICE, "p2sh-segwit")
    amt       = rand_btc(0.002, 0.06)
    txid      = send_to_address(peer, p2sh_addr, amt)
    maybe_mine()
    ok(f"{peer} → Alice (p2sh-segwit)  {amt:.8f} BTC  TX={txid[:16]}…")
    return txid


def tx_change_avoidance() -> str | None:
    """Alice finds an exact-match UTXO to pay without producing change output."""
    hdr("Change-Avoidance Payment (exact UTXO match)")
    ensure_funded(ALICE, 0.5)
    utxos = get_utxos(ALICE, 1)
    if not utxos:
        info("No UTXOs, skipping")
        return None
    utxo   = random.choice(utxos)
    fee    = FEE_RESERVE
    net    = round(utxo["amount"] - fee, 8)
    if net <= DUST_LIMIT:
        info("UTXO too small, skipping")
        return None
    peer   = rand_peer()
    dest   = get_new_address(peer, rand_addr_type())
    raw    = create_raw_tx(
        [{"txid": utxo["txid"], "vout": utxo["vout"]}],
        [{dest: net}]
    )
    signed = sign_raw_tx(ALICE, raw)
    txid   = send_raw(signed["hex"])
    maybe_mine()
    ok(f"Change-avoidance  {net:.8f} BTC → {peer}  TX={txid[:16]}…")
    return txid


def tx_risky_origin_receive() -> str:
    """Simulate receiving funds from the 'risky' wallet (taint scenario)."""
    hdr("Receive from Risky Wallet")
    ensure_funded("risky", 0.3)
    alice_addr = get_new_address(ALICE, rand_addr_type())
    amt        = rand_btc(0.003, 0.04)
    txid       = send_to_address("risky", alice_addr, amt)
    maybe_mine()
    ok(f"risky → Alice  {amt:.8f} BTC  TX={txid[:16]}…")
    return txid


def tx_address_reuse_receive() -> tuple[str, str]:
    """Two different peers send to the same Alice address (natural address-reuse)."""
    hdr("Natural Address Reuse (two inbound)")
    reused_addr = get_new_address(ALICE, random.choice(["bech32", "bech32m"]))
    peer_a, peer_b = random.sample(SIDE_WALLETS, 2)
    ensure_funded(peer_a, 0.2)
    ensure_funded(peer_b, 0.2)
    txid1 = send_to_address(peer_a, reused_addr, rand_btc(0.003, 0.03))
    txid2 = send_to_address(peer_b, reused_addr, rand_btc(0.003, 0.03))
    maybe_mine()
    ok(f"Two peers sent to same Alice addr  TX1={txid1[:16]}…  TX2={txid2[:16]}…")
    return txid1, txid2


# ─── Archetype registry (name, function, weight) ─────────────────────────────
ARCHETYPES: list[tuple[str, callable, float]] = [
    ("simple_payment",            tx_simple_payment,            3.5),
    ("receive_from_peer",         tx_receive_from_peer,         3.0),
    ("round_amount_payment",      tx_round_amount_payment,      2.5),
    ("self_transfer",             tx_self_transfer,             2.0),
    ("multi_output",              tx_multi_output,              2.0),
    ("high_freq_small",           tx_high_freq_small,           1.5),
    ("receive_multiple_senders",  tx_receive_multiple_senders,  1.5),
    ("exchange_withdrawal",       tx_exchange_withdrawal,       1.5),
    ("legacy_address_receive",    tx_legacy_address_receive,    1.5),
    ("p2sh_wrapped_receive",      tx_p2sh_wrapped_receive,      1.5),
    ("change_avoidance",          tx_change_avoidance,          1.5),
    ("consolidation",             tx_consolidation,             1.0),
    ("utxo_split",                tx_utxo_split,                1.0),
    ("chain_hop",                 tx_chain_hop,                 1.0),
    ("mixed_type_spend",          tx_mixed_type_spend,          1.0),
    ("cold_to_hot",               tx_cold_to_hot,               1.0),
    ("lightning_channel_like",    tx_lightning_channel_like,    1.0),
    ("address_reuse_receive",     tx_address_reuse_receive,     1.0),
    ("risky_origin_receive",      tx_risky_origin_receive,      0.5),
    ("psbt_coinjoin",             tx_psbt_coinjoin,             0.5),
]

_NAMES, _FNS, _WEIGHTS = zip(*ARCHETYPES)
_TOTAL_W = sum(_WEIGHTS)


def weighted_choice() -> tuple[str, callable]:
    r = random.uniform(0, _TOTAL_W)
    cum = 0.0
    for name, fn, w in zip(_NAMES, _FNS, _WEIGHTS):
        cum += w
        if r <= cum:
            return name, fn
    return _NAMES[-1], _FNS[-1]


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create n realistic varied Bitcoin transactions for Alice's wallet on regtest",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("n", type=int,
                        help="Number of transaction events to generate")
    parser.add_argument("--seed", type=int, default=None,
                        help="Fix RNG seed (for reproducible runs)")
    parser.add_argument("--mine-final", dest="mine_final",
                        action="store_true", default=True,
                        help="Mine a final confirming block after all TXs (default: on)")
    parser.add_argument("--no-mine-final", dest="mine_final",
                        action="store_false",
                        help="Skip the final confirming block")
    args = parser.parse_args()

    print(f"\n{B}{C}{'═'*70}{RST}")
    print(f"{B}{C}  create_random_transactions.py{RST}")
    print(f"{B}  Generating {args.n} realistic transaction events for Alice{RST}")
    print(f"{B}{C}{'═'*70}{RST}")

    if args.seed is not None:
        random.seed(args.seed)
        info(f"RNG seeded manually: {args.seed}")
    else:
        reseed()

    # ── Bootstrap: make sure every wallet has funds ──────────────────────────
    info("Bootstrapping wallet balances…")
    for w in ALL_WALLETS:
        ensure_funded(w, 0.3)
    mine_confirm(1)
    time.sleep(0.3)

    # ── Main loop ─────────────────────────────────────────────────────────────
    completed  = 0
    failed     = 0
    used_types: list[str] = []
    next_mine  = random.randint(3, 6)    # mine after this many events

    for i in range(args.n):
        name, fn = weighted_choice()
        print(f"\n{B}[{i+1}/{args.n}]{RST} {DIM}{name}{RST}")
        try:
            fn()
            completed += 1
            used_types.append(name)
        except Exception as exc:
            warn(f"'{name}' raised: {exc}")
            failed += 1
            # Fallback: guaranteed-safe simple payment
            try:
                tx_simple_payment()
                completed += 1
                used_types.append("simple_payment(fallback)")
            except Exception as exc2:
                warn(f"Fallback also failed: {exc2}")

        # Periodic mining to keep mempool manageable
        if (i + 1) >= next_mine:
            info("Periodic block mine to clear mempool…")
            mine_blocks(random.randint(1, 2))
            time.sleep(0.2)
            next_mine += random.randint(3, 6)

    # ── Final block ───────────────────────────────────────────────────────────
    if args.mine_final:
        info("Mining final confirming block…")
        mine_confirm(1)

    # ── Summary ───────────────────────────────────────────────────────────────
    type_counts = Counter(used_types)
    print(f"\n{B}{C}{'═'*70}{RST}")
    print(f"{B}  Summary{RST}")
    print(f"{B}{C}{'─'*70}{RST}")
    print(f"  Requested  : {args.n}")
    print(f"  Completed  : {G}{completed}{RST}")
    print(f"  Failed     : {R if failed else G}{failed}{RST}")
    print(f"  Chain height: {get_block_count()}")
    alice_bal = get_balance(ALICE)
    print(f"  Alice balance: {G}{alice_bal:.8f}{RST} BTC")
    print(f"\n  Transaction-type breakdown:")
    for t, cnt in type_counts.most_common():
        bar = "█" * cnt
        print(f"    {G}{cnt:3d}{RST}  {bar[:30]:<30}  {t}")
    print(f"{B}{C}{'═'*70}{RST}\n")


if __name__ == "__main__":
    main()
