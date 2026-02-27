#!/usr/bin/env python3
"""
verify.py
=========
End-to-end proof that detect.py catches every vulnerability that reproduce.py
creates — on a REGTEST chain.

Steps:
  1. Wipe & restart regtest
  2. Create wallets, fund miner
  3. Run reproduce.py (create all 12 vulnerability scenarios)
  4. Run detect.py --wallet alice (capture output)
  5. Parse output and assert every detector (1–12) produced ≥1 finding
  6. Print a 12-row proof table

Usage:
    python3 verify.py
"""

import subprocess
import sys
import os
import re
import time

DIR = os.path.dirname(os.path.abspath(__file__))
WALLETS = ["miner", "alice", "bob", "carol", "exchange", "risky"]

G = "\033[92m"
R = "\033[91m"
B = "\033[1m"
C = "\033[96m"
Y = "\033[93m"
RST = "\033[0m"


def run(cmd, check=True, timeout=300):
    """Run a shell command, return stdout."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode != 0:
        print(f"  {R}FAIL:{RST} {cmd}")
        print(f"  stderr: {result.stderr.strip()}")
        sys.exit(1)
    return result.stdout.strip()


def btc(cmd):
    return run(f"bitcoin-cli -regtest {cmd}")


def btcw(wallet, cmd):
    return run(f"bitcoin-cli -regtest -rpcwallet={wallet} {cmd}")


def banner(msg):
    print(f"\n{B}{C}{'═' * 70}{RST}")
    print(f"{B}{C}  {msg}{RST}")
    print(f"{B}{C}{'═' * 70}{RST}")


# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Fresh regtest
# ─────────────────────────────────────────────────────────────────────────────
def setup_regtest():
    banner("Step 1: Fresh regtest chain")
    # Stop if running
    run("bitcoin-cli -regtest stop 2>/dev/null || true", check=False)
    time.sleep(2)

    # Wipe
    run("rm -rf ~/.bitcoin/regtest")
    print("  ✓ Wiped regtest datadir")

    # Ensure bitcoin.conf exists with regtest settings
    conf = os.path.expanduser("~/.bitcoin/bitcoin.conf")
    with open(conf, "w") as f:
        f.write("regtest=1\ntxindex=1\n\n[regtest]\n"
                "fallbackfee=0.00010\ndustrelayfee=0.00000001\n"
                "acceptnonstdtxn=1\nserver=1\n")
    print("  ✓ Wrote bitcoin.conf")

    # Start
    run("bitcoind -regtest -daemon")
    # Wait for RPC to become ready
    print("  … waiting for bitcoind RPC …", end="", flush=True)
    for i in range(30):
        time.sleep(1)
        res = subprocess.run("bitcoin-cli -regtest getblockchaininfo",
                             shell=True, capture_output=True, text=True, timeout=10)
        if res.returncode == 0:
            print(f" ready after {i+1}s")
            break
    else:
        print(f"\n  {R}ERROR: bitcoind didn't start after 30s{RST}")
        sys.exit(1)
    print("  ✓ bitcoind started")

    # Create wallets
    for w in WALLETS:
        btc(f'createwallet "{w}"')
    print(f"  ✓ Created wallets: {', '.join(WALLETS)}")

    # Mine 110 blocks to get mature coinbases
    addr = btcw("miner", 'getnewaddress "" bech32')
    btc(f"generatetoaddress 110 {addr}")
    balance = btcw("miner", "getbalance")
    print(f"  ✓ Mined 110 blocks — miner balance: {balance} BTC")


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Reproduce
# ─────────────────────────────────────────────────────────────────────────────
def run_reproduce():
    banner("Step 2: Run reproduce.py (create 12 vulnerability scenarios)")
    result = subprocess.run(
        [sys.executable, os.path.join(DIR, "reproduce.py")],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        print(f"  {R}reproduce.py FAILED:{RST}")
        print(result.stderr)
        sys.exit(1)

    # Count successes
    successes = result.stdout.count("✓")
    print(f"  ✓ reproduce.py completed — {successes} scenario(s) created")
    # Print abbreviated output
    for line in result.stdout.split("\n"):
        if "✓" in line or "REPRODUCE" in line:
            print(f"    {line.strip()}")
    return result.stdout


# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Detect
# ─────────────────────────────────────────────────────────────────────────────
def run_detect():
    banner("Step 3: Run detect.py --wallet alice")
    result = subprocess.run(
        [sys.executable, os.path.join(DIR, "detect.py"),
         "--wallet", "alice",
         "--known-risky-wallets", "risky",
         "--known-exchange-wallets", "exchange"],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        print(f"  {R}detect.py FAILED:{RST}")
        print(result.stderr)
        sys.exit(1)
    print(f"  ✓ detect.py completed")
    return result.stdout


# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Parse & verify
# ─────────────────────────────────────────────────────────────────────────────
DETECTORS = {
    1:  ("Address Reuse",               r"1 · Address Reuse"),
    2:  ("CIOH",                        r"2 · Common Input Ownership"),
    3:  ("Dust UTXO Detection",         r"3 · Dust UTXO Detection"),
    4:  ("Dust Spent with Normal",      r"4 · Dust Spent with Normal"),
    5:  ("Change Output Detection",     r"5 · Probable Change Output"),
    6:  ("Consolidation Origin",        r"6 · UTXOs from Prior Consolidation"),
    7:  ("Script Type Mixing",          r"7 · Script Type Mixing"),
    8:  ("Cluster Merge",               r"8 · Cluster Merge"),
    9:  ("UTXO Age / Lookback",         r"9 · UTXO Age"),
    10: ("Exchange Origin",             r"10 · Probable Exchange Origin"),
    11: ("Tainted UTXOs",               r"11 · Tainted UTXOs"),
    12: ("Behavioral Fingerprint",      r"12 · Behavioral Fingerprint"),
}


def parse_and_verify(detect_output):
    banner("Step 4: Verification — does detect catch every reproduced vulnerability?")

    # Split output into sections per detector
    lines = detect_output.split("\n")
    results = {}
    current_id = None

    for line in lines:
        # Check if this line starts a detector section
        for did, (name, pattern) in DETECTORS.items():
            if pattern in line:
                current_id = did
                results[did] = {"findings": 0, "warnings": 0, "lines": []}
                break
        # Count findings/warnings within current section
        if current_id is not None:
            if "FINDING" in line:
                results[current_id]["findings"] += 1
            if "WARNING" in line:
                results[current_id]["warnings"] += 1
            results[current_id]["lines"].append(line)

    # Also parse the summary line
    total_findings = 0
    total_warnings = 0
    m = re.search(r"Findings:\s+(\d+)", detect_output)
    if m:
        total_findings = int(m.group(1))
    m = re.search(r"Warnings:\s+(\d+)", detect_output)
    if m:
        total_warnings = int(m.group(1))

    # ── Print proof table ──
    print()
    print(f"  {'#':>3}  {'Detector':<30}  {'Findings':>8}  {'Warnings':>8}  {'Status'}")
    print(f"  {'─'*3}  {'─'*30}  {'─'*8}  {'─'*8}  {'─'*8}")

    all_pass = True
    for did in sorted(DETECTORS.keys()):
        name = DETECTORS[did][0]
        r = results.get(did, {"findings": 0, "warnings": 0})
        f_count = r["findings"]
        w_count = r["warnings"]
        detected = f_count > 0 or w_count > 0
        status = f"{G}PASS ✓{RST}" if detected else f"{R}FAIL ✗{RST}"
        if not detected:
            all_pass = False
        print(f"  {did:>3}  {name:<30}  {f_count:>8}  {w_count:>8}  {status}")

    print(f"  {'─'*3}  {'─'*30}  {'─'*8}  {'─'*8}  {'─'*8}")
    print(f"  {'':>3}  {'TOTAL':<30}  {total_findings:>8}  {total_warnings:>8}")
    print()

    if all_pass:
        print(f"  {G}{B}═══ ALL 12 DETECTORS FIRED — PROOF COMPLETE ═══{RST}")
        print(f"  {G}Every reproduced vulnerability was caught by detect.py on regtest.{RST}")
    else:
        failed = [did for did in DETECTORS if results.get(did, {}).get("findings", 0) == 0
                  and results.get(did, {}).get("warnings", 0) == 0]
        print(f"  {R}{B}═══ FAILURE — {len(failed)} detector(s) did not fire ═══{RST}")
        for did in failed:
            print(f"  {R}  Detector {did}: {DETECTORS[did][0]}{RST}")

    return all_pass


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print(f"\n{B}{'═' * 70}{RST}")
    print(f"{B}{C}  VERIFY: reproduce → detect end-to-end proof on REGTEST{RST}")
    print(f"{B}{'═' * 70}{RST}")

    setup_regtest()
    run_reproduce()
    detect_output = run_detect()
    passed = parse_and_verify(detect_output)

    print()
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
