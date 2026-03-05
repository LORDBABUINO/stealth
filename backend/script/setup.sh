#!/usr/bin/env bash
# =============================================================================
# setup.sh — Bootstrap Bitcoin Core regtest for privacy vulnerability testing
# =============================================================================
# Reproduces the full environment:
#   • Stops any running bitcoind (both regtest and signet)
#   • Optionally wipes the regtest data dir (pass --fresh to start from block 0)
#   • Starts bitcoind with all config passed via CLI flags (no bitcoin.conf edits)
#   • Creates wallets: miner alice bob carol exchange risky
#   • Mines 110 blocks so coinbases mature and miner has spendable BTC
#
# Usage:
#   ./setup.sh           # keep existing chain state, reload wallets
#   ./setup.sh --fresh   # wipe regtest, start from genesis
# =============================================================================
set -euo pipefail

# ─── Config ───────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATADIR="${SCRIPT_DIR}/bitcoin-data"
REGTEST_DIR="${DATADIR}/regtest"
WALLETS=(miner alice bob carol exchange risky)
INITIAL_BLOCKS=110          # must be >100 so coinbases mature

# ─── Helpers ──────────────────────────────────────────────────────────────────
G="\033[92m"; Y="\033[93m"; R="\033[91m"; B="\033[1m"; C="\033[96m"; RST="\033[0m"
ok()   { echo -e "  ${G}✓${RST} $*"; }
info() { echo -e "  ${Y}ℹ${RST} $*"; }
err()  { echo -e "  ${R}✗${RST} $*"; exit 1; }
bcli() { bitcoin-cli -datadir="$DATADIR" -regtest "$@"; }

# ─── Parse args ───────────────────────────────────────────────────────────────
FRESH=0
for arg in "$@"; do
  [[ "$arg" == "--fresh" ]] && FRESH=1
done

echo ""
echo -e "${B}${C}══════════════════════════════════════════════════════════${RST}"
echo -e "${B}${C}  Bitcoin Regtest Setup — privacy vulnerability harness${RST}"
echo -e "${B}${C}══════════════════════════════════════════════════════════${RST}"
[[ $FRESH -eq 1 ]] && echo -e "  ${Y}Mode: FRESH — regtest chain will be wiped${RST}"

# ─── 1. Stop running daemons ──────────────────────────────────────────────────
echo ""
echo -e "${B}Step 1: Stop any running bitcoind${RST}"

# Try to stop regtest instance (port 18443)
if bcli stop 2>/dev/null; then
  ok "Stopped regtest bitcoind"
  sleep 2
else
  info "No regtest bitcoind running (or already stopped)"
fi

# Hard-kill any remaining bitcoind processes
if pgrep -x bitcoind > /dev/null 2>&1; then
  info "Hard-killing remaining bitcoind processes …"
  pkill -x bitcoind || true
  sleep 2
fi

# ─── 2. Optionally wipe regtest chain ────────────────────────────────────────
if [[ $FRESH -eq 1 ]]; then
  echo ""
  echo -e "${B}Step 2: Wipe regtest data dir${RST}"
  rm -rf "$REGTEST_DIR"
  ok "Wiped ${REGTEST_DIR}"
else
  echo ""
  info "Step 2: Keeping existing regtest chain (use --fresh to wipe)"
fi

# ─── 3. Start bitcoind ────────────────────────────────────────────────────────
echo ""
echo -e "${B}Step 3: Start bitcoind${RST}"
mkdir -p "$DATADIR"
bitcoind -daemon \
  -datadir="$DATADIR" \
  -regtest \
  -txindex=1 \
  -server=1 \
  -fallbackfee=0.00010 \
  -dustrelayfee=0.00000001 \
  -acceptnonstdtxn=1
ok "bitcoind launched"

# Wait for RPC to become ready
echo -n "  … waiting for RPC"
for i in $(seq 1 30); do
  sleep 1
  echo -n "."
  if bcli getblockchaininfo > /dev/null 2>&1; then
    echo ""
    ok "RPC ready after ${i}s"
    break
  fi
  if [[ $i -eq 30 ]]; then
    echo ""
    err "bitcoind did not respond within 30s — check logs at ${REGTEST_DIR}/debug.log"
  fi
done

BLOCKS=$(bcli getblockcount)
info "Chain height: ${BLOCKS} blocks"

# ─── 4. Create / load wallets ─────────────────────────────────────────────────
echo ""
echo -e "${B}Step 4: Create wallets${RST}"
for w in "${WALLETS[@]}"; do
  if bcli createwallet "$w" 2>/dev/null | grep -q '"name"'; then
    ok "Created wallet: ${w}"
  else
    # Wallet DB already exists on disk — just load it
    if bcli loadwallet "$w" 2>/dev/null | grep -q '"name"'; then
      ok "Loaded existing wallet: ${w}"
    else
      # Already loaded (returned error -35)
      info "Wallet already loaded: ${w}"
    fi
  fi
done

# ─── 5. Mine initial blocks (only if fresh or chain has <110 blocks) ──────────
echo ""
echo -e "${B}Step 5: Mine initial blocks${RST}"
BLOCKS=$(bcli getblockcount)

if [[ $BLOCKS -lt $INITIAL_BLOCKS ]]; then
  NEED=$(( INITIAL_BLOCKS - BLOCKS ))
  info "At block ${BLOCKS}, need ${NEED} more to reach ${INITIAL_BLOCKS}"
  MINER_ADDR=$(bcli -rpcwallet=miner getnewaddress "" bech32)
  bcli generatetoaddress "$NEED" "$MINER_ADDR" > /dev/null
  BLOCKS=$(bcli getblockcount)
  ok "Mined to block ${BLOCKS}"
else
  ok "Already at block ${BLOCKS} — no mining needed"
fi

MINER_BAL=$(bcli -rpcwallet=miner getbalance)
ok "Miner balance: ${MINER_BAL} BTC"

# ─── 6. Summary ───────────────────────────────────────────────────────────────
echo ""
echo -e "${B}${C}══════════════════════════════════════════════════════════${RST}"
echo -e "${B}  Setup complete!${RST}"
echo -e "${B}${C}══════════════════════════════════════════════════════════${RST}"
echo -e "  Chain:   ${G}regtest${RST}"
echo -e "  Blocks:  ${G}$(bcli getblockcount)${RST}"
echo -e "  Wallets: ${G}${WALLETS[*]}${RST}"
echo ""
echo -e "  Next steps:"
echo -e "    python3 reproduce.py     # create 12 vulnerability scenarios"
echo -e "    python3 detect.py --wallet alice \\"
echo -e "            --known-risky-wallets risky \\"
echo -e "            --known-exchange-wallets exchange"
echo ""
