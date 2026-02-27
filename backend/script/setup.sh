#!/usr/bin/env bash
# =============================================================================
# setup.sh — Bootstrap Bitcoin Core regtest for privacy vulnerability testing
# =============================================================================
# Reproduces the full environment:
#   • Writes ~/.bitcoin/bitcoin.conf (regtest, txindex, dustrelayfee, etc.)
#   • Stops any running bitcoind (both regtest and signet)
#   • Optionally wipes the regtest data dir (pass --fresh to start from block 0)
#   • Starts:  bitcoind -daemon -regtest
#   • Creates wallets: miner alice bob carol exchange risky
#   • Mines 110 blocks so coinbases mature and miner has spendable BTC
#
# Usage:
#   ./setup.sh           # keep existing chain state, reload wallets
#   ./setup.sh --fresh   # wipe regtest, start from genesis
# =============================================================================
set -euo pipefail

# ─── Colours ──────────────────────────────────────────────────────────────────
G="\033[92m"; Y="\033[93m"; R="\033[91m"; B="\033[1m"; C="\033[96m"; RST="\033[0m"
ok()   { echo -e "  ${G}✓${RST} $*"; }
info() { echo -e "  ${Y}ℹ${RST} $*"; }
err()  { echo -e "  ${R}✗${RST} $*"; exit 1; }

# ─── Config ───────────────────────────────────────────────────────────────────
BITCOIN_CONF="${HOME}/.bitcoin/bitcoin.conf"
REGTEST_DIR="${HOME}/.bitcoin/regtest"
WALLETS=(miner alice bob carol exchange risky)
INITIAL_BLOCKS=110          # must be >100 so coinbases mature
MINER_FUND_BTC=500          # approximate, depends on block subsidy

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
if bitcoin-cli -regtest stop 2>/dev/null; then
  ok "Stopped regtest bitcoind"
  sleep 2
else
  info "No regtest bitcoind running (or already stopped)"
fi

# Try to stop signet instance (port 38332) if one is running
if bitcoin-cli -signet stop 2>/dev/null; then
  ok "Stopped signet bitcoind"
  sleep 2
else
  info "No signet bitcoind running"
fi

# Hard-kill any remaining bitcoind processes
if pgrep -x bitcoind > /dev/null 2>&1; then
  info "Hard-killing remaining bitcoind processes …"
  pkill -x bitcoind || true
  sleep 2
fi

# ─── 2. Write bitcoin.conf ────────────────────────────────────────────────────
echo ""
echo -e "${B}Step 2: Write ${BITCOIN_CONF}${RST}"
mkdir -p "$(dirname "$BITCOIN_CONF")"

cat > "$BITCOIN_CONF" << 'EOF'
# Bitcoin Core configuration
# Network: regtest (local testing only)
regtest=1
txindex=1

[regtest]
# Fee policy — needed so wallets can broadcast without estimatefee data
fallbackfee=0.00010

# Allow outputs as small as 1 sat (needed for dust-attack reproduction)
dustrelayfee=0.00000001

# Accept non-standard transactions (needed for some test scenarios)
acceptnonstdtxn=1

# Enable RPC server
server=1
EOF

ok "Wrote bitcoin.conf"

# ─── 3. Optionally wipe regtest chain ─────────────────────────────────────────
if [[ $FRESH -eq 1 ]]; then
  echo ""
  echo -e "${B}Step 3: Wipe regtest data dir${RST}"
  rm -rf "$REGTEST_DIR"
  ok "Wiped ${REGTEST_DIR}"
else
  echo ""
  info "Step 3: Keeping existing regtest chain (use --fresh to wipe)"
fi

# ─── 4. Start bitcoind ────────────────────────────────────────────────────────
echo ""
echo -e "${B}Step 4: Start bitcoind -daemon -regtest${RST}"
bitcoind -daemon -regtest
ok "bitcoind launched"

# Wait for RPC to become ready
echo -n "  … waiting for RPC"
for i in $(seq 1 30); do
  sleep 1
  echo -n "."
  if bitcoin-cli -regtest getblockchaininfo > /dev/null 2>&1; then
    echo ""
    ok "RPC ready after ${i}s"
    break
  fi
  if [[ $i -eq 30 ]]; then
    echo ""
    err "bitcoind did not respond within 30s — check logs at ${REGTEST_DIR}/debug.log"
  fi
done

BLOCKS=$(bitcoin-cli -regtest getblockcount)
info "Chain height: ${BLOCKS} blocks"

# ─── 5. Create / load wallets ─────────────────────────────────────────────────
echo ""
echo -e "${B}Step 5: Create wallets${RST}"
for w in "${WALLETS[@]}"; do
  if bitcoin-cli -regtest createwallet "$w" 2>/dev/null | grep -q '"name"'; then
    ok "Created wallet: ${w}"
  else
    # Wallet DB already exists on disk — just load it
    if bitcoin-cli -regtest loadwallet "$w" 2>/dev/null | grep -q '"name"'; then
      ok "Loaded existing wallet: ${w}"
    else
      # Already loaded (returned error -35)
      info "Wallet already loaded: ${w}"
    fi
  fi
done

# ─── 6. Mine initial blocks (only if fresh or chain has <110 blocks) ──────────
echo ""
echo -e "${B}Step 6: Mine initial blocks${RST}"
BLOCKS=$(bitcoin-cli -regtest getblockcount)

if [[ $BLOCKS -lt $INITIAL_BLOCKS ]]; then
  NEED=$(( INITIAL_BLOCKS - BLOCKS ))
  info "At block ${BLOCKS}, need ${NEED} more to reach ${INITIAL_BLOCKS}"
  MINER_ADDR=$(bitcoin-cli -regtest -rpcwallet=miner getnewaddress "" bech32)
  bitcoin-cli -regtest generatetoaddress "$NEED" "$MINER_ADDR" > /dev/null
  BLOCKS=$(bitcoin-cli -regtest getblockcount)
  ok "Mined to block ${BLOCKS}"
else
  ok "Already at block ${BLOCKS} — no mining needed"
fi

MINER_BAL=$(bitcoin-cli -regtest -rpcwallet=miner getbalance)
ok "Miner balance: ${MINER_BAL} BTC"

# ─── 7. Summary ───────────────────────────────────────────────────────────────
echo ""
echo -e "${B}${C}══════════════════════════════════════════════════════════${RST}"
echo -e "${B}  Setup complete!${RST}"
echo -e "${B}${C}══════════════════════════════════════════════════════════${RST}"
echo -e "  Chain:   ${G}regtest${RST}"
echo -e "  Blocks:  ${G}$(bitcoin-cli -regtest getblockcount)${RST}"
echo -e "  Wallets: ${G}${WALLETS[*]}${RST}"
echo ""
echo -e "  Next steps:"
echo -e "    python3 reproduce.py     # create 12 vulnerability scenarios"
echo -e "    python3 detect.py --wallet alice \\"
echo -e "            --known-risky-wallets risky \\"
echo -e "            --known-exchange-wallets exchange"
echo -e "    python3 verify.py --fresh  # full automated proof"
echo ""
