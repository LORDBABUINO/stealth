#!/usr/bin/env bash
# run_all.sh — Setup custom signet and run all 12 vulnerability tests
set -euo pipefail

cd "$(dirname "$0")"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Bitcoin Privacy Vulnerability Suite — Full Run             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Setup signet (if not already running)
if bitcoin-cli -signet getblockchaininfo &>/dev/null; then
    HEIGHT=$(bitcoin-cli -signet getblockcount)
    echo "✓ Custom Signet already running at block $HEIGHT"
    
    # Check wallets exist
    WALLETS=$(bitcoin-cli -signet listwallets 2>/dev/null)
    if echo "$WALLETS" | grep -q "alice"; then
        echo "✓ Wallets already created"
    else
        echo "⚠ Wallets not found. Running setup..."
        bash setup_signet.sh
    fi
else
    echo "Starting custom Signet setup..."
    bash setup_signet.sh
fi

echo ""
echo "Running vulnerability tests..."
echo ""

# Step 2: Run all tests
python3 test_vulnerabilities.py "$@"
