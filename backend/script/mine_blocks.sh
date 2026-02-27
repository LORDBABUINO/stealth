#!/usr/bin/env bash
# mine_blocks.sh — Mine N blocks on the custom Signet
set -euo pipefail

N="${1:-1}"
source "$HOME/.bitcoin/signet_keys.env"

MINER="/home/renato/Desktop/bitcoin/bitcoin/contrib/signet/miner"
GRIND="bitcoin-util grind"
CLI="bitcoin-cli -signet"

CURRENT=$($CLI getblockcount)
TARGET=$((CURRENT + N))
echo "Mining $N blocks (from $CURRENT to $TARGET)..."

BLOCK_TIME=$(date +%s)
for i in $(seq 1 $N); do
    BLOCK_TIME=$((BLOCK_TIME + 1))
    $MINER \
      --cli="bitcoin-cli -rpcwallet=miner" \
      generate \
      --grind-cmd="$GRIND" \
      --address="$MINER_ADDR" \
      --min-nbits \
      --set-block-time="$BLOCK_TIME" \
      2>&1 >/dev/null
done
echo "Done. Block height: $($CLI getblockcount)"
