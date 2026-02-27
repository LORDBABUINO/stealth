#!/usr/bin/env bash
# =============================================================================
# setup_signet.sh — Bootstrap a private custom Signet for vulnerability testing
# =============================================================================
set -euo pipefail

DATADIR="$HOME/.bitcoin"
SIGNET_DIR="$DATADIR/signet"
MINER="/home/renato/Desktop/bitcoin/bitcoin/contrib/signet/miner"
GRIND="bitcoin-util grind"
CLI="bitcoin-cli"

echo "============================================"
echo "  STEP 0: Cleanup previous state"
echo "============================================"
bitcoin-cli stop 2>/dev/null || true
bitcoin-cli -signet stop 2>/dev/null || true
sleep 3

# Remove old signet data but keep blocks/chainstate for mainnet untouched
rm -rf "$SIGNET_DIR"
rm -f "$DATADIR/bitcoin.conf"

echo "============================================"
echo "  STEP 1: Generate Signet challenge key"
echo "============================================"
rm -f "$DATADIR/bitcoin.conf"

# Generate key pair using Python + bitcoin-cli (no wallet needed)
KEYPAIR=$(python3 -c "
import hashlib, os, struct

# Generate a random 32-byte private key
privkey_bytes = os.urandom(32)

# secp256k1 parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def modinv(a, m):
    g, x, _ = extended_gcd(a % m, m)
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        lam = (3 * x1 * x1 + A) * modinv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * modinv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mult(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

privkey_int = int.from_bytes(privkey_bytes, 'big') % N
if privkey_int == 0:
    privkey_int = 1
privkey_bytes = privkey_int.to_bytes(32, 'big')

pub = scalar_mult(privkey_int, (Gx, Gy))
pubkey_bytes = b'\x02' + pub[0].to_bytes(32, 'big') if pub[1] % 2 == 0 else b'\x03' + pub[0].to_bytes(32, 'big')

# WIF encode (testnet/signet = 0xEF prefix)
wif_payload = b'\xef' + privkey_bytes + b'\x01'  # compressed
checksum = hashlib.sha256(hashlib.sha256(wif_payload).digest()).digest()[:4]
import base64
# base58 encoding
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
num = int.from_bytes(wif_payload + checksum, 'big')
b58 = ''
while num > 0:
    num, rem = divmod(num, 58)
    b58 = ALPHABET[rem] + b58
for byte in (wif_payload + checksum):
    if byte == 0:
        b58 = '1' + b58
    else:
        break

print(f'{b58} {pubkey_bytes.hex()}')
")

PRIVKEY=$(echo "$KEYPAIR" | awk '{print $1}')
PUBKEY=$(echo "$KEYPAIR" | awk '{print $2}')

# Build 1-of-1 multisig signet challenge: OP_1 <33-byte pubkey> OP_1 OP_CHECKMULTISIG
SIGNETCHALLENGE="5121${PUBKEY}51ae"

echo ""
echo ">>> Private key (WIF):  $PRIVKEY"
echo ">>> Public key:         $PUBKEY"
echo ">>> Signet challenge:   $SIGNETCHALLENGE"
echo ""

# Save keys for later use
cat > "$DATADIR/signet_keys.env" <<EOF
PRIVKEY=$PRIVKEY
PUBKEY=$PUBKEY
SIGNETCHALLENGE=$SIGNETCHALLENGE
EOF

echo "============================================"
echo "  STEP 2: Write bitcoin.conf for custom Signet"
echo "============================================"
rm -rf "$DATADIR/regtest"
rm -f "$DATADIR/bitcoin.conf"

cat > "$DATADIR/bitcoin.conf" <<EOF
signet=1
[signet]
daemon=1
server=1
txindex=1
signetchallenge=$SIGNETCHALLENGE
acceptnonstdtxn=1
fallbackfee=0.00010
mintxfee=0.00001
dustrelayfee=0.00000001
minrelaytxfee=0.00001
EOF

echo "Config written to $DATADIR/bitcoin.conf"
cat "$DATADIR/bitcoin.conf"

echo ""
echo "============================================"
echo "  STEP 3: Start custom Signet node"
echo "============================================"
bitcoind
sleep 3

# Wait for RPC
for i in $(seq 1 30); do
    if $CLI -signet getblockchaininfo >/dev/null 2>&1; then
        echo "  Signet node ready"
        break
    fi
    echo "  Waiting for node to start... ($i)"
    sleep 2
done

echo "Node info:"
$CLI -signet getblockchaininfo | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'  Chain:  {d[\"chain\"]}')
print(f'  Blocks: {d[\"blocks\"]}')
"

echo ""
echo "============================================"
echo "  STEP 4: Create wallets"
echo "============================================"
WALLETS=("miner" "alice" "bob" "carol" "exchange" "risky")

for w in "${WALLETS[@]}"; do
    echo -n "  Creating wallet '$w'... "
    $CLI -signet -named createwallet wallet_name="$w" descriptors=true 2>&1 | grep -o '"name": "[^"]*"' || echo "(exists or loaded)"
done

echo "  Loaded wallets:"
$CLI -signet listwallets

echo ""
echo "============================================"
echo "  STEP 5: Import Signet challenge key into miner wallet"
echo "============================================"
# For descriptor wallets, we need to import with the PRIVATE key in the descriptor
# Import both combo (for general key use) and multi(1,...) (for signet challenge signing)
COMBO_INFO=$($CLI -signet getdescriptorinfo "combo($PRIVKEY)")
COMBO_CHECKSUM=$(echo "$COMBO_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin)['checksum'])")
COMBO_DESC="combo($PRIVKEY)#$COMBO_CHECKSUM"

MULTI_INFO=$($CLI -signet getdescriptorinfo "multi(1,$PRIVKEY)")
MULTI_CHECKSUM=$(echo "$MULTI_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin)['checksum'])")
MULTI_DESC="multi(1,$PRIVKEY)#$MULTI_CHECKSUM"

echo "  Importing combo and multi(1,...) descriptors..."

$CLI -signet -rpcwallet=miner importdescriptors "[{\"desc\": \"$COMBO_DESC\", \"timestamp\": \"now\"}, {\"desc\": \"$MULTI_DESC\", \"timestamp\": \"now\"}]" | python3 -c "
import sys, json
r = json.load(sys.stdin)
for i, item in enumerate(r):
    s = item.get('success', False)
    print(f'  Import {i+1} success: {s}')
    if not s:
        print(f'  Error: {item.get(\"error\", \"unknown\")}')
"

echo ""
echo "============================================"
echo "  STEP 6: Mine initial blocks (110 blocks)"
echo "============================================"

MINER_ADDR=$($CLI -signet -rpcwallet=miner getnewaddress "" bech32)
echo "  Mining to: $MINER_ADDR"

echo "  Mining 110 blocks (this may take a minute)..."
BLOCK_TIME=$(date +%s)
for i in $(seq 1 110); do
    BLOCK_TIME=$((BLOCK_TIME + 1))
    $MINER \
      --cli="$CLI -rpcwallet=miner" \
      generate \
      --grind-cmd="$GRIND" \
      --address="$MINER_ADDR" \
      --min-nbits \
      --set-block-time="$BLOCK_TIME" \
      2>&1 >/dev/null
    if [ $((i % 10)) -eq 0 ]; then
        echo "    Mined block $i / 110"
    fi
done

HEIGHT=$($CLI -signet getblockcount)
echo "  Block height: $HEIGHT"

echo ""
echo "============================================"
echo "  STEP 7: Fund wallets"
echo "============================================"

MINER_BAL=$($CLI -signet -rpcwallet=miner getbalance)
echo "  Miner balance: $MINER_BAL BTC"

# Fund each wallet
for w in alice bob carol exchange risky; do
    ADDR=$($CLI -signet -rpcwallet=$w getnewaddress "" bech32)
    TXID=$($CLI -signet -rpcwallet=miner sendtoaddress "$ADDR" 10.0)
    echo "  Funded $w with 10 BTC (txid: ${TXID:0:16}...)"
done

echo "  Mining 6 more blocks to confirm funding..."
BLOCK_TIME=$(($(date +%s) + 200))
for i in $(seq 1 6); do
    BLOCK_TIME=$((BLOCK_TIME + 1))
    $MINER \
      --cli="$CLI -rpcwallet=miner" \
      generate \
      --grind-cmd="$GRIND" \
      --address="$MINER_ADDR" \
      --min-nbits \
      --set-block-time="$BLOCK_TIME" \
      2>&1 >/dev/null
done

echo ""
echo "  Final balances:"
for w in miner alice bob carol exchange risky; do
    BAL=$($CLI -signet -rpcwallet=$w getbalance)
    echo "    $w: $BAL BTC"
done

echo ""
echo "============================================"
echo "  SETUP COMPLETE"
echo "============================================"
echo ""
echo "  Custom Signet is running with:"
echo "    - 6 wallets (miner, alice, bob, carol, exchange, risky)"
echo "    - Each funded with 10 BTC"
echo "    - txindex=1 for historical lookups"
echo "    - acceptnonstdtxn=1 for dust experiments"
echo ""
echo "  Signet keys saved to: $DATADIR/signet_keys.env"
echo "  To mine more blocks, use: ./mine_blocks.sh <N>"
echo ""

# Save mining address for later mining
echo "MINER_ADDR=$MINER_ADDR" >> "$DATADIR/signet_keys.env"
