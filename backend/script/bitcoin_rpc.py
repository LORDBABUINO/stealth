"""
bitcoin_rpc.py — Thin wrapper around bitcoin-cli for Python tests.
Uses subprocess calls to bitcoin-cli -regtest.
"""

import json
import subprocess
import time
import os

CLI = "bitcoin-cli"
SIGNET_ARGS = [CLI, "-regtest"]

def cli(*args, wallet=None):
    """Call bitcoin-cli -regtest [wallet] <args> and return parsed JSON or string."""
    cmd = list(SIGNET_ARGS)
    if wallet:
        cmd.append(f"-rpcwallet={wallet}")
    cmd.extend(str(a) for a in args)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"bitcoin-cli error: {result.stderr.strip()}\n  cmd: {' '.join(cmd)}")

    output = result.stdout.strip()
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return output


def mine_blocks(n=1):
    """Mine n blocks on regtest using generatetoaddress."""
    miner_addr = cli("getnewaddress", "", "bech32", wallet="miner")
    cli("generatetoaddress", n, miner_addr)
    return int(cli("getblockcount"))


def fund_wallet(wallet_name, amount=1.0, from_wallet="miner"):
    """Send `amount` BTC from `from_wallet` to a new address in `wallet_name`."""
    addr = cli("getnewaddress", "", "bech32", wallet=wallet_name)
    txid = cli("sendtoaddress", addr, f"{amount:.8f}", wallet=from_wallet)
    return txid, addr


def wait_for_mempool_empty(timeout=60):
    """Wait until mempool is empty (all txs mined)."""
    for _ in range(timeout * 2):
        info = cli("getmempoolinfo")
        if info["size"] == 0:
            return True
        time.sleep(0.5)
    return False


def get_tx(txid):
    """Get decoded transaction."""
    return cli("getrawtransaction", txid, "true")


def get_utxos(wallet_name, min_conf=0):
    """List unspent outputs for a wallet."""
    return cli("listunspent", min_conf, wallet=wallet_name)


def get_balance(wallet_name):
    """Get wallet balance."""
    return float(cli("getbalance", wallet=wallet_name))


def send_raw(hex_tx):
    """Broadcast a raw transaction."""
    return cli("sendrawtransaction", hex_tx)


def create_funded_psbt(wallet_name, inputs, outputs, options=None):
    """Create a funded PSBT."""
    args = ["walletcreatefundedpsbt", json.dumps(inputs), json.dumps(outputs), 0]
    if options:
        args.append(json.dumps(options))
    return cli(*args, wallet=wallet_name)


def process_psbt(wallet_name, psbt):
    """Sign a PSBT."""
    return cli("walletprocesspsbt", psbt, wallet=wallet_name)


def finalize_psbt(psbt):
    """Finalize a PSBT."""
    return cli("finalizepsbt", psbt)


def decode_psbt(psbt):
    """Decode a PSBT."""
    return cli("decodepsbt", psbt)


def create_raw_tx(inputs, outputs):
    """Create a raw transaction."""
    return cli("createrawtransaction", json.dumps(inputs), json.dumps(outputs))


def sign_raw_tx(wallet_name, hex_tx):
    """Sign a raw transaction."""
    return cli("signrawtransactionwithwallet", hex_tx, wallet=wallet_name)


def decode_raw_tx(hex_tx):
    """Decode a raw transaction."""
    return cli("decoderawtransaction", hex_tx)


def get_block_count():
    """Get current block height."""
    return int(cli("getblockcount"))


def get_new_address(wallet_name, addr_type="bech32"):
    """Get a new address."""
    return cli("getnewaddress", "", addr_type, wallet=wallet_name)


def send_to_address(wallet_name, address, amount):
    """Send BTC to an address."""
    return cli("sendtoaddress", address, f"{amount:.8f}", wallet=wallet_name)


if __name__ == "__main__":
    print("Testing RPC connection...")
    info = cli("getblockchaininfo")
    print(f"  Chain: {info['chain']}")
    print(f"  Blocks: {info['blocks']}")

    for w in ["miner", "alice", "bob", "carol", "exchange", "risky"]:
        try:
            bal = get_balance(w)
            print(f"  {w}: {bal} BTC")
        except Exception as e:
            print(f"  {w}: ERROR - {e}")
