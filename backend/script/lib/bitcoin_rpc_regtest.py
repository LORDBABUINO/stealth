"""
bitcoin_rpc.py — Thin wrapper around bitcoin-cli for Python tests.
Connection settings are read from config.ini in the same directory.
"""

import json
import subprocess
import time
import os
import configparser

# ── Load config ──────────────────────────────────────────────────────────────

def _load_config():
    cfg = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
    cfg.read(config_path)
    return cfg["bitcoin"] if "bitcoin" in cfg else {}

def _build_base_args(section):
    cli_bin = section.get("cli", "bitcoin-cli")
    network = section.get("network", "regtest").strip().lower()

    args = [cli_bin]

    network_flags = {
        "regtest": "-regtest",
        "testnet": "-testnet",
        "signet":  "-signet",
    }
    if network in network_flags:
        args.append(network_flags[network])

    for key, flag in [("rpchost", "-rpcconnect"), ("rpcport", "-rpcport"),
                      ("rpcuser", "-rpcuser"), ("rpcpassword", "-rpcpassword")]:
        value = section.get(key, "").strip()
        if value:
            args.append(f"{flag}={value}")

    return args

_cfg = _load_config()
_BASE_ARGS = _build_base_args(_cfg)

# Keep these for any scripts that might reference them directly
CLI = _cfg.get("cli", "bitcoin-cli")
SIGNET_ARGS = _BASE_ARGS

# def cli(*args, wallet=None):
#     """Call bitcoin-cli [network] [wallet] <args> and return parsed JSON or string."""
#     cmd = list(_BASE_ARGS)



from lib.clis import  cli_regtest
def cli(*args, wallet=None):
    return cli_regtest(*args, wallet=wallet)
# import requests

# CLI = "bitcoin-cli"
# SIGNET_ARGS = [CLI]

# def cli_testnet(*args, wallet=None):
#     """Call Bitcoin RPC endpoint via HTTP and return parsed JSON or string."""
    
#     url = "https://bitcoin-testnet-rpc.publicnode.com"
#     args=args[0].split(' ')
#     print(f"args: {args}")
#     def parse_param(p):
#         try:
#             return json.loads(p)
#         except (json.JSONDecodeError, TypeError):
#             return p

#     payload = {
#         "jsonrpc": "1.0",
#         "id": "cli",
#         "method": args[0] if args else "getblockcount",
#         "params": [parse_param(p) for p in args[1:]] if len(args) > 1 else []
#     }
#     print(f"RPC request: {payload}")
    
#     try:
#         response = requests.post(url, json=payload, timeout=60)
#         response.raise_for_status()
#         result = response.json()
        
#         if "error" in result and result["error"]:
#             raise RuntimeError(f"bitcoin-cli error: {result['error']}")
        
#         return result.get("result")
#     except requests.RequestException as e:
#         raise RuntimeError(f"RPC request failed: {str(e)}")

# def cli_mainnet(*args, wallet=None):
#     """Call bitcoin-cli -regtest [wallet] <args> and return parsed JSON or string."""
#     cmd = list(SIGNET_ARGS)
#     if wallet:
#         cmd.append(f"-rpcwallet={wallet}")
#     cmd.extend(str(a) for a in args)
#     cmd = ' '.join(cmd)
#     ssh_pass = os.environ.get("SSHPASS") or os.environ.get("SSH_PASS")
#     if not ssh_pass:
#         raise RuntimeError("Environment variable SSHPASS or SSH_PASS must be set")
#     thecli = f"sshpass -p {ssh_pass} ssh root@95.111.247.57 '{cmd}'"
#     result = subprocess.run(thecli, shell=True, capture_output=True, text=True, timeout=60)
#     if result.returncode != 0:
#         raise RuntimeError(f"bitcoin-cli error: {result.stderr.strip()}\n  cmd: {' '.join(cmd)}")

#     output = result.stdout.strip()
#     if not output:
#         return None
#     try:
#         return json.loads(output)
#     except json.JSONDecodeError:
#         return output

# def cli_regtest(*args, wallet=None):
#     """Call bitcoin-cli -regtest [wallet] <args> and return parsed JSON or string."""
#     cmd = [CLI, "-regtest"]
#     if wallet:
#         cmd.append(f"-rpcwallet={wallet}")
#     cmd.extend(str(a) for a in args)
#     result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
#     if result.returncode != 0:
#         raise RuntimeError(f"bitcoin-cli error: {result.stderr.strip()}\n  cmd: {' '.join(cmd)}")

#     output = result.stdout.strip()
#     if not output:
#         return None
#     try:
#         return json.loads(output)
#     except json.JSONDecodeError:
#         return output

# def cli(*args, wallet=None):
#     return cli_testnet(*args, wallet=wallet)
#     # return cli_regtest(*args, wallet=wallet)

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
