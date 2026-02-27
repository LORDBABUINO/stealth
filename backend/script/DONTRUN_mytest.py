"""
bitcoin_rpc.py — Thin wrapper around bitcoin-cli for Python tests.
Uses subprocess calls to bitcoin-cli -regtest.
"""

import json
import subprocess
import time
import os
import requests

CLI = "bitcoin-cli"
SIGNET_ARGS = [CLI]

def cli_testnet(*args, wallet=None):
    """Call Bitcoin RPC endpoint via HTTP and return parsed JSON or string."""
    
    url = "https://bitcoin-testnet-rpc.publicnode.com"
    args=args[0].split(' ')
    print(f"args: {args}")
    def parse_param(p):
        try:
            return json.loads(p)
        except (json.JSONDecodeError, TypeError):
            return p

    payload = {
        "jsonrpc": "1.0",
        "id": "cli",
        "method": args[0] if args else "getblockcount",
        "params": [parse_param(p) for p in args[1:]] if len(args) > 1 else []
    }
    print(f"RPC request: {payload}")
    
    try:
        response = requests.post(url, json=payload, timeout=60)
        response.raise_for_status()
        result = response.json()
        
        if "error" in result and result["error"]:
            raise RuntimeError(f"bitcoin-cli error: {result['error']}")
        
        return result.get("result")
    except requests.RequestException as e:
        raise RuntimeError(f"RPC request failed: {str(e)}")

def cli_mainnet(*args, wallet=None):
    """Call bitcoin-cli -regtest [wallet] <args> and return parsed JSON or string."""
    cmd = list(SIGNET_ARGS)
    if wallet:
        cmd.append(f"-rpcwallet={wallet}")
    cmd.extend(str(a) for a in args)
    cmd = ' '.join(cmd)
    ssh_pass = os.environ.get("SSHPASS") or os.environ.get("SSH_PASS")
    if not ssh_pass:
        raise RuntimeError("Environment variable SSHPASS or SSH_PASS must be set")
    thecli = f"sshpass -p {ssh_pass} ssh root@95.111.247.57 '{cmd}'"
    result = subprocess.run(thecli, shell=True, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"bitcoin-cli error: {result.stderr.strip()}\n  cmd: {' '.join(cmd)}")

    output = result.stdout.strip()
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return output

def cli_regtest(*args, wallet=None):
    """Call bitcoin-cli -regtest [wallet] <args> and return parsed JSON or string."""
    cmd = [CLI, "-regtest"]
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

block_count =  cli_testnet("getblockcount")
print("testnet:", block_count)
blockhash = cli_testnet(f"getblockhash {block_count}")
block = cli_testnet(f"getblock {blockhash}")
print("testnet:", block)


# print("mainnet:", cli_mainnet("getblockcount"))
# print("regtest:", cli_regtest("getblockcount"))
