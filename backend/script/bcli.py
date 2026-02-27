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

from lib.bitcoin_rpc_testnet import cli
# from lib.bitcoin_rpc_testnet import cli

block_count =  cli("getblockcount")
print("testnet:", block_count)
blockhash = cli(f"getblockhash {block_count}")
block = cli(f"getblock {blockhash}")
print("testnet:", block)

# print("mainnet:", cli_mainnet("getblockcount"))
# print("regtest:", cli_regtest("getblockcount"))
