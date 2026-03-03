#!/usr/bin/env python3
import argparse
import getpass
import hashlib
from embit import bip32
from embit.networks import NETWORKS
from embit.script import p2wpkh
from embit.ec import PrivateKey

parser = argparse.ArgumentParser(description="Derive WIF and address from seed phrase")
parser.add_argument("seed", nargs="?", help="Seed phrase (if omitted, you'll be prompted)")
parser.add_argument("--network", choices=["test", "main"], default="test", help="Network")
args = parser.parse_args()

seed_phrase = args.seed or getpass.getpass("Seed phrase: ")

seed_bytes = hashlib.pbkdf2_hmac(
    "sha512",
    seed_phrase.encode("utf-8"),
    b"electrum",
    iterations=2048,
)

root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS[args.network]["xprv"])
key = root.derive("m/84h/1h/0h/0/0")

privkey = PrivateKey(key.key.secret)
print("WIF:", privkey.wif(NETWORKS[args.network]))
print("Address:", p2wpkh(key.to_public()).address(NETWORKS[args.network]))