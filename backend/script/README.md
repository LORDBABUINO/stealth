pass: "aW2u~fYiuLu3)%a"

METAMASK:
1.twenty
2.series
3.camera
4.invite
5.dismiss
6.gentle
7.dose
8.hotel
9.circle
10.eight
11.rotate
12.assault

ENKRYPT:
damage
scare
aerobic
eagle
club
typical
cricket
kick
jaguar
paddle
void
dinner

sshpass $SSHPASS ssh user@REMOTE_HOST 'bitcoin-cli getblockcount'

electrum alice:
summer recipe phrase depth accident shuffle doctor trip hurdle jeans crop plate

electrum bob:
curtain tiny reduce deer icon maid fresh lunch vivid inform woman squirrel


alice_t4:
- bulk cactus balance toward hawk glory regret blast cinnamon game confirm vintage
- tb1qllp2tyl03qskw49mg3wl04paegrrn7ll6rfef4
bob_t4:
- paper pact now deal next unique option animal region dismiss detect pipe
- tb1qtxdyzss48eue5clr2v7cd76fjsv3krs77s5ma0
carol_t4:
- regular hawk empty only caught train half upon chaos clap until guitar
- tb1qhkyuf6vkxefc8lpyuhxdutjhwc8m78hry8cthj
miner_t4:
- mutual east bench couple cage volume demand slush slab all swallow section
- tb1qa7wryry350swml5gnq92as5hxcgnewppqrsn6j
exchange_t4:
- awkward sick super sausage parrot apple bread loud kangaroo shop result issue
- tb1qa093eafvdz0wa2k6l274ve7asvm353mv45cl4w
risky_t4:
- town daring skill mechanic buzz head day quality inhale park cinnamon random
- tb1qhjd00gdjzne9khq6shlc9spcdag2gt8c468hfr






===========================================

bitcoin-cli -testnet4 unloadwallet alice
rm -rf ~/.bitcoin/testnet4/wallets/alice
python load.py "bulk cactus balance toward hawk glory regret blast cinnamon ga
me confirm vintage"
WIF: cTNftSdam7X3sdwVy8aQ8vshDjQBgosS76HWMg6XrGjqYDJyYHCD
Address: tb1qumm4e6h5pacudhn7np7lr4tdwgk8khulkaj0ny
{
  "descriptor": "wpkh(02439f42b07b13682a319c06cc209119d10f96f72db9ba5a0f1b843ef89ce7807c)#j50ja6ax",
  "checksum": "p30q9gg3",
  "isrange": false,
  "issolvable": true,
  "hasprivatekeys": true
}
bitcoin-cli -testnet4 createwallet "alice"
<!-- bitcoin-cli -testnet4 -rpcwallet=alice importdescriptors \
  '[{"desc":"wpkh(02439f42b07b13682a319c06cc209119d10f96f72db9ba5a0f1b843ef89ce7807c)#j50ja6ax","timestamp":"now","range":[0,100]}]' -->
<!-- bitcoin-cli -testnet4 -rpcwallet=alice importdescriptors \
  '[{"desc":"wpkh(02439f42b07b13682a319c06cc209119d10f96f72db9ba5a0f1b843ef89ce7807c)#j50ja6ax","timestamp":"now"}]' -->



bitcoin-cli -testnet4 getdescriptorinfo "wpkh(cTNftSdam7X3sdwVy8aQ8vshDjQBgosS76HWMg6XrGjqYDJyYHCD)"
wpkh(02439f42b07b13682a319c06cc209119d10f96f72db9ba5a0f1b843ef89ce7807c)#j50ja6ax
bitcoin-cli -testnet4 -rpcwallet=alice importdescriptors \
  '[{"desc":"wpkh(02439f42b07b13682a319c06cc209119d10f96f72db9ba5a0f1b843ef89ce7807c)#j50ja6ax","timestamp":"now"}]'



  
  bitcoin-cli -testnet4 -rpcwallet=alice importdescriptors \
'[{
  "desc":"wpkh(02439f42b07b13682a319c06cc209119d10f96f72db9ba5a0f1b843ef89ce7807c)#j50ja6ax",
  "timestamp":"now",
  "active":true
}]'

==================


```bash
export user=alice
export seed="bulk cactus balance toward hawk glory regret blast cinnamon game confirm vintage"
bitcoin-cli -testnet4 unloadwallet "$user"
rm -rf ~/.bitcoin/testnet4/wallets/$user
bitcoin-cli -testnet4 createwallet "$user" true true "" false true

export WIF="$(python3 - <<'PY'
from embit import bip32
from embit.networks import NETWORKS
from embit.ec import PrivateKey
import hashlib, os
seed_phrase = os.environ['seed']
seed_bytes = hashlib.pbkdf2_hmac('sha512', seed_phrase.encode(), b'electrum', iterations=2048)
root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS['test']['xprv'])
key = root.derive("m/84h/1h/0h/0/0")
privkey = PrivateKey(key.key.secret)
print(privkey.wif(NETWORKS['test']))
PY
)"
export WIF

# descriptor=$(bitcoin-cli -testnet4 getdescriptorinfo "wpkh($WIF)" | jq -r .descriptor)
# Get just the checksum
checksum=$(bitcoin-cli -testnet4 getdescriptorinfo "wpkh($WIF)" | jq -r .checksum)

bitcoin-cli -testnet4 -rpcwallet=$user importdescriptors \
"[{
  \"desc\": \"wpkh($WIF)#$checksum\",
  \"timestamp\": \"now\"
}]"
```




```bash
export user=alice
export seed="bulk cactus balance toward hawk glory regret blast cinnamon game confirm vintage"

bitcoin-cli -testnet4 unloadwallet "$user" 2>/dev/null
rm -rf ~/.bitcoin/testnet4/wallets/$user
bitcoin-cli -testnet4 createwallet "$user"

export WIF="$(python3 - <<'PY'
from embit import bip32
from embit.networks import NETWORKS
from embit.ec import PrivateKey
import hashlib, os
seed_phrase = os.environ['seed']
seed_bytes = hashlib.pbkdf2_hmac('sha512', seed_phrase.encode(), b'electrum', iterations=2048)
root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS['test']['xprv'])
key = root.derive("m/84h/1h/0h/0/0")
privkey = PrivateKey(key.key.secret)
print(privkey.wif(NETWORKS['test']))
PY
)"

checksum=$(bitcoin-cli -testnet4 getdescriptorinfo "wpkh($WIF)" | jq -r .checksum)

bitcoin-cli -testnet4 -rpcwallet=$user importdescriptors \
"[{
  \"desc\": \"wpkh($WIF)#$checksum\",
  \"timestamp\": \"now\"
}]"

# ensure balance is defined and compare using bc, fallback to 0 on error
result=$(echo "${balance:-0} > 0" | bc -l 2>/dev/null || echo 0)
if [ "$result" -eq 1 ]; then
    echo "balance > 0"
else
    echo "balance <= 0"
fi

```


```bash

export user=alice
export seed="bulk cactus balance toward hawk glory regret blast cinnamon game confirm vintage"

bitcoin-cli -testnet4 unloadwallet "$user" 2>/dev/null
rm -rf ~/.bitcoin/testnet4/wallets/$user
bitcoin-cli -testnet4 createwallet "$user"

# Get the xprv root key
export XPRV="$(python3 - <<'PY'
from embit import bip32
from embit.networks import NETWORKS
import hashlib, os

seed_phrase = os.environ['seed']
seed_bytes = hashlib.pbkdf2_hmac('sha512', seed_phrase.encode(), b'electrum', iterations=2048)
root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS['test']['xprv'])
print(root.to_base58())
PY
)"

# Import receiving addresses (m/0/*)
recv_check=$(bitcoin-cli -testnet4 getdescriptorinfo "wpkh($XPRV/0/*)" | jq -r .checksum)
# Import change addresses (m/1/*)
change_check=$(bitcoin-cli -testnet4 getdescriptorinfo "wpkh($XPRV/1/*)" | jq -r .checksum)

bitcoin-cli -testnet4 -rpcwallet=$user importdescriptors \
"[
  {
    \"desc\": \"wpkh($XPRV/0/*)#$recv_check\",
    \"timestamp\": 0,
    \"range\": [0, 50],
    \"internal\": false
  },
  {
    \"desc\": \"wpkh($XPRV/1/*)#$change_check\",
    \"timestamp\": 0,
    \"range\": [0, 50],
    \"internal\": true
  }
]"


bitcoin-cli -testnet4 -rpcwallet=$user getblockchaininfo

# Check current block height
bitcoin-cli -testnet4 getblockcount

# Rescan from a reasonable starting height (adjust as needed)
bitcoin-cli -testnet4 -rpcwallet=$user rescanblockchain 50000
```






alice_t4:
- bulk cactus balance toward hawk glory regret blast cinnamon game confirm vintage
- tb1qllp2tyl03qskw49mg3wl04paegrrn7ll6rfef4
bob_t4:
- paper pact now deal next unique option animal region dismiss detect pipe
- tb1qtxdyzss48eue5clr2v7cd76fjsv3krs77s5ma0
carol_t4:
- regular hawk empty only caught train half upon chaos clap until guitar
- tb1qhkyuf6vkxefc8lpyuhxdutjhwc8m78hry8cthj
miner_t4:
- mutual east bench couple cage volume demand slush slab all swallow section
- tb1qa7wryry350swml5gnq92as5hxcgnewppqrsn6j
exchange_t4:
- awkward sick super sausage parrot apple bread loud kangaroo shop result issue
- tb1qa093eafvdz0wa2k6l274ve7asvm353mv45cl4w
risky_t4:
- town daring skill mechanic buzz head day quality inhale park cinnamon random
- tb1qhjd00gdjzne9khq6shlc9spcdag2gt8c468hfr


```bash
export user=risky
export seed="town daring skill mechanic buzz head day quality inhale park cinnamon random"
python3 - <<'PY'
from embit import bip32
from embit.networks import NETWORKS
from embit.script import p2wpkh
import hashlib

seed_phrase = "town daring skill mechanic buzz head day quality inhale park cinnamon random"
seed_bytes = hashlib.pbkdf2_hmac("sha512", seed_phrase.encode("utf-8"), b"electrum", iterations=2048)
root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS["test"]["xprv"])

# Print first 5 receiving and first 3 change for m/0h path
print("=== Receiving (m/0h/0/*) ===")
for i in range(5):
    child = root.derive(f"m/0h/0/{i}")
    addr = p2wpkh(child.key).address(NETWORKS["test"])
    print(f"  m/0h/0/{i} -> {addr}")

print("=== Change (m/0h/1/*) ===")
for i in range(3):
    child = root.derive(f"m/0h/1/{i}")
    addr = p2wpkh(child.key).address(NETWORKS["test"])
    print(f"  m/0h/1/{i} -> {addr}")
PY

bitcoin-cli -testnet4 unloadwallet "$user" 2>/dev/null
rm -rf ~/.bitcoin/testnet4/wallets/$user
bitcoin-cli -testnet4 createwallet "$user"

export XPRV="$(python3 - <<'PY'
from embit import bip32
from embit.networks import NETWORKS
import hashlib
seed_phrase = "bulk cactus balance toward hawk glory regret blast cinnamon game confirm vintage"
seed_bytes = hashlib.pbkdf2_hmac("sha512", seed_phrase.encode("utf-8"), b"electrum", iterations=2048)
root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS["test"]["xprv"])
account = root.derive("m/0h")
print(account.to_base58())
PY
)"

recv_check=$(bitcoin-cli -testnet4 getdescriptorinfo "wpkh($XPRV/0/*)" | jq -r .checksum)
change_check=$(bitcoin-cli -testnet4 getdescriptorinfo "wpkh($XPRV/1/*)" | jq -r .checksum)

bitcoin-cli -testnet4 -rpcwallet=$user importdescriptors "[
  {\"desc\": \"wpkh($XPRV/0/*)#$recv_check\", \"timestamp\": \"now\", \"range\": [0, 50], \"internal\": false},
  {\"desc\": \"wpkh($XPRV/1/*)#$change_check\", \"timestamp\": \"now\", \"range\": [0, 50], \"internal\": true}
]"

bitcoin-cli -testnet4 -rpcwallet=$user rescanblockchain 107570
bitcoin-cli -testnet4 -rpcwallet=$user getbalance
```