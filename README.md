# Stealth

A privacy audit tool for Bitcoin wallets. Stealth analyzes the transaction history of a wallet descriptor and surfaces privacy vulnerabilities at the UTXO level.

## What it does

Paste a Bitcoin wallet descriptor into the input screen and click **Analyze**. Stealth fetches the on-chain history for all addresses derived from that descriptor, then produces a report listing every UTXO in the wallet and the privacy flaws associated with each one.

## Vulnerabilities detected

### Address Reuse
Detects when the same address has received more than one payment. Address reuse links multiple transactions to a single entity and permanently exposes the full balance history of that address to anyone inspecting the chain.

### CIOH (Common Input Ownership Heuristic)
Detects transactions where inputs from multiple of your addresses were co-signed. This is the foundational clustering heuristic used by chain-analysis firms: it proves all co-signed inputs belong to the same wallet.

### Dust Attack
Identifies UTXOs that originated from dust — tiny amounts sent by a third party to track a wallet. When the user later spends that dust alongside their own coins, the inputs are merged and previously unconnected addresses are linked.

### Dust Spending
Flags transactions that spend a dust UTXO together with normal-sized inputs, actively triggering the dust-tracking link.

### Change Output Detection
Detects transactions where the change output is trivially identifiable through heuristics such as round-number payments, mismatched script types between change and payment, or use of the internal (BIP-44 `/1/*`) derivation path.

### UTXO Consolidation
Flags UTXOs born from a consolidation transaction (many inputs, few outputs). Consolidation merges the histories of all input addresses into one UTXO, amplifying the privacy damage of every prior vulnerability.

### Script Type Mixing
Detects transactions that mix different input script types (e.g. P2PKH alongside P2WPKH). This is rare and highly identifying, shrinking the anonymity set significantly.

### Cluster Merge
Identifies transactions that merge UTXOs from different funding chains, linking independent coin histories and allowing chain-analysis firms to associate previously separate clusters.

### UTXO Age Spread
Flags wallets where unspent outputs have significantly different ages. A wide age spread can reveal hoarding patterns and help correlate activity across time periods.

### Exchange Origin
Detects UTXOs received from likely exchange batch withdrawals, identified by high output counts, many unique recipients, and a large input-to-output ratio.

### Tainted UTXO Merge
Flags transactions that spend tainted inputs (from known risky sources) alongside clean inputs, spreading taint to the clean coin history.

### Behavioral Fingerprint
Analyses patterns across all send transactions — fee rates, output counts, RBF signalling, locktime usage, round amounts, and script type consistency — to detect wallet software fingerprints that chain-analysis firms use for clustering.

## How to use

1. Open the application.
2. On the first screen, paste your wallet descriptor into the input field.
   - Supported formats: `wpkh(...)`, `pkh(...)`, `sh(wpkh(...))`, `tr(...)`, and multisig variants.
3. Click **Analyze**.
4. Review the results:
   - A list of all UTXOs currently held by the wallet.
   - For each UTXO, the privacy vulnerabilities detected in its history are highlighted.

## Installation

### Prerequisites

| Dependency | Version | Purpose |
|---|---|---|
| [Bitcoin Core](https://bitcoincore.org/en/download/) | ≥ 26 | Local regtest node |
| Python | ≥ 3.10 | Analysis engine (`detect.py`) |
| Java | 21 | Quarkus backend |
| Node.js + yarn | ≥ 18 | React frontend |

### 1. Clone the repository

```bash
git clone https://github.com/LORDBABUINO/stealth.git
cd stealth
```

### 2. Bootstrap Bitcoin Core (regtest)

```bash
cd backend/script
./setup.sh          # starts bitcoind, creates wallets, mines 110 blocks
```

Pass `--fresh` to wipe the chain and start from genesis.

### 3. Generate vulnerable transactions (required before using the app)

```bash
python3 reproduce.py
```

This script sends transactions between the test wallets to reproduce all 12 privacy vulnerability types — address reuse, dust attacks, CIOH, consolidation, script-type mixing, and more. **The application will return no findings without this step**, since a freshly mined chain has no transaction history to analyse.

After it runs, get a descriptor to paste into the app:

```bash
bitcoin-cli -regtest -rpcwallet=alice listdescriptors | python3 -c \
  "import sys,json; d=json.load(sys.stdin)['descriptors']; print(d[0]['desc'])"
```

Copy the output and use it as the descriptor in the application.

### 4. Start the backend

```bash
cd backend/src/StealthBackend
./mvnw quarkus:dev
```

The API will be available at `http://localhost:8080`.

### 5. Start the frontend

```bash
cd frontend
yarn install
yarn dev
```

Open `http://localhost:5173` in your browser.

## Running

1. Paste a wallet descriptor into the input field (e.g. `wpkh([fp/84h/0h/0h]xpub.../0/*)`).
2. Click **Analyze** — the frontend calls `GET /api/wallet/scan?descriptor=…` on the backend, which runs `detect.py` against your local regtest node.
3. Review the findings: each entry shows the vulnerability type, severity, and a collapsible details panel.

## Project structure

```
stealth/
├── frontend/          # React + Vite UI
├── backend/
│   ├── script/        # detect.py, reproduce.py, setup.sh, bitcoin_rpc.py
│   └── src/           # Quarkus Java REST API
└── slides/            # Slidev pitch presentation
```

## Privacy notice

Stealth does **not** store, log, or transmit your wallet descriptor or any derived keys. All analysis is read-only and uses publicly available on-chain data. However, querying a third-party node or API for your transaction history may itself reveal your addresses to that service. For maximum privacy, point the backend at your own Bitcoin node.
