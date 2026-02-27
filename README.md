# Stealth

A privacy audit tool for Bitcoin wallets. Stealth analyzes the transaction history of a wallet descriptor and surfaces privacy findings from real on-chain heuristics.

## What it does

Paste a Bitcoin wallet descriptor into the input screen and click **Analyze**. Stealth derives addresses from the descriptor, scans wallet-related chain history, and returns a report with structured `findings` and `warnings`.

## Detection taxonomy (ground truth)

Stealth's source-of-truth detector is [`backend/script/detect.py`](backend/script/detect.py). The frontend renders the `type` values emitted by that script.

### Finding types

| Type | Meaning |
|---|---|
| `ADDRESS_REUSE` | Address received funds in multiple transactions, linking history and balances. |
| `CIOH` | Multi-input linkage (Common Input Ownership Heuristic) across co-spent inputs. |
| `DUST` | Dust output detection (current or historical). |
| `DUST_SPENDING` | Dust input spent with normal inputs, actively linking clusters. |
| `CHANGE_DETECTION` | Change output appears trivially identifiable through heuristics. |
| `CONSOLIDATION` | UTXO created from many-input consolidation transaction. |
| `SCRIPT_TYPE_MIXING` | Mixed input script families in one spend (strong fingerprint). |
| `CLUSTER_MERGE` | Inputs from previously separate funding chains merged in one tx. |
| `UTXO_AGE_SPREAD` | Large age spread across UTXOs reveals dormancy/lookback patterns. |
| `EXCHANGE_ORIGIN` | Probable exchange batch-withdrawal origin. |
| `TAINTED_UTXO_MERGE` | Tainted and clean inputs merged, propagating taint. |
| `BEHAVIORAL_FINGERPRINT` | Consistent transaction behavior reveals wallet/user fingerprint. |

### Warning-only types

| Type | Meaning |
|---|---|
| `DORMANT_UTXOS` | Dormant/aged UTXO pattern warning. |
| `DIRECT_TAINT` | Direct receipt from a known risky source. |

`severity` values are emitted as uppercase strings (for example `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`).

## How to use

1. Open the application.
2. On the first screen, paste your wallet descriptor into the input field.
   - Supported formats: `wpkh(...)`, `pkh(...)`, `sh(wpkh(...))`, `tr(...)`, and multisig variants.
3. Click **Analyze**.
4. Review the results:
   - Summary counters for findings, warnings, and transactions analyzed.
   - Collapsible finding/warning cards with type, severity, description, and structured evidence.

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

This script sends transactions between the test wallets to reproduce all 12 detector finding types. **The application will return no findings without this step**, since a freshly mined chain has no transaction history to analyze.

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
3. Review the report:
   - `findings[]` and `warnings[]` entries each include `type`, `severity`, `description`, and optional `details`.
   - The summary panel shows `findings`, `warnings`, and whether the scan is `clean`.

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
