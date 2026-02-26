# Stealth

A privacy audit tool for Bitcoin wallets. Stealth analyzes the transaction history of a wallet descriptor and surfaces privacy vulnerabilities at the UTXO level.

## What it does

Paste a Bitcoin wallet descriptor into the input screen and click **Analyze**. Stealth fetches the on-chain history for all addresses derived from that descriptor, then produces a report listing every UTXO in the wallet and the privacy flaws associated with each one.

## Vulnerabilities detected

### Address Reuse
Detects when the same address has received more than one payment. Address reuse is one of the most damaging privacy practices in Bitcoin: it links multiple transactions to a single entity and permanently exposes the full balance history of that address to anyone inspecting the chain.

### Dust Spend
Identifies UTXOs that originated from dust attacks — tiny amounts sent by a third party specifically to track a wallet. When the user later spends that dust alongside their own coins, the inputs are merged, linking previously unconnected addresses and revealing ownership clusters.

### UTXO Consolidation
Flags transactions where multiple UTXOs were combined into a single output. Consolidation is a strong on-chain signal that all the input addresses belong to the same wallet (the Common Input Ownership Heuristic). The resulting UTXO carries the taint of every address that funded it.

### CIOH (Common Input Ownership Heuristic)
Detects UTXOs that were created by, or whose history involves, transactions where inputs from different addresses were co-signed. This is the foundational clustering heuristic used by chain-analysis firms to link addresses to a single entity.

## How to use

1. Open the application.
2. On the first screen, paste your wallet descriptor into the input field.
   - Supported formats: `wpkh(...)`, `pkh(...)`, `sh(wpkh(...))`, `tr(...)`, and multisig variants.
3. Click **Analyze**.
4. Review the results:
   - A list of all UTXOs currently held by the wallet.
   - For each UTXO, the privacy vulnerabilities detected in its history are highlighted.

## Project structure

```
stealth/
├── frontend/   # User interface
└── backend/    # Descriptor parsing, chain data fetching, and analysis engine
```

## Privacy notice

Stealth does **not** store, log, or transmit your wallet descriptor or any derived keys. All analysis is read-only and uses publicly available on-chain data. However, querying a third-party node or API for your transaction history may itself reveal your addresses to that service. For maximum privacy, point the backend at your own Bitcoin node.
