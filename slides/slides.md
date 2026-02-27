---
theme: default
title: Stealth — Bitcoin Wallet Privacy Analyzer
titleTemplate: '%s | Stealth'
class: stealth-theme
fonts:
  sans: Inter
  mono: JetBrains Mono
lineNumbers: false
drawings:
  persist: false
transition: slide
mdc: true
---

# STEAL<span class="accent">TH</span>

### Bitcoin Wallet Privacy Analyzer

A privacy audit tool that surfaces vulnerabilities at the UTXO level.

---

# The Problem

<div class="grid grid-cols-2 gap-8">

<div>

**Bitcoin privacy is fragile**

- Chain analysis firms track wallets
- Common heuristics link addresses
- Users rarely know their exposure
- One bad UTXO can taint the rest

</div>

<div>

**Today's tools**

- Complex, require expertise
- No UTXO-level visibility
- Hard to understand risk before spending

</div>

</div>

---

# What Stealth Does

<div class="grid grid-cols-2 gap-6">

<div>

**Input**
- Paste wallet descriptor
- Supports `wpkh`, `pkh`, `sh(wpkh)`, `tr`, multisig

**Output**
- Structured findings + warnings
- Type/severity/description + evidence details
- Severity badges mapped from detector output

</div>

<div>

```bash
# One click
wpkh([xpub...]/0/*) → Analyze
```

→ Full report with actionable insights

</div>

</div>

---

# Vulnerabilities Detected

| Detector Type | Meaning |
|---------------|---------|
| `ADDRESS_REUSE` | Same address received multiple payments, linking history |
| `CIOH` | Multi-input ownership clustering signal |
| `DUST` / `DUST_SPENDING` | Dust detection and dust+normal co-spend linkage |
| `CHANGE_DETECTION` | Payment/change outputs become easy to distinguish |
| `CONSOLIDATION` / `CLUSTER_MERGE` | Input histories merged into one cluster |
| `SCRIPT_TYPE_MIXING` | Mixed input script families create fingerprint |
| `UTXO_AGE_SPREAD` | Old/new UTXO spread leaks dormancy patterns |
| `EXCHANGE_ORIGIN` | Probable exchange batch-withdrawal origin |
| `TAINTED_UTXO_MERGE` | Tainted + clean input merge propagates taint |
| `BEHAVIORAL_FINGERPRINT` | Transaction style consistency re-identifies wallet |
| Warnings: `DORMANT_UTXOS`, `DIRECT_TAINT` | Non-finding risk signals shown separately |

---

# How It Works

<div class="grid grid-cols-3 gap-4">

<div class="card p-4">

**1. Parse**
- Extract addresses from descriptor
- Support all common formats

</div>

<div class="card p-4">

**2. Fetch**
- On-chain history per address
- Uses Bitcoin node / API

</div>

<div class="card p-4">

**3. Analyze**
- Apply privacy heuristics
- Flag each UTXO with findings

</div>

</div>

---

# Architecture

```
stealth/
├── frontend/   # React + Vite — input, loading, report
└── backend/    # Java/Quarkus — descriptor parsing, chain data, analysis
```

- **Read-only** — no keys, no storage, no transmission of descriptors
- **Self-hostable** — point at your own node for max privacy

---

# Demo Flow

1. **Input screen** — paste descriptor, click Analyze
2. **Loading** — fetches and analyzes
3. **Report** — summary bar (findings / warnings / tx analyzed)
4. Expandable finding cards: type, severity, description, structured evidence

---

# Why It Matters

- **Users** — understand exposure before consolidating or spending
- **Wallets** — integrate as pre-spend check
- **Researchers** — study privacy heuristics at scale
- **Privacy-first** — no cloud, no logs, no tracking

---

# Thank You

**STEAL<span class="accent">TH</span>**

Bitcoin Wallet Privacy Analyzer

---

# Appendix — Supported Descriptors

- `wpkh(...)` — native SegWit
- `pkh(...)` — legacy
- `sh(wpkh(...))` — nested SegWit
- `tr(...)` — Taproot
- Multisig variants

All analysis uses publicly available on-chain data.
