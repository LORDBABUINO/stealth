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
- Every UTXO listed
- Privacy flaws per UTXO
- Severity badges (high / medium / low)

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

| Vulnerability | What it means |
|---------------|---------------|
| **Address Reuse** | Same address received >1 payment — links tx history, exposes balance |
| **Dust Spend** | UTXO from dust attack — when spent, links previously unconnected addresses |
| **UTXO Consolidation** | Multiple inputs merged — strong signal all belong to same wallet |
| **CIOH** | Common Input Ownership Heuristic — chain analysis firms use this to cluster addresses |

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
3. **Report** — summary bar (total / vulnerable / clean) + UTXO cards
4. Each card: address, amount, badges, expandable details

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
