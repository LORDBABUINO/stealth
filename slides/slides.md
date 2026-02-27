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
transition: fade
colorSchema: dark
mdc: true
---

<div class="hero-wrap">
 
  <h1 class="hero-title">STEAL<span class="accent">TH</span></h1>
  <p class="hero-subtitle">Bitcoin Wallet Privacy Analyzer</p>
  <p class="hero-copy">A read-only audit engine that surfaces wallet exposure at the UTXO level before funds move.</p>
  <div class="hero-chips">
    <span class="chip chip-safe">No keys</span>
    <span class="chip">UTXO-level findings</span>
    <span class="chip">Self-hostable</span>
  </div>
</div>

---

# The Problem
<br>
<div class="panel accent-panel">
  <p class="kicker">Visibility gap</p>
  <h3>Bitcoin privacy leaks are invisible to users</h3>
  <ul class="list">
    <li>Companies like <b>Chainalysis</b> can analyze wallet privacy</li>
    <li><b>Users cannot</b></li>
    <li>People may expose: full transaction history, identity links, and behavioral fingerprints</li>
  </ul>
<br>
<p>Companies can analyze your privacy better than you can.
</p>
</div>

---

# Why This Happens
<br>
<div class="panel accent-panel">
<h3>Privacy is broken by <b>patterns</b>, not hacks</h3>

Common wallet patterns that leak privacy:

- Multi-input transactions (CIOH / consolidation) 
- Combining coins
- Address reuse   
- Sending change to same input address  
- Dust UTXOs  
- Exchange linkage / taint signals  
</div>

---

## Visibility Imbalance

<p class="footnote">Chainalysis users can see wallet-linkage signals that the average user cannot see about themselves.</p>

<div class="seesaw-wrap">
  <div class="seesaw">
    <div class="seesaw-beam-bar"></div>
    <div class="seesaw-beam">
      <div class="seesaw-side heavy">
        <span class="chainalysis-wordmark">Chainalysis</span>
      </div>
      <div class="seesaw-pivot"></div>
      <div class="seesaw-side light">
        <span class="user-label">user</span>
      </div>
    </div>
  </div>
</div>

---

## Privacy Parity

<p class="footnote">With Stealth, users gain visibility closer to institutional-grade analysis.</p>

<div class="seesaw-wrap">
  <div class="seesaw seesaw-balanced">
    <div class="seesaw-beam-bar"></div>
    <div class="seesaw-beam">
      <div class="seesaw-side heavy">
        <span class="chainalysis-wordmark">Chainalysis</span>
      </div>
      <div class="seesaw-pivot"></div>
      <div class="seesaw-side light">
        <div class="user-stealth-stack">
          <span class="user-label">user</span>
          <span class="stealth-wordmark">STEAL<span class="accent">TH</span></span>
        </div>
      </div>
    </div>
  </div>
</div>

---

## How It Works
<br>
<div class="split three">

<div class="panel step">

<p class="step-index">01</p>
<h3>Parse</h3>
<ul class="list">
  <li>Input public descriptor</li>
  <li>Get all addresses and UTXOs</li>
</ul>

</div>

<div class="panel step">

<p class="step-index">02</p>
<h3>Fetch</h3>
<ul class="list">
  <li>Load on-chain history per address</li>
  <li>Use Bitcoin node</li>
</ul>

</div>

<div class="panel step">

<p class="step-index">03</p>
<h3>Analyze</h3>
<ul class="list">
  <li>Use privacy heuristics</li>
  <li>Flag each UTXO with findings and suggestions</li>
</ul>

</div>

</div>

---

## Demo

<div class="panel">
  <video
    controls
    autoplay
    muted
    loop
    playsinline
    src="/demo-2x-fast.mp4"
    style="width: 100%; border-radius: 12px; border: 1px solid var(--border);"
  ></video>
  <p class="footnote">2x playback and compressed for lightweight deck rendering.</p>
</div>

---

## Vulnerabilities Detected
<br>
<table class="detector-table">
  <thead>
    <tr>
      <th>Detector Type</th>
      <th>Meaning</th>
    </tr>
  </thead>
  <tbody>
    <tr><td><code>ADDRESS_REUSE</code></td><td>Repeated receive address links payment history</td></tr>
    <tr><td><code>CIOH</code></td><td>Multi-input ownership clustering signal</td></tr>
    <tr><td><code>DUST</code> / <code>DUST_SPENDING</code></td><td>Dust + normal co-spend linkage pattern</td></tr>
    <tr><td><code>CHANGE_DETECTION</code></td><td>Payment and change outputs become distinguishable</td></tr>
    <tr><td><code>CONSOLIDATION</code> / <code>CLUSTER_MERGE</code></td><td>Input histories merged into one traceable cluster</td></tr>
    <tr><td><code>SCRIPT_TYPE_MIXING</code></td><td>Mixed script families create a wallet fingerprint</td></tr>
    <tr><td><code>UTXO_AGE_SPREAD</code></td><td>Old/new spread leaks dormancy behavior</td></tr>
    <tr><td><code>EXCHANGE_ORIGIN</code></td><td>Probable exchange withdrawal origin signature</td></tr>
    <tr><td><code>TAINTED_UTXO_MERGE</code></td><td>Tainted + clean merge propagates contamination</td></tr>
    <tr><td><code>BEHAVIORAL_FINGERPRINT</code></td><td>Consistent transaction style re-identifies wallet</td></tr>
  </tbody>
</table>

<p class="footnote">Warnings: <code>DORMANT_UTXOS</code> and <code>DIRECT_TAINT</code> are shown as contextual risk signals.</p>

---

## Roadmap

<div class="split two">
  <div class="panel">
    <p class="kicker">Expanded Heuristics</p>
    <ul class="list">
      <li><code>LEGACY_SCRIPT_EXPOSURE</code> — old script usage (<code>p2pkh</code> / nested-only flows) shrinking anonymity set</li>
      <li><code>ADDRESS_GAP_LEAK</code> — sparse derivation usage exposing wallet generation behavior</li>
      <li><code>AMOUNT_FINGERPRINT</code> — repeated denomination templates across spends</li>
      <li><code>TIME_PATTERN_FINGERPRINT</code> — recurring timing cadence linking sessions</li>
    </ul>
  </div>
  <div class="panel">
    <p class="kicker">Improvements</p>
    <ul class="list">
      <li><b>Mainnet Support</b></li><br>
      <li><b>Mobile Support</b></li><br>
      <li><b>Cluster Visualization</b></li><br>
      <li><b>One-click solution</b></li>
    </ul>
  </div>
</div>

<p class="footnote">Roadmap detectors are additive and keep the same read-only, no-key security model.</p>

---

<div class="hero-wrap end">
  <p class="eyebrow">Thank You</p>
  <h1 class="hero-title">STEAL<span class="accent">TH</span></h1>
  <p class="hero-subtitle">Bitcoin Wallet Privacy Analyzer</p>
  <p class="hero-copy">Protect privacy before you broadcast intent.</p>
</div>

