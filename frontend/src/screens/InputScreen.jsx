import { useState } from 'react'
import styles from './InputScreen.module.css'
import { classifyInput } from '../lib/inputClassifier'
import { buildScanRequest } from '../lib/buildScanRequest'

const PLACEHOLDER = 'Paste a descriptor, xpub, address, or a list of UTXOs (txid:vout per line)'

const BADGES = {
  descriptor: 'Descriptor',
  xpub: 'Extended public key',
  address: 'Address',
  unknown: 'Not recognized',
}

export default function InputScreen({ onAnalyze }) {
  const [text, setText] = useState('')
  const [birthDate, setBirthDate] = useState('')

  const classified = classifyInput(text)
  const { kind } = classified
  const showBadge = text.trim().length > 0
  const showBirthDate = kind !== 'utxos'
  const showWarning = (kind === 'descriptor' || kind === 'xpub') && !birthDate

  function handleSubmit(e) {
    e.preventDefault()
    if (!text.trim() || kind === 'unknown') return
    onAnalyze({
      body: buildScanRequest(classified, birthDate),
      kind,
      text: classified.value,
    })
  }

  return (
    <div className={styles.root}>
      <div className={styles.container}>
        <div className={styles.wordmark}>
          <div className={styles.logo}>
            STEAL<span>TH</span>
          </div>
          <div className={styles.tagline}>Bitcoin Wallet Privacy Analyzer</div>
        </div>

        <form className={styles.card} onSubmit={handleSubmit}>
          <div className={styles.labelRow}>
            <label className={styles.label} htmlFor="wallet-input">
              Wallet Input
            </label>
            {showBadge && (
              <span className={styles.badge} data-kind={kind}>
                {kind === 'utxos' ? `UTXO list (${classified.utxos.length})` : BADGES[kind]}
              </span>
            )}
          </div>
          <textarea
            id="wallet-input"
            className={styles.textarea}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={PLACEHOLDER}
            spellCheck={false}
            autoCorrect="off"
            autoCapitalize="off"
          />

          {showBirthDate && (
            <div className={styles.dateField}>
              <label className={styles.label} htmlFor="birth-date">
                Wallet birth date <span className={styles.labelNote}>(speeds up mainnet scans)</span>
              </label>
              <input
                id="birth-date"
                type="date"
                className={styles.dateInput}
                value={birthDate}
                onChange={(e) => setBirthDate(e.target.value)}
              />
            </div>
          )}

          {showWarning && (
            <p className={styles.warning}>
              Without a birth date, mainnet scans rescan the whole chain and can take an hour.
            </p>
          )}

          <button
            type="submit"
            className={styles.button}
            disabled={!text.trim() || kind === 'unknown'}
          >
            Analyze Wallet
          </button>
          <p className={styles.hint}>
            Supports descriptors like <code>wpkh(...)</code>, <code>xpub</code>/<code>tpub</code> keys,
            addresses, and <code>txid:vout</code> lists
          </p>
        </form>
      </div>
    </div>
  )
}
