import { useState } from 'react'
import styles from './InputScreen.module.css'

const PLACEHOLDER = `wpkh([a1b2c3d4/84h/0h/0h]xpub6CatWdiZynkCminahu8Gmr7FAVnQXBTSMaBxn6qmBNkdm9tDkFzWmjmDrLBCQSTa7BHgpEjCXzMTCyDsQLSmcGYJHBB7cTwpqLNRKGP47uw/0/*)#qwer1234`

export default function InputScreen({ onAnalyze }) {
  const [descriptor, setDescriptor] = useState('')

  function handleSubmit(e) {
    e.preventDefault()
    const trimmed = descriptor.trim()
    if (!trimmed) return
    onAnalyze(trimmed)
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
          <label className={styles.label} htmlFor="descriptor">
            Wallet Descriptor
          </label>
          <textarea
            id="descriptor"
            className={styles.textarea}
            value={descriptor}
            onChange={(e) => setDescriptor(e.target.value)}
            placeholder={PLACEHOLDER}
            spellCheck={false}
            autoCorrect="off"
            autoCapitalize="off"
          />
          <button
            type="submit"
            className={styles.button}
            disabled={!descriptor.trim()}
          >
            Analyze Wallet
          </button>
          <p className={styles.hint}>
            Supports <code>wpkh()</code>, <code>pkh()</code>, <code>sh(wpkh())</code> descriptors
          </p>
        </form>
      </div>
    </div>
  )
}
