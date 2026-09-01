import { useState, useEffect } from 'react'
import styles from './LoadingScreen.module.css'

const MESSAGES = [
  'Resolving descriptors',
  'Deriving addresses',
  'Importing & scanning blockchain',
  'Loading transaction history',
  'Running vulnerability detectors',
]

export default function LoadingScreen({ text, kind }) {
  const [msgIndex, setMsgIndex] = useState(0)

  useEffect(() => {
    const interval = setInterval(() => {
      setMsgIndex((i) => (i + 1) % MESSAGES.length)
    }, 1000)
    return () => clearInterval(interval)
  }, [])

  const shortText = text.length > 48 ? `${text.slice(0, 48)}…` : text
  const isChainScan = kind === 'descriptor' || kind === 'xpub'

  return (
    <div className={styles.root}>
      <div className={styles.scanner}>
        <div className={styles.ring} />
        <div className={styles.ring2} />
        <div className={styles.ring3} />
        <div className={styles.logoMark}>
          ST<span>LT</span>H
        </div>
      </div>

      <div className={styles.status}>
        <div key={msgIndex} className={styles.statusText}>
          {MESSAGES[msgIndex]}<span className={styles.dots}>...</span>
        </div>
        <div className={styles.descriptor}>{shortText}</div>
        {isChainScan && (
          <div className={styles.note}>
            Scanning the chain for your wallet's history. This can take a few minutes.
          </div>
        )}
      </div>

      <div className={styles.progressBar}>
        <div className={styles.progressFill} />
      </div>
    </div>
  )
}
