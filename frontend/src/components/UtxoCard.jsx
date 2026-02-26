import { useState } from 'react'
import VulnerabilityBadge from './VulnerabilityBadge'
import styles from './UtxoCard.module.css'

function truncateAddress(addr) {
  if (!addr || addr.length <= 20) return addr
  return `${addr.slice(0, 12)}…${addr.slice(-8)}`
}

function truncateTxid(txid) {
  if (!txid || txid.length <= 24) return txid
  return `${txid.slice(0, 16)}…${txid.slice(-8)}`
}

export default function UtxoCard({ utxo }) {
  const [open, setOpen] = useState(false)
  const isClean = utxo.vulnerabilities.length === 0

  const highestSeverity = utxo.vulnerabilities.reduce((acc, v) => {
    const order = { high: 3, medium: 2, low: 1 }
    return (order[v.severity] ?? 0) > (order[acc] ?? 0) ? v.severity : acc
  }, null)

  return (
    <div
      className={`${styles.card} ${isClean ? styles.clean : styles.hasVulnerabilities}`}
    >
      <div
        className={styles.header}
        onClick={() => setOpen((o) => !o)}
        role="button"
        aria-expanded={open}
      >
        <div className={styles.headerLeft}>
          <div className={styles.addressRow}>
            <span className={styles.address} title={utxo.address}>
              {truncateAddress(utxo.address)}
            </span>
          </div>
          <div className={styles.badges}>
            {isClean ? (
              <span className={styles.cleanLabel}>✓ Clean</span>
            ) : (
              utxo.vulnerabilities.map((v, i) => (
                <VulnerabilityBadge key={i} type={v.type} severity={v.severity} />
              ))
            )}
          </div>
        </div>

        <div className={styles.headerRight}>
          <span className={styles.amount}>
            {utxo.amountBtc.toFixed(8)} BTC
          </span>
          <span className={styles.confirmations}>
            {utxo.confirmations.toLocaleString()} confs
          </span>
        </div>

        <span className={`${styles.chevron} ${open ? styles.open : ''}`}>▼</span>
      </div>

      <div className={`${styles.detail} ${open ? styles.open : ''}`}>
        <span className={styles.txidLabel}>txid</span>
        <div className={styles.txid}>
          {utxo.txid}:{utxo.vout}
        </div>

        {!isClean && (
          <div className={styles.vulnerabilityList}>
            {utxo.vulnerabilities.map((v, i) => (
              <div key={i} className={`${styles.vulnItem} ${styles[v.severity]}`}>
                <div className={styles.vulnHeader}>
                  <VulnerabilityBadge type={v.type} severity={v.severity} />
                </div>
                <p className={styles.vulnDesc}>{v.description}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
