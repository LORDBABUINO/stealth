import UtxoCard from '../components/UtxoCard'
import styles from './ReportScreen.module.css'

function truncateDescriptor(desc) {
  if (!desc || desc.length <= 80) return desc
  return `${desc.slice(0, 80)}…`
}

export default function ReportScreen({ report, descriptor, onReset }) {
  const { summary, utxos } = report

  return (
    <div className={styles.root}>
      <div className={styles.container}>
        {/* Nav */}
        <div className={styles.header}>
          <div className={styles.nav}>
            <div className={styles.wordmark}>
              STEAL<span>TH</span>
            </div>
            <button className={styles.backButton} onClick={onReset}>
              ← Analyze Another Wallet
            </button>
          </div>

          <div className={styles.descriptorBox}>
            <span className={styles.descriptorLabel}>Analyzed descriptor</span>
            <div className={styles.descriptorValue}>
              {truncateDescriptor(descriptor)}
            </div>
          </div>
        </div>

        {/* Summary bar */}
        <div className={styles.summaryBar}>
          <div className={`${styles.summaryCard} ${styles.total}`}>
            <div className={styles.summaryNumber}>{summary.total}</div>
            <div className={styles.summaryLabel}>Total UTXOs</div>
          </div>
          <div className={`${styles.summaryCard} ${styles.vulnerable}`}>
            <div className={styles.summaryNumber}>{summary.vulnerable}</div>
            <div className={styles.summaryLabel}>Vulnerable</div>
          </div>
          <div className={`${styles.summaryCard} ${styles.clean}`}>
            <div className={styles.summaryNumber}>{summary.clean}</div>
            <div className={styles.summaryLabel}>Clean</div>
          </div>
        </div>

        {/* UTXO list */}
        <div className={styles.listHeader}>
          <span className={styles.listTitle}>UTXO Analysis</span>
        </div>
        <div className={styles.utxoList}>
          {utxos.map((utxo) => (
            <UtxoCard key={`${utxo.txid}:${utxo.vout}`} utxo={utxo} />
          ))}
        </div>
      </div>
    </div>
  )
}
