const ONE_DAY = 86400

export function buildScanRequest(classified, birthDate) {
  const { kind, value } = classified
  if (kind === 'utxos') return { utxos: classified.utxos }
  if (kind !== 'descriptor' && kind !== 'xpub' && kind !== 'address') {
    throw new Error(`Cannot build a scan request from ${kind} input`)
  }

  const body = { descriptor: kind === 'address' ? `addr(${value})` : value }
  if (birthDate) {
    const ts = Math.floor(Date.parse(`${birthDate}T00:00:00Z`) / 1000) - ONE_DAY
    if (Number.isFinite(ts)) body.rescan_since = ts
  }
  return body
}
