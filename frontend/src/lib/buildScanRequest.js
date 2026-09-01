export function buildScanRequest(classified, birthDate) {
  if (classified.kind === 'utxos') return { utxos: classified.utxos }

  const descriptor = classified.kind === 'address'
    ? `addr(${classified.value})`
    : classified.value
  const body = { descriptor }
  if (birthDate) {
    body.rescan_since = Math.floor(Date.parse(`${birthDate}T00:00:00Z`) / 1000)
  }
  return body
}
