export const analyzeWallet = async (descriptor) => {
  const res1 = await fetch('/api/wallet/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ descriptor }),
  })
  if (!res1.ok) throw new Error('Analysis request failed')
  const { analysisId } = await res1.json()

  const res2 = await fetch(`/api/wallet/${analysisId}/utxos`)
  if (!res2.ok) throw new Error('Failed to fetch report')
  return res2.json()
}
