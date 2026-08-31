export const analyzeWallet = async (descriptor) => {
  const res = await fetch('/api/wallet/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ descriptor }),
  })
  if (!res.ok) throw new Error('Analysis failed')
  return res.json()
}
