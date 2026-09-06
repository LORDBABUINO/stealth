export const analyzeWallet = async (body) => {
  const res = await fetch('/api/wallet/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error('Analysis failed')
  return res.json()
}
