export const analyzeWallet = async (descriptor) => {
  const res = await fetch(`/api/wallet/scan?descriptor=${encodeURIComponent(descriptor)}`)
  if (!res.ok) throw new Error('Analysis failed')
  return res.json()
}
