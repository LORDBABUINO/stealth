const PRIVATE_KEY = /\b[xtyzuv]prv/
const UTXO_LINE = /^[0-9a-fA-F]{64}:\d+$/
const XPUB = /^(xpub|ypub|zpub|tpub|upub|vpub)[1-9A-HJ-NP-Za-km-z]{20,}(\/(\*|\d+[h']?))*$/
const BECH32 = /^(bc1|tb1|bcrt1)[02-9ac-hj-np-z]{6,87}$/i
const LEGACY = /^[13][1-9A-HJ-NP-Za-km-z]{25,34}$/

export function classifyInput(text) {
  const value = (text ?? '').trim()
  if (!value) return { kind: 'unknown', value }
  if (PRIVATE_KEY.test(value)) return { kind: 'private', value }

  const lines = value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
  if (lines.every((l) => UTXO_LINE.test(l))) {
    const utxos = lines.map((l) => {
      const [txid, vout] = l.split(':')
      return { txid: txid.toLowerCase(), vout: Number(vout) }
    })
    return { kind: 'utxos', value, utxos }
  }

  if (XPUB.test(value)) return { kind: 'xpub', value }
  if (value.includes('(') && value.includes(')')) return { kind: 'descriptor', value }
  if (BECH32.test(value) || LEGACY.test(value)) return { kind: 'address', value }
  return { kind: 'unknown', value }
}
