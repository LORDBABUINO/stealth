import { describe, it, expect, vi, afterEach } from 'vitest'
import { analyzeWallet } from './walletService'

afterEach(() => vi.unstubAllGlobals())

describe('analyzeWallet', () => {
  it('POSTs the prepared body verbatim', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({ findings: [] }) })
    vi.stubGlobal('fetch', fetchMock)

    const body = { descriptor: 'wpkh(abc)', rescan_since: 1615766400 }
    const result = await analyzeWallet(body)

    expect(fetchMock).toHaveBeenCalledWith('/api/wallet/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    expect(result).toEqual({ findings: [] })
  })

  it('POSTs a utxos body untouched', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({}) })
    vi.stubGlobal('fetch', fetchMock)

    const body = { utxos: [{ txid: 'a'.repeat(64), vout: 0 }] }
    await analyzeWallet(body)

    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual(body)
  })

  it('throws when the response is not ok', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false }))
    await expect(analyzeWallet({ descriptor: 'x' })).rejects.toThrow('Analysis failed')
  })
})
