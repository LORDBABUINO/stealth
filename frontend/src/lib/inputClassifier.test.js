import { describe, it, expect } from 'vitest'
import { classifyInput } from './inputClassifier'

const XPUB = 'xpub6CatWdiZynkCminahu8Gmr7FAVnQXBTSMaBxn6qmBNkdm9tDkFzWmjmDrLBCQSTa7BHgpEjCXzMTCyDsQLSmcGYJHBB7cTwpqLNRKGP47uw'
const TXID = 'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16'

describe('classifyInput: utxos', () => {
  it('classifies a single txid:vout line', () => {
    expect(classifyInput(`${TXID}:0`)).toEqual({
      kind: 'utxos',
      value: `${TXID}:0`,
      utxos: [{ txid: TXID, vout: 0 }],
    })
  })

  it('classifies multiple lines with numeric vouts', () => {
    const text = `${TXID}:1\n${TXID}:12`
    expect(classifyInput(text).kind).toBe('utxos')
    expect(classifyInput(text).utxos).toEqual([
      { txid: TXID, vout: 1 },
      { txid: TXID, vout: 12 },
    ])
  })

  it('tolerates surrounding spaces, blank lines and CRLF', () => {
    const text = `  ${TXID}:0  \r\n\r\n  ${TXID}:3\n`
    const result = classifyInput(text)
    expect(result.kind).toBe('utxos')
    expect(result.utxos).toEqual([
      { txid: TXID, vout: 0 },
      { txid: TXID, vout: 3 },
    ])
  })

  it('accepts uppercase hex and normalizes txid to lowercase', () => {
    const result = classifyInput(`${TXID.toUpperCase()}:5`)
    expect(result.kind).toBe('utxos')
    expect(result.utxos).toEqual([{ txid: TXID, vout: 5 }])
  })

  it('rejects a 63-char txid', () => {
    expect(classifyInput(`${TXID.slice(1)}:0`).kind).toBe('unknown')
  })

  it('rejects when any line is not txid:vout', () => {
    expect(classifyInput(`${TXID}:0\nnot-a-utxo`).kind).toBe('unknown')
  })

  it('rejects non-hex txid', () => {
    expect(classifyInput(`${'z'.repeat(64)}:0`).kind).toBe('unknown')
  })
})

describe('classifyInput: xpub', () => {
  it.each(['xpub', 'ypub', 'zpub', 'tpub', 'upub', 'vpub'])(
    'classifies %s-prefixed keys',
    (prefix) => {
      const key = prefix + XPUB.slice(4)
      expect(classifyInput(key)).toEqual({ kind: 'xpub', value: key })
    }
  )

  it('trims surrounding whitespace and newlines', () => {
    expect(classifyInput(`  ${XPUB}\n`)).toEqual({ kind: 'xpub', value: XPUB })
  })

  it('accepts a derivation suffix like /0/*', () => {
    expect(classifyInput(`${XPUB}/0/*`).kind).toBe('xpub')
  })

  it('rejects invalid base58 characters after the prefix', () => {
    expect(classifyInput(`xpub0OIl${XPUB.slice(8)}`).kind).toBe('unknown')
  })

  it('rejects an implausibly short key', () => {
    expect(classifyInput('xpub123abc').kind).toBe('unknown')
  })
})

describe('classifyInput: descriptor', () => {
  it.each([
    `wpkh(${XPUB}/0/*)`,
    `sh(wpkh(${XPUB}/0/*))`,
    `pkh(${XPUB}/0/*)`,
    `tr(${XPUB}/0/*)`,
    'addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)',
  ])('classifies %s', (desc) => {
    expect(classifyInput(desc)).toEqual({ kind: 'descriptor', value: desc })
  })

  it('classifies a descriptor with key origin and checksum', () => {
    const desc = `wpkh([a1b2c3d4/84h/0h/0h]${XPUB}/0/*)#qwer1234`
    expect(classifyInput(desc).kind).toBe('descriptor')
  })

  it('trims surrounding whitespace', () => {
    const desc = `wpkh(${XPUB})`
    expect(classifyInput(`\n ${desc} `).value).toBe(desc)
  })
})

describe('classifyInput: address', () => {
  it.each([
    'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
    'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',
    'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080',
    '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
    '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
  ])('classifies %s', (addr) => {
    expect(classifyInput(addr)).toEqual({ kind: 'address', value: addr })
  })

  it('classifies an all-uppercase bech32 address', () => {
    expect(classifyInput('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4').kind).toBe('address')
  })

  it('rejects a legacy-looking string with invalid base58 chars', () => {
    expect(classifyInput('1A1zP1eP5QGefi2DMPTfTL5SLmv7D0OIl').kind).toBe('unknown')
  })
})

describe('classifyInput: unknown', () => {
  it.each(['', '   \n  ', 'hello world', 'deadbeef', '42'])(
    'classifies %j as unknown',
    (text) => {
      expect(classifyInput(text).kind).toBe('unknown')
    }
  )

  it('handles null and undefined', () => {
    expect(classifyInput(null).kind).toBe('unknown')
    expect(classifyInput(undefined).kind).toBe('unknown')
  })
})
