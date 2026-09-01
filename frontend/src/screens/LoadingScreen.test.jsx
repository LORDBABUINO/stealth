// @vitest-environment jsdom
import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import LoadingScreen from './LoadingScreen'

afterEach(cleanup)

const NOTE = /Scanning the chain for your wallet's history\. This can take a few minutes\./i

describe('LoadingScreen', () => {
  it('shows the chain-scan note for descriptor scans', () => {
    render(<LoadingScreen text="wpkh(abc)" kind="descriptor" />)
    expect(screen.getByText(NOTE)).toBeTruthy()
  })

  it('shows the chain-scan note for xpub scans', () => {
    render(<LoadingScreen text="xpub6C..." kind="xpub" />)
    expect(screen.getByText(NOTE)).toBeTruthy()
  })

  it('does not show the note for utxo scans', () => {
    render(<LoadingScreen text="deadbeef:0" kind="utxos" />)
    expect(screen.queryByText(NOTE)).toBeNull()
  })

  it('shows the truncated input text', () => {
    render(<LoadingScreen text={'a'.repeat(60)} kind="descriptor" />)
    expect(screen.getByText(`${'a'.repeat(48)}…`)).toBeTruthy()
  })
})
