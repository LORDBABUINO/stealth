// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import ErrorBoundary from './ErrorBoundary'

afterEach(cleanup)

function Bomb() {
  throw new Error('boom')
}

function renderQuietly(ui) {
  const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
  const result = render(ui)
  spy.mockRestore()
  return result
}

describe('ErrorBoundary', () => {
  it('renders children when nothing throws', () => {
    render(<ErrorBoundary><div>all good</div></ErrorBoundary>)
    expect(screen.getByText('all good')).toBeTruthy()
  })

  it('contains a throwing child and shows the fallback', () => {
    renderQuietly(<ErrorBoundary><Bomb /></ErrorBoundary>)
    expect(screen.getByText(/something went wrong/i)).toBeTruthy()
    expect(screen.getByRole('button', { name: /back to input/i })).toBeTruthy()
  })

  it('calls onReset when the back button is clicked', () => {
    const onReset = vi.fn()
    renderQuietly(<ErrorBoundary onReset={onReset}><Bomb /></ErrorBoundary>)
    fireEvent.click(screen.getByRole('button', { name: /back to input/i }))
    expect(onReset).toHaveBeenCalled()
  })
})
