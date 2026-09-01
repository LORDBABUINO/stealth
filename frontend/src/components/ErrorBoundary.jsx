import { Component } from 'react'
import styles from './ErrorBoundary.module.css'

export default class ErrorBoundary extends Component {
  state = { hasError: false }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error, info) {
    console.error('Render error:', error, info)
  }

  handleReset = () => {
    this.setState({ hasError: false })
    this.props.onReset?.()
  }

  render() {
    if (!this.state.hasError) return this.props.children
    return (
      <div className={styles.root}>
        <p className={styles.message}>Something went wrong.</p>
        <button type="button" className={styles.button} onClick={this.handleReset}>
          Back to input
        </button>
      </div>
    )
  }
}
