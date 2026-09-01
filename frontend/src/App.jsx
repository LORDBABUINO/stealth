import { useState } from 'react'
import InputScreen from './screens/InputScreen'
import LoadingScreen from './screens/LoadingScreen'
import ReportScreen from './screens/ReportScreen'
import ErrorBoundary from './components/ErrorBoundary'
import { analyzeWallet } from './services/walletService'

export default function App() {
  const [screen, setScreen] = useState('input')
  const [scan, setScan] = useState(null)
  const [report, setReport] = useState(null)

  async function handleAnalyze(nextScan) {
    setScan(nextScan)
    setScreen('loading')
    try {
      const result = await analyzeWallet(nextScan.body)
      setReport(result)
      setScreen('report')
    } catch (err) {
      console.error('Analysis failed:', err)
      setScreen('input')
    }
  }

  function handleReset() {
    setScreen('input')
    setScan(null)
    setReport(null)
  }

  function renderScreen() {
    if (screen === 'loading') return <LoadingScreen text={scan?.text} kind={scan?.kind} />
    if (screen === 'report') return <ReportScreen report={report} descriptor={scan?.text} onReset={handleReset} />
    return <InputScreen onAnalyze={handleAnalyze} />
  }

  return <ErrorBoundary onReset={handleReset}>{renderScreen()}</ErrorBoundary>
}
