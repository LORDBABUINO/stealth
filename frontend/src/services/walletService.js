import { mockReport } from '../mocks/mockData'

export const analyzeWallet = async (descriptor) => {
  await new Promise((r) => setTimeout(r, 4000))
  return mockReport
}
