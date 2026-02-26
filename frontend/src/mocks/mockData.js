export const mockReport = {
  descriptor: 'wpkh([a1b2c3d4/84h/0h/0h]xpub6CatWdiZynkCminahu8Gmr7FAVnQXBTSMaBxn6qmBNkdm9tDkFzWmjmDrLBCQSTa7BHgpEjCXzMTCyDsQLSmcGYJHBB7cTwpqLNRKGP47uw/0/*)#qwer1234',
  summary: {
    total: 5,
    clean: 1,
    vulnerable: 4,
  },
  utxos: [
    {
      txid: '3a7f2b8c1d4e9f0a6b5c2d7e8f3a1b4c9d2e5f0a7b8c1d4e9f2a5b6c3d7e8f1',
      vout: 0,
      address: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
      amountBtc: 0.05234891,
      confirmations: 1842,
      vulnerabilities: [],
    },
    {
      txid: 'b4c8e2f6a1d5b9c3e7f1a5d9b3c7e1f5a9d3b7c1e5f9a3d7b1c5e9f3a7d1b5',
      vout: 1,
      address: 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
      amountBtc: 0.00023000,
      confirmations: 312,
      vulnerabilities: [
        {
          type: 'DUST_SPEND',
          severity: 'medium',
          description:
            'This UTXO is near the dust threshold. Spending it may cost more in fees than its value, and dust outputs are often used as tracking vectors by chain surveillance companies.',
        },
        {
          type: 'ADDRESS_REUSE',
          severity: 'high',
          description:
            'This address has received funds in 3 separate transactions. Address reuse breaks the one-time-address privacy model and allows observers to link all deposits to the same wallet.',
        },
      ],
    },
    {
      txid: 'f9e3d7c1b5a9f3d7c1b5a9f3d7c1b5a9f3d7c1b5a9f3d7c1b5a9f3d7c1b5a9',
      vout: 0,
      address: 'bc1q9h7garjcdkl4h5khfz2yxkhsmhep5j7g4cjtch',
      amountBtc: 0.12000000,
      confirmations: 4521,
      vulnerabilities: [
        {
          type: 'CONSOLIDATION',
          severity: 'medium',
          description:
            'This UTXO was created by consolidating 7 inputs in a single transaction. Consolidation reveals that all input addresses belong to the same wallet, reducing privacy significantly.',
        },
      ],
    },
    {
      txid: '2c6e0a4f8b2d6e0a4f8b2d6e0a4f8b2d6e0a4f8b2d6e0a4f8b2d6e0a4f8b2d',
      vout: 2,
      address: 'bc1qm34mqf4vn8f5vhf0q3djg2zuzfm9aap6e3n4j',
      amountBtc: 0.87654321,
      confirmations: 98,
      vulnerabilities: [
        {
          type: 'CIOH',
          severity: 'high',
          description:
            'Common Input Ownership Heuristic (CIOH): this UTXO was spent alongside UTXOs from different derivation paths in the same transaction, strongly suggesting to analysts that all inputs share a common owner.',
        },
        {
          type: 'ADDRESS_REUSE',
          severity: 'high',
          description:
            'This address appears in 5 transactions as both sender and receiver, a pattern that severely compromises wallet privacy and makes cluster analysis trivial.',
        },
      ],
    },
    {
      txid: '7d1b5e9f3a7d1b5e9f3a7d1b5e9f3a7d1b5e9f3a7d1b5e9f3a7d1b5e9f3a7d',
      vout: 0,
      address: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8zeqchgx',
      amountBtc: 0.00500000,
      confirmations: 2103,
      vulnerabilities: [
        {
          type: 'DUST_SPEND',
          severity: 'low',
          description:
            'A small dust amount was received at this address in a prior transaction. While the dust has not been spent, its presence could be used to track this UTXO if included in a future transaction.',
        },
      ],
    },
  ],
}
