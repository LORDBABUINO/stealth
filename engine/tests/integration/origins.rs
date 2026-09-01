use crate::common::*;

// ─── 6. Consolidation Origin ───────────────────────────────────────────────

#[test]
fn detect_consolidation() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice 4 small UTXOs
    for _ in 0..4 {
        let a = alice.new_address().unwrap();
        bob.send_to_address(&a, Amount::from_sat(300_000)).unwrap();
    }
    mine(&node, 1, &da);

    // Alice consolidates into one address (>=3 inputs, <=2 outputs)
    let utxos = alice.list_unspent().unwrap();
    let small: Vec<_> = utxos
        .0
        .iter()
        .filter(|u| u.amount > 0.002 && u.amount < 0.004)
        .collect();
    assert!(small.len() >= 3, "need at least 3 small utxos");

    let inputs: Vec<Input> = small
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total_sats: u64 = small.iter().map(|u| (u.amount * 1e8).round() as u64).sum();
    let consol_addr = alice.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[Output::new(
                consol_addr,
                Amount::from_sat(total_sats - 10_000),
            )],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::Consolidation));
}

// ─── 10. Exchange Origin ───────────────────────────────────────────────────

#[test]
fn detect_exchange_origin() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let exchange = node.create_wallet("exchange").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    // Fund exchange
    let ea = exchange.new_address().unwrap();
    node.client
        .send_to_address(&ea, Amount::from_btc(5.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Exchange batch withdrawal to 8 addresses (alice gets some, bob gets some)
    let mut amounts: BTreeMap<Address, Amount> = BTreeMap::new();
    for i in 0..5u64 {
        let a = alice.new_address().unwrap();
        amounts.insert(a, Amount::from_sat(1_000_000 + i * 100_000));
    }
    for i in 0..3u64 {
        let b = bob.new_address().unwrap();
        amounts.insert(b, Amount::from_sat(1_000_000 + i * 200_000));
    }
    let send_result = exchange.send_many(amounts).unwrap();
    mine(&node, 1, &da);

    let exchange_txids: HashSet<Txid> = [send_result.0.parse::<Txid>().unwrap()]
        .into_iter()
        .collect();
    let gateway = gateway_for(&node);
    let report = scan_wallet_with(&gateway, "alice", None, Some(&exchange_txids));
    assert!(has_finding(&report, VulnerabilityType::ExchangeOrigin));
}

// ─── 11. Tainted UTXOs ─────────────────────────────────────────────────────

#[test]
fn detect_tainted_utxo_merge() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let risky = node.create_wallet("risky").unwrap();
    let bob = node.create_wallet("bob").unwrap();

    // Fund
    let ra = risky.new_address().unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ra, Amount::from_btc(2.0).unwrap())
        .unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Risky sends to alice
    let ta = alice.new_address().unwrap();
    let taint_result = risky
        .send_to_address(&ta, Amount::from_sat(1_000_000))
        .unwrap();
    let taint_txid: Txid = taint_result.0.parse().unwrap();

    // Bob sends clean to alice
    let ca = alice.new_address().unwrap();
    bob.send_to_address(&ca, Amount::from_sat(1_000_000))
        .unwrap();
    mine(&node, 1, &da);

    // Alice spends both together (tainted + clean)
    let utxos = alice.list_unspent().unwrap();
    assert!(utxos.0.len() >= 2);

    let inputs: Vec<Input> = utxos
        .0
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total_sats: u64 = utxos
        .0
        .iter()
        .map(|u| (u.amount * 1e8).round() as u64)
        .sum();
    let carol = node.create_wallet("carol").unwrap();
    let dest = carol.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[Output::new(dest, Amount::from_sat(total_sats - 10_000))],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let risky_txids: HashSet<Txid> = [taint_txid].into_iter().collect();
    let gateway = gateway_for(&node);
    let report = scan_wallet_with(&gateway, "alice", Some(&risky_txids), None);
    assert!(has_finding(&report, VulnerabilityType::TaintedUtxoMerge));
}
