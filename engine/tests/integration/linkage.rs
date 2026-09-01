use crate::common::*;

// ─── 2. Common Input Ownership Heuristic (CIOH) ────────────────────────────

#[test]
fn detect_cioh() {
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

    // Give alice multiple small UTXOs (each to a different address)
    for _ in 0..5 {
        let a = alice.new_address().unwrap();
        bob.send_to_address(&a, Amount::from_sat(500_000)).unwrap();
    }
    mine(&node, 1, &da);

    // Alice consolidates them into one tx (multi-input -> CIOH)
    let utxos = alice.list_unspent().unwrap();
    let small: Vec<_> = utxos.0.iter().filter(|u| u.amount < 0.006).collect();
    assert!(small.len() >= 2, "need at least 2 small utxos");

    let inputs: Vec<Input> = small
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total_sats: u64 = small.iter().map(|u| (u.amount * 1e8).round() as u64).sum();
    let fee_sats: u64 = 10_000;
    let dest = bob.new_address().unwrap();
    let outputs = vec![Output::new(dest, Amount::from_sat(total_sats - fee_sats))];

    let raw = alice.create_raw_transaction(&inputs, &outputs).unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    assert!(signed.complete);
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::Cioh));
}

// ─── 8. Cluster Merge ──────────────────────────────────────────────────────

#[test]
fn detect_cluster_merge() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let carol = node.create_wallet("carol").unwrap();
    // Fund bob and carol
    let ba = bob.new_address().unwrap();
    let ca = carol.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    node.client
        .send_to_address(&ca, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Bob sends to alice_addr_1, Carol sends to alice_addr_2
    let a1 = alice.new_address().unwrap();
    let a2 = alice.new_address().unwrap();
    bob.send_to_address(&a1, Amount::from_sat(400_000)).unwrap();
    carol
        .send_to_address(&a2, Amount::from_sat(400_000))
        .unwrap();
    mine(&node, 1, &da);

    // Alice spends both together -> cluster merge
    let utxos = alice.list_unspent().unwrap();
    assert!(utxos.0.len() >= 2, "need at least 2 utxos");

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
    let dest = bob.new_address().unwrap();
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

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::ClusterMerge));
}

// ─── 15. Deterministic Link Detection ──────────────────────────────────────

#[test]
fn detect_deterministic_links() {
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

    // Give alice two UTXOs: 700k and 400k sats
    let a1 = alice.new_address().unwrap();
    let a2 = alice.new_address().unwrap();
    bob.send_to_address(&a1, Amount::from_sat(700_000)).unwrap();
    bob.send_to_address(&a2, Amount::from_sat(400_000)).unwrap();
    mine(&node, 1, &da);

    // Alice spends both into two outputs: 600k and 400k.
    // Only one valid interpretation: 700k→600k, 400k→400k
    // (400k < 600k so it can't fund the 600k output = deterministic link)
    let utxos = alice.list_unspent().unwrap();
    let inputs: Vec<Input> = utxos
        .0
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();

    let dest1 = bob.new_address().unwrap();
    let dest2 = bob.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[
                Output::new(dest1, Amount::from_sat(600_000)),
                Output::new(dest2, Amount::from_sat(400_000)),
            ],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::DeterministicLink));
}

// ─── 16. Unnecessary Input Detection ───────────────────────────────────────

#[test]
fn detect_unnecessary_input() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(3.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice a big UTXO (1 BTC) and a small UTXO (0.01 BTC)
    let a1 = alice.new_address().unwrap();
    let a2 = alice.new_address().unwrap();
    bob.send_to_address(&a1, Amount::from_btc(1.0).unwrap())
        .unwrap();
    bob.send_to_address(&a2, Amount::from_sat(1_000_000))
        .unwrap();
    mine(&node, 1, &da);

    // Alice sends 0.005 BTC (500k sats) using BOTH inputs — unnecessary
    // because the 1 BTC input alone is enough
    let utxos = alice.list_unspent().unwrap();
    let inputs: Vec<Input> = utxos
        .0
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    assert!(inputs.len() >= 2);

    let total_sats: u64 = utxos
        .0
        .iter()
        .map(|u| (u.amount * 1e8).round() as u64)
        .sum();
    let payment_sats: u64 = 500_000;
    let fee_sats: u64 = 10_000;
    let change_sats = total_sats - payment_sats - fee_sats;

    let dest = bob.new_address().unwrap();
    let change_addr = alice.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[
                Output::new(dest, Amount::from_sat(payment_sats)),
                Output::new(change_addr, Amount::from_sat(change_sats)),
            ],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::UnnecessaryInput));
}
