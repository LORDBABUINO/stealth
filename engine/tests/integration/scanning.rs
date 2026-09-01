use crate::common::*;

// ─── Full Report Smoke Test ─────────────────────────────────────────────────

#[test]
fn full_report_generates() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let aa = alice.new_address().unwrap();
    node.client.send_to_address(&aa, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");

    assert_eq!(
        report.summary.findings + report.summary.warnings,
        report.findings.len() + report.warnings.len()
    );
    assert_eq!(report.stats.utxos_current, 1);
}

// ─── Descriptor rescan_since ───────────────────────────────────────────────

#[test]
fn descriptor_scan_honors_rescan_since() {
    let node = node();
    let da = node.client.new_address().unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let one_year_ago = now - 365 * 24 * 3600;

    // Mine the funding history with year-old block timestamps so a later
    // rescan_since cutoff has something to exclude. Funding carol via a
    // coinbase avoids needing spendable balance under mocktime.
    node.client
        .call::<serde_json::Value>("setmocktime", &[serde_json::json!(one_year_ago)])
        .unwrap();
    mine(&node, 100, &da);

    let carol = node.create_wallet("carol").unwrap();
    let ca = carol.new_address().unwrap();
    mine(&node, 1, &ca);

    // Back to the present for the chain tip.
    node.client
        .call::<serde_json::Value>("setmocktime", &[serde_json::json!(now)])
        .unwrap();
    mine(&node, 10, &da);

    let gateway = gateway_for(&node);
    let descriptor = format!("addr({ca})");

    // Default full rescan sees the funding transaction.
    let engine = AnalysisEngine::new(&gateway, EngineSettings::default());
    let report = engine
        .analyze(ScanTarget::Descriptor(descriptor.clone()))
        .unwrap();
    assert!(report.stats.transactions_analyzed >= 1);

    // A cutoff between the funding time and the tip excludes the old tx.
    let settings = EngineSettings {
        rescan_since: Some(now - 30 * 24 * 3600),
        ..EngineSettings::default()
    };
    let engine = AnalysisEngine::new(&gateway, settings);
    let report = engine.analyze(ScanTarget::Descriptor(descriptor)).unwrap();
    assert_eq!(report.stats.transactions_analyzed, 0);
}

// ─── Ancestor depth bound ──────────────────────────────────────────────────

#[test]
fn ancestor_walk_is_bounded_by_max_depth() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    // Build a linear 5-tx chain: bob funds himself repeatedly, then pays
    // alice. Bob always holds exactly one UTXO, so each send spends the
    // previous transaction's output.
    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client.send_to_address(&ba, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    for _ in 0..3 {
        let next = bob.new_address().unwrap();
        bob.call::<serde_json::Value>("sendall", &[serde_json::json!([next.to_string()])])
            .unwrap();
        mine(&node, 1, &da);
        let utxos = bob.list_unspent().unwrap();
        assert_eq!(utxos.0.len(), 1, "bob must stay at a single utxo");
    }

    let aa = alice.new_address().unwrap();
    bob.call::<serde_json::Value>("sendall", &[serde_json::json!([aa.to_string()])])
        .unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let history = gateway.scan_wallet("alice").unwrap();

    // Alice's tx (depth 0) + parent (1) + grandparent (2). The two
    // older ancestors of the chain must not be fetched.
    assert_eq!(history.transactions.len(), 3);
}
