use crate::common::*;

// ─── Bare extended public key as scan input ─────────────────────────────────

// Extract the first bare tpub from a descriptor string like
// "wpkh([fp/84h/1h/0h]tpubXXX/0/*)#checksum".
fn extract_tpub(descriptor: &str) -> Option<String> {
    let start = descriptor.find("tpub")?;
    let rest = &descriptor[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_alphanumeric())
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

#[test]
fn bare_tpub_scan_finds_wallet_activity() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let aa = alice.new_address().unwrap();
    node.client.send_to_address(&aa, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    // Pull the wallet's external wpkh descriptor and reduce it to a
    // bare tpub with on-chain history.
    let descs = alice
        .call::<serde_json::Value>("listdescriptors", &[])
        .unwrap();
    let tpub = descs["descriptors"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|d| d["desc"].as_str())
        .find(|desc| desc.starts_with("wpkh(") && desc.contains("/0/*"))
        .and_then(extract_tpub)
        .expect("no wpkh external descriptor with a tpub found");

    let gateway = gateway_for(&node);
    let engine = AnalysisEngine::new(&gateway, EngineSettings::default());
    let report = engine
        .analyze(ScanTarget::Descriptor(tpub))
        .expect("bare tpub scan failed");

    assert!(
        report.stats.transactions_analyzed >= 1,
        "expected the wpkh candidate to find the funding tx, got {}",
        report.stats.transactions_analyzed
    );
}
