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
    let da = node.client.new_address().expect("miner address");
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").expect("create alice wallet");
    let aa = alice.new_address().expect("alice address");
    node.client
        .send_to_address(&aa, Amount::ONE_BTC)
        .expect("fund alice");
    mine(&node, 1, &da);

    // Pull the wallet's external wpkh descriptor and reduce it to a
    // bare tpub with on-chain history.
    let descs = alice
        .call::<serde_json::Value>("listdescriptors", &[])
        .expect("listdescriptors");
    let tpub = descs["descriptors"]
        .as_array()
        .expect("descriptors array")
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

// ─── Private key inputs must never leak ─────────────────────────────────────

#[test]
fn xprv_input_is_rejected_without_leaking_the_key() {
    // BIP-32 test vector 1 private key (published spec constant).
    let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jP\
                PqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    // Rejection must happen before any RPC call, so an unreachable
    // gateway is enough.
    let gateway =
        BitcoinCoreRpc::from_url("http://127.0.0.1:1", None, None).expect("offline gateway handle");
    let engine = AnalysisEngine::new(&gateway, EngineSettings::default());
    let error = engine
        .analyze(ScanTarget::Descriptor(xprv.to_owned()))
        .expect_err("private key input must be rejected");

    let message = error.to_string();
    assert!(
        !message.contains(xprv),
        "private key leaked into error: {message}"
    );
    assert!(message.contains("private key"), "{message}");
}
