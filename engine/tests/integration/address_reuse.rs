use crate::common::*;

// ─── 1. Address Reuse ───────────────────────────────────────────────────────

#[test]
fn detect_address_reuse() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client.send_to_address(&ba, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    // Reuse the same alice address twice
    let reused = alice.new_address().unwrap();
    bob.send_to_address(&reused, Amount::from_sat(1_000_000))
        .unwrap();
    bob.send_to_address(&reused, Amount::from_sat(2_000_000))
        .unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::AddressReuse));
}
