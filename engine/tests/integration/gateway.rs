use crate::common::*;

use stealth_engine::gateway::ResolvedDescriptor;

// ─── Non-ranged descriptor derivation ──────────────────────────────────────

#[test]
fn scan_descriptors_derives_addresses_for_unranged_addr_descriptor() {
    let node = node();
    let da = node.client.new_address().expect("default address");
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").expect("create alice");
    let aa = alice.new_address().expect("alice address");
    node.client
        .send_to_address(&aa, Amount::ONE_BTC)
        .expect("fund alice");
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let desc = gateway
        .normalize_descriptor(&format!("addr({aa})"))
        .expect("normalize addr descriptor");
    let resolved = ResolvedDescriptor {
        desc,
        internal: false,
        active: true,
        range_end: 999,
        rescan_since: None,
    };

    let history = gateway
        .scan_descriptors(&[resolved])
        .expect("scan_descriptors");

    assert!(
        !history.wallet_txs.is_empty(),
        "funding tx must be visible to the descriptor scan"
    );
    let expected = aa
        .to_string()
        .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
        .expect("parse alice address");
    assert!(
        history.derived_addresses.contains(&expected),
        "derived_addresses must contain the addr() descriptor address, got: {:?}",
        history.derived_addresses
    );
}

// ─── listtransactions pagination ───────────────────────────────────────────

#[test]
fn list_transactions_paginates_beyond_page_size() {
    let node = node();
    let da = node.client.new_address().expect("default address");
    mine(&node, 110, &da);

    let bob = node.create_wallet("bob").expect("create bob");
    for _ in 0..12 {
        let ba = bob.new_address().expect("bob address");
        node.client
            .send_to_address(&ba, Amount::from_sat(100_000))
            .expect("fund bob");
    }
    mine(&node, 1, &da);

    let gateway = gateway_for(&node).with_tx_page_size(5);
    let history = gateway.scan_wallet("bob").expect("scan_wallet");

    assert_eq!(
        history.wallet_txs.len(),
        12,
        "all wallet transactions must be returned across pages"
    );
    let unique: HashSet<Txid> = history.wallet_txs.iter().map(|entry| entry.txid).collect();
    assert_eq!(unique.len(), 12, "pages must not duplicate transactions");
}
