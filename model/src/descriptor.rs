use bitcoin::base58;

use crate::error::AnalysisError;
use crate::gateway::ResolvedDescriptor;

// BIP-32 canonical and SLIP-132 extended public key version bytes.
const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
const TPUB_VERSION: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];
const YPUB_VERSION: [u8; 4] = [0x04, 0x9d, 0x7c, 0xb2];
const ZPUB_VERSION: [u8; 4] = [0x04, 0xb2, 0x47, 0x46];
const UPUB_VERSION: [u8; 4] = [0x04, 0x4a, 0x52, 0x62];
const VPUB_VERSION: [u8; 4] = [0x04, 0x5f, 0x1c, 0xf6];

// version(4) + depth(1) + fingerprint(4) + child(4) + chain code(32) + key(33)
const EXTENDED_KEY_LEN: usize = 78;

/// Expand a raw scan input into descriptor candidates.
///
/// Bare extended public keys become descriptor templates on the receive
/// chain (`/0/*`): SLIP-132 keys (zpub/ypub/vpub/upub) are re-encoded
/// with the canonical version bytes and mapped to their script type,
/// while ambiguous xpub/tpub keys expand to all common script types.
/// Anything else (descriptors, `addr(...)`, garbage) passes through
/// untouched.
pub fn expand_input(raw: &str) -> Vec<String> {
    let key = raw.trim();
    let payload = match base58::decode_check(key) {
        Ok(bytes) if bytes.len() == EXTENDED_KEY_LEN => bytes,
        _ => return vec![raw.to_owned()],
    };

    let mut version = [0u8; 4];
    version.copy_from_slice(&payload[..4]);

    match version {
        XPUB_VERSION | TPUB_VERSION => vec![
            format!("pkh({key}/0/*)"),
            format!("sh(wpkh({key}/0/*))"),
            format!("wpkh({key}/0/*)"),
            format!("tr({key}/0/*)"),
        ],
        ZPUB_VERSION => vec![format!("wpkh({}/0/*)", recode(&payload, XPUB_VERSION))],
        YPUB_VERSION => vec![format!("sh(wpkh({}/0/*))", recode(&payload, XPUB_VERSION))],
        VPUB_VERSION => vec![format!("wpkh({}/0/*)", recode(&payload, TPUB_VERSION))],
        UPUB_VERSION => vec![format!("sh(wpkh({}/0/*))", recode(&payload, TPUB_VERSION))],
        _ => vec![raw.to_owned()],
    }
}

fn recode(payload: &[u8], version: [u8; 4]) -> String {
    let mut bytes = version.to_vec();
    bytes.extend_from_slice(&payload[4..]);
    base58::encode_check(&bytes)
}

/// Trait for normalizing a raw descriptor string (e.g. via `getdescriptorinfo`).
pub trait DescriptorNormalizer {
    fn normalize(&self, descriptor: &str) -> Result<String, AnalysisError>;
}

/// Normalize raw descriptor strings: strip checksums, infer receive/change
/// pairs (`/0/*` ↔ `/1/*`), deduplicate.
///
/// When a `normalizer` is provided (typically a [`BlockchainGateway`]),
/// each candidate is passed through `getdescriptorinfo` for canonical
/// checksumming.
pub fn normalize_descriptors<N: DescriptorNormalizer + ?Sized>(
    raw_descriptors: &[String],
    derivation_range_end: u32,
    rescan_since: Option<u64>,
    normalizer: &N,
) -> Result<Vec<ResolvedDescriptor>, AnalysisError> {
    let mut resolved = Vec::new();

    for raw in raw_descriptors {
        let without_checksum = raw
            .split('#')
            .next()
            .map(str::trim)
            .unwrap_or_default()
            .to_string();

        if without_checksum.is_empty() {
            return Err(AnalysisError::EmptyDescriptor);
        }

        let candidates = if without_checksum.contains("/0/*") {
            vec![
                (without_checksum.clone(), false),
                (without_checksum.replace("/0/*", "/1/*"), true),
            ]
        } else if without_checksum.contains("/1/*") {
            vec![
                (without_checksum.replace("/1/*", "/0/*"), false),
                (without_checksum.clone(), true),
            ]
        } else {
            vec![(without_checksum.clone(), false)]
        };

        for (candidate, internal) in candidates {
            let normalized = normalizer
                .normalize(&candidate)
                .map_err(|error| match error {
                    AnalysisError::DescriptorNormalization { .. } => error,
                    other => AnalysisError::DescriptorNormalization {
                        descriptor: candidate.clone(),
                        message: other.to_string(),
                    },
                })?;

            let descriptor = ResolvedDescriptor {
                desc: normalized,
                internal,
                active: true,
                range_end: derivation_range_end,
                rescan_since,
            };

            if !resolved.iter().any(|item| item == &descriptor) {
                resolved.push(descriptor);
            }
        }
    }

    Ok(resolved)
}

/// Lightweight descriptor normalization that strips checksums and infers
/// receive/change pairs without calling an RPC normalizer.
///
/// Returns `(descriptor_string, is_internal)` pairs.
pub fn normalize_descriptors_raw(raw_descriptors: &[String]) -> Vec<(String, bool)> {
    let mut result = Vec::new();

    for raw in raw_descriptors {
        let without_checksum = raw
            .split('#')
            .next()
            .map(str::trim)
            .unwrap_or_default()
            .to_string();

        if without_checksum.is_empty() {
            continue;
        }

        let candidates = if without_checksum.contains("/0/*") {
            vec![
                (without_checksum.clone(), false),
                (without_checksum.replace("/0/*", "/1/*"), true),
            ]
        } else if without_checksum.contains("/1/*") {
            vec![
                (without_checksum.replace("/1/*", "/0/*"), false),
                (without_checksum.clone(), true),
            ]
        } else {
            vec![(without_checksum, false)]
        };

        for pair in candidates {
            if !result.contains(&pair) {
                result.push(pair);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    struct IdentityNormalizer;

    impl DescriptorNormalizer for IdentityNormalizer {
        fn normalize(&self, descriptor: &str) -> Result<String, AnalysisError> {
            Ok(descriptor.to_owned())
        }
    }

    #[test]
    fn propagates_rescan_since_to_resolved_descriptors() {
        let raw = vec!["wpkh(xpub/0/*)".to_owned()];
        let resolved = normalize_descriptors(&raw, 99, Some(1234), &IdentityNormalizer).unwrap();
        assert_eq!(resolved.len(), 2);
        assert!(resolved.iter().all(|d| d.rescan_since == Some(1234)));
    }

    #[test]
    fn rescan_since_defaults_to_none() {
        let raw = vec!["addr(bc1qexample)".to_owned()];
        let resolved = normalize_descriptors(&raw, 99, None, &IdentityNormalizer).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].rescan_since, None);
    }

    // ── expand_input ────────────────────────────────────────────────────

    // BIP-32 test vector 1, chain m (public key).
    const BIP32_VECTOR1_XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8Nqtwyb\
                                      GhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
    const TPUB_VERSION: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];
    const YPUB_VERSION: [u8; 4] = [0x04, 0x9d, 0x7c, 0xb2];
    const ZPUB_VERSION: [u8; 4] = [0x04, 0xb2, 0x47, 0x46];
    const UPUB_VERSION: [u8; 4] = [0x04, 0x4a, 0x52, 0x62];
    const VPUB_VERSION: [u8; 4] = [0x04, 0x5f, 0x1c, 0xf6];

    fn reencode(key: &str, version: [u8; 4]) -> String {
        let payload = bitcoin::base58::decode_check(key).unwrap();
        let mut bytes = version.to_vec();
        bytes.extend_from_slice(&payload[4..]);
        bitcoin::base58::encode_check(&bytes)
    }

    #[test]
    fn zpub_expands_to_wpkh_over_canonical_xpub() {
        let zpub = reencode(BIP32_VECTOR1_XPUB, ZPUB_VERSION);
        assert_eq!(
            expand_input(&zpub),
            vec![format!("wpkh({BIP32_VECTOR1_XPUB}/0/*)")]
        );
    }

    #[test]
    fn ypub_expands_to_sh_wpkh_over_canonical_xpub() {
        let ypub = reencode(BIP32_VECTOR1_XPUB, YPUB_VERSION);
        assert_eq!(
            expand_input(&ypub),
            vec![format!("sh(wpkh({BIP32_VECTOR1_XPUB}/0/*))")]
        );
    }

    #[test]
    fn vpub_expands_to_wpkh_over_canonical_tpub() {
        let vpub = reencode(BIP32_VECTOR1_XPUB, VPUB_VERSION);
        let tpub = reencode(BIP32_VECTOR1_XPUB, TPUB_VERSION);
        assert_eq!(expand_input(&vpub), vec![format!("wpkh({tpub}/0/*)")]);
    }

    #[test]
    fn upub_expands_to_sh_wpkh_over_canonical_tpub() {
        let upub = reencode(BIP32_VECTOR1_XPUB, UPUB_VERSION);
        let tpub = reencode(BIP32_VECTOR1_XPUB, TPUB_VERSION);
        assert_eq!(expand_input(&upub), vec![format!("sh(wpkh({tpub}/0/*))")]);
    }

    #[test]
    fn bare_xpub_expands_to_four_script_candidates() {
        let xpub = BIP32_VECTOR1_XPUB;
        assert_eq!(
            expand_input(xpub),
            vec![
                format!("pkh({xpub}/0/*)"),
                format!("sh(wpkh({xpub}/0/*))"),
                format!("wpkh({xpub}/0/*)"),
                format!("tr({xpub}/0/*)"),
            ]
        );
    }

    #[test]
    fn bare_tpub_expands_to_four_script_candidates() {
        let tpub = reencode(BIP32_VECTOR1_XPUB, TPUB_VERSION);
        assert_eq!(
            expand_input(&tpub),
            vec![
                format!("pkh({tpub}/0/*)"),
                format!("sh(wpkh({tpub}/0/*))"),
                format!("wpkh({tpub}/0/*)"),
                format!("tr({tpub}/0/*)"),
            ]
        );
    }

    #[test]
    fn descriptors_pass_through_untouched() {
        let wrapped = format!("wpkh({BIP32_VECTOR1_XPUB}/0/*)#abcd1234");
        assert_eq!(expand_input(&wrapped), vec![wrapped.clone()]);
        assert_eq!(
            expand_input("addr(bc1qexample)"),
            vec!["addr(bc1qexample)".to_owned()]
        );
    }

    #[test]
    fn non_key_inputs_pass_through_untouched() {
        assert_eq!(expand_input("garbage"), vec!["garbage".to_owned()]);

        // Corrupt the checksum: still starts with "xpub" but must not expand.
        let mut corrupted = BIP32_VECTOR1_XPUB.to_owned();
        corrupted.pop();
        corrupted.push('9');
        assert_eq!(expand_input(&corrupted), vec![corrupted.clone()]);

        // Valid base58check but not 78 bytes (a legacy address payload).
        let short = bitcoin::base58::encode_check(&[0x00; 21]);
        assert_eq!(expand_input(&short), vec![short.clone()]);
    }
}
