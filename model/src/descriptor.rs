use crate::error::AnalysisError;
use crate::gateway::ResolvedDescriptor;

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
}
