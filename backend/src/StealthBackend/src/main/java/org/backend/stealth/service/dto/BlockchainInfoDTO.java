package org.backend.stealth.service.dto;

/**
 * DTO for blockchain information
 */
public record BlockchainInfoDTO(
    String network,
    long height,
    String latestBlockHash,
    String esploraUrl
) {
}

