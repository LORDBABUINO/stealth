package org.backend.stealth.service.dto;

/**
 * DTO for testnet4 connection status
 */
public record Testnet4StatusDTO(
    boolean connected,
    String status,
    long blockHeight,
    String esploraUrl
) {
}

