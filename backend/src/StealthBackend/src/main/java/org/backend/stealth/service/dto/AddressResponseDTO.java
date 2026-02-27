package org.backend.stealth.service.dto;

/**
 * DTO for address response with instructions
 */
public record AddressResponseDTO(
    String address,
    String instructions
) {
}

