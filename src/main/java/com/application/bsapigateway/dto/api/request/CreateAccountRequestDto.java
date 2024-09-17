package com.application.bsapigateway.dto.api.request;

public record CreateAccountRequestDto(
        String username,
        String email,
        String password
) {
}
