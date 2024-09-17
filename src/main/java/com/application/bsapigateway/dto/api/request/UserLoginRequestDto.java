package com.application.bsapigateway.dto.api.request;

public record UserLoginRequestDto(
        String email,
        String password
) {
}
