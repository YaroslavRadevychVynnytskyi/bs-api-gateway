package com.application.bsapigateway.dto.api.response;

import com.application.bsapigateway.dto.api.generic.Role;
import java.util.Set;

public record UserResponseDto(
        Long id,
        String email,
        String firstName,
        String lastName,
        String shippingAddress,
        Set<Role> roles
) {
}
