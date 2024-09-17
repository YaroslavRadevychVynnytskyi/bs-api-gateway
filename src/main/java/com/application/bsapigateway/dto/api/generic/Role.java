package com.application.bsapigateway.dto.api.generic;

import lombok.Data;

@Data
public class Role {
    private Long id;
    private RoleName name;

    public enum RoleName {
        ADMIN,
        USER
    }
}
