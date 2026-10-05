package com.rikkei.identity.dto;

import jakarta.validation.constraints.NotBlank;

public record RefreshRequest(
        @NotBlank(message = "refreshToken không được để trống") String refreshToken
) {
}
