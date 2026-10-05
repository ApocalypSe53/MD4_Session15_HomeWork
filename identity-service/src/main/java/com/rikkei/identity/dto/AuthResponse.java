package com.rikkei.identity.dto;

public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long accessTokenExpiresIn,   // giây
        long refreshTokenExpiresIn   // giây
) {
}
