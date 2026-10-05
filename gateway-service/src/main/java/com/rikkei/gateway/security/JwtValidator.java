package com.rikkei.gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;

@Component
public class JwtValidator {

    private final Key signingKey;

    /** Dùng chung Secret Key (Base64) với Identity Service */
    public JwtValidator(@Value("${jwt.secret}") String secret) {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    /**
     * Xác thực chữ ký + hạn dùng và trả về payload.
     *
     * @throws io.jsonwebtoken.ExpiredJwtException nếu token đã hết hạn
     * @throws io.jsonwebtoken.JwtException        nếu sai chữ ký / sai định dạng
     */
    public Claims validate(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
