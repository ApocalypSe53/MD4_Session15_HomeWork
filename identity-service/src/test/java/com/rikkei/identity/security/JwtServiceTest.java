package com.rikkei.identity.security;

import com.rikkei.identity.entity.Role;
import com.rikkei.identity.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceTest {

    private static final String SECRET =
            "dGhpcy1pcy1hLXZlcnktc2VjcmV0LWtleS1mb3ItaWRlbnRpdHktc2VydmljZS1oczI1Ng==";

    private final JwtService jwtService = new JwtService(SECRET, 900_000);

    @Test
    void accessTokenContainsSubRoleJtiAndExpiresIn15Minutes() {
        User user = User.builder().username("student01").role(Role.STUDENT).build();

        String token = jwtService.generateAccessToken(user);
        Claims claims = jwtService.parseClaims(token);

        assertThat(claims.getSubject()).isEqualTo("student01");
        assertThat(claims.get("role", String.class)).isEqualTo("STUDENT");
        assertThat(claims.getId()).isNotBlank();
        assertThat(claims.getExpiration().getTime() - claims.getIssuedAt().getTime()).isEqualTo(900_000);

        String header = new String(Base64.getUrlDecoder().decode(token.split("\\.")[0]));
        assertThat(header).contains("\"alg\":\"HS256\"");
    }

    @Test
    void eachTokenHasUniqueJti() {
        User user = User.builder().username("instructor01").role(Role.INSTRUCTOR).build();

        String jti1 = jwtService.parseClaims(jwtService.generateAccessToken(user)).getId();
        String jti2 = jwtService.parseClaims(jwtService.generateAccessToken(user)).getId();

        assertThat(jti1).isNotEqualTo(jti2);
    }
}
