package com.rikkei.gateway.filter;

import com.rikkei.gateway.security.JwtValidator;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthenticationFilterTest {

    private static final String SECRET =
            "dGhpcy1pcy1hLXZlcnktc2VjcmV0LWtleS1mb3ItaWRlbnRpdHktc2VydmljZS1oczI1Ng==";
    private static final String OTHER_SECRET =
            "YW5vdGhlci1zZWNyZXQta2V5LXRoYXQtaXMtYXQtbGVhc3QtMjU2LWJpdHMtbG9uZyEhIQ==";

    private JwtAuthenticationFilter filter;
    private AtomicReference<ServerWebExchange> forwarded;
    private GatewayFilterChain chain;

    @BeforeEach
    void setUp() {
        filter = new JwtAuthenticationFilter(new JwtValidator(SECRET), List.of("/api/auth/**"));
        forwarded = new AtomicReference<>();
        chain = exchange -> {
            forwarded.set(exchange);
            return Mono.empty();
        };
    }

    @Test
    void missingToken_returns401() {
        MockServerWebExchange exchange = exchange(null);

        filter.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(forwarded.get()).isNull();
    }

    @Test
    void expiredToken_returns401() {
        MockServerWebExchange exchange = exchange(token(SECRET, -60_000));

        filter.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getBodyAsString().block()).contains("hết hạn");
        assertThat(forwarded.get()).isNull();
    }

    @Test
    void wrongSignature_returns401() {
        MockServerWebExchange exchange = exchange(token(OTHER_SECRET, 900_000));

        filter.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(forwarded.get()).isNull();
    }

    @Test
    void validToken_addsRoleHeader_andOverridesSpoofedValue() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/courses")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(SECRET, 900_000))
                        .header(JwtAuthenticationFilter.USER_ROLE_HEADER, "ADMIN"));

        filter.filter(exchange, chain).block();

        assertThat(forwarded.get()).isNotNull();
        assertThat(forwarded.get().getRequest().getHeaders().get(JwtAuthenticationFilter.USER_ROLE_HEADER))
                .containsExactly("STUDENT");
    }

    @Test
    void publicPath_passesWithoutToken() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/auth/login"));

        filter.filter(exchange, chain).block();

        assertThat(forwarded.get()).isNotNull();
    }

    private static MockServerWebExchange exchange(String token) {
        MockServerHttpRequest.BaseBuilder<?> builder = MockServerHttpRequest.get("/api/courses");
        if (token != null) {
            builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }
        return MockServerWebExchange.from(builder);
    }

    private static String token(String secret, long ttlMs) {
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        Date now = new Date();
        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject("student01")
                .claim("role", "STUDENT")
                .setIssuedAt(new Date(now.getTime() - 120_000))
                .setExpiration(new Date(now.getTime() + ttlMs))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
}
