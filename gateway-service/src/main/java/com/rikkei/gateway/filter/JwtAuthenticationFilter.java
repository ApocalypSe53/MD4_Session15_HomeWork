package com.rikkei.gateway.filter;

import com.rikkei.gateway.security.JwtValidator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

/**
 * "Trạm gác biên phòng": mọi request đi qua Gateway (trừ public-paths) phải mang
 * Access Token hợp lệ trong header Authorization: Bearer &lt;token&gt;.
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    public static final String USER_ROLE_HEADER = "X-User-Role";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtValidator jwtValidator;
    private final List<String> publicPaths;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public JwtAuthenticationFilter(JwtValidator jwtValidator,
                                   @Value("${jwt.public-paths:}") List<String> publicPaths) {
        this.jwtValidator = jwtValidator;
        this.publicPaths = publicPaths;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();

        if (isPublic(path)) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (!StringUtils.hasText(authHeader) || !authHeader.startsWith(BEARER_PREFIX)) {
            return unauthorized(exchange, "Thiếu Access Token (Authorization: Bearer <token>)");
        }

        Claims claims;
        try {
            claims = jwtValidator.validate(authHeader.substring(BEARER_PREFIX.length()).trim());
        } catch (ExpiredJwtException e) {
            return unauthorized(exchange, "Access Token đã hết hạn");
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Invalid JWT on {}: {}", path, e.getMessage());
            return unauthorized(exchange, "Access Token không hợp lệ (sai chữ ký hoặc sai định dạng)");
        }

        String role = claims.get("role", String.class);
        if (!StringUtils.hasText(role)) {
            return unauthorized(exchange, "Access Token không chứa claim role");
        }

        // set() ghi đè -> client không thể tự gửi X-User-Role giả mạo xuống Course-Service
        ServerHttpRequest mutatedRequest = request.mutate()
                .headers(h -> h.set(USER_ROLE_HEADER, role))
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    /** Chạy sớm nhất trong chuỗi filter để chặn request không hợp lệ ngay từ đầu */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    private boolean isPublic(String path) {
        return publicPaths.stream().anyMatch(p -> pathMatcher.match(p, path));
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String body = """
                {"timestamp":"%s","status":401,"error":"Unauthorized","message":"%s","path":"%s"}"""
                .formatted(Instant.now(), message, exchange.getRequest().getPath().value());
        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }
}
