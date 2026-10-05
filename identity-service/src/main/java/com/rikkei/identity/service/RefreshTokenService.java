package com.rikkei.identity.service;

import com.rikkei.identity.entity.RefreshToken;
import com.rikkei.identity.entity.User;
import com.rikkei.identity.exception.InvalidRefreshTokenException;
import com.rikkei.identity.repository.RefreshTokenRepository;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

@Slf4j
@Service
public class RefreshTokenService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final RefreshTokenRepository refreshTokenRepository;

    @Getter
    private final long refreshTokenExpirationMs;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
                               @Value("${jwt.refresh-token-expiration-ms}") long refreshTokenExpirationMs) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.refreshTokenExpirationMs = refreshTokenExpirationMs;
    }

    /** Sinh chuỗi ngẫu nhiên (64 byte, base64url) sống 7 ngày và lưu vào bảng refresh_tokens */
    public RefreshToken createRefreshToken(User user) {
        RefreshToken refreshToken = RefreshToken.builder()
                .token(generateRandomToken())
                .user(user)
                .expiryDate(Instant.now().plusMillis(refreshTokenExpirationMs))
                .revoked(false)
                .build();
        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Token Rotation: kiểm tra token cũ, đánh dấu đã dùng (revoked) rồi cấp Refresh Token mới.
     * <p>
     * Nếu một token ĐÃ bị xoay vòng lại được gửi lên (reuse) -> nhiều khả năng token đã bị đánh cắp,
     * nên thu hồi luôn mọi Refresh Token còn hiệu lực của user đó, buộc đăng nhập lại.
     * noRollbackFor để việc thu hồi này vẫn được commit dù method ném exception.
     */
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public RefreshToken rotate(String token) {
        RefreshToken current = refreshTokenRepository.findByTokenForUpdate(token)
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh Token không tồn tại"));

        if (current.isRevoked()) {
            int revoked = refreshTokenRepository.revokeAllByUser(current.getUser());
            log.warn("Refresh Token reuse detected for user '{}' -> revoked {} active token(s)",
                    current.getUser().getUsername(), revoked);
            throw new InvalidRefreshTokenException("Refresh Token đã được sử dụng (đã bị xoay vòng)");
        }

        if (current.getExpiryDate().isBefore(Instant.now())) {
            throw new InvalidRefreshTokenException("Refresh Token đã hết hạn, vui lòng đăng nhập lại");
        }

        current.setRevoked(true);   // đánh dấu đã dùng -> không thể dùng lại
        return createRefreshToken(current.getUser());
    }

    private static String generateRandomToken() {
        byte[] bytes = new byte[64];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
