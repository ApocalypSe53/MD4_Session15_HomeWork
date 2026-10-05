package com.rikkei.identity.service;

import com.rikkei.identity.dto.AuthResponse;
import com.rikkei.identity.dto.LoginRequest;
import com.rikkei.identity.dto.RefreshRequest;
import com.rikkei.identity.entity.RefreshToken;
import com.rikkei.identity.entity.User;
import com.rikkei.identity.exception.InvalidRefreshTokenException;
import com.rikkei.identity.repository.UserRepository;
import com.rikkei.identity.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Transactional
    public AuthResponse login(LoginRequest request) {
        // DaoAuthenticationProvider dùng BCryptPasswordEncoder.matches() so sánh mật khẩu thô với hash trong DB.
        // Sai username/password -> ném BadCredentialsException.
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));

        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new BadCredentialsException("Bad credentials"));

        return issueTokens(user, refreshTokenService.createRefreshToken(user));
    }

    /** Đổi Refresh Token cũ lấy cặp Access + Refresh Token hoàn toàn mới (Token Rotation) */
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public AuthResponse refresh(RefreshRequest request) {
        RefreshToken newRefreshToken = refreshTokenService.rotate(request.refreshToken());
        return issueTokens(newRefreshToken.getUser(), newRefreshToken);
    }

    private AuthResponse issueTokens(User user, RefreshToken refreshToken) {
        return new AuthResponse(
                jwtService.generateAccessToken(user),
                refreshToken.getToken(),
                "Bearer",
                jwtService.getAccessTokenExpirationMs() / 1000,
                refreshTokenService.getRefreshTokenExpirationMs() / 1000
        );
    }
}
