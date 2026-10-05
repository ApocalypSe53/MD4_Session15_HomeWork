package com.rikkei.identity.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rikkei.identity.entity.RefreshToken;
import com.rikkei.identity.repository.RefreshTokenRepository;
import com.rikkei.identity.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerRefreshTest {

    @Autowired
    private MockMvc mvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private UserRepository userRepository;

    @Test
    void refresh_rotatesToken_andRejectsReuseOfOldToken() throws Exception {
        JsonNode login = json(login("student01", "123456").andExpect(status().isOk()));
        String oldRefresh = login.get("refreshToken").asText();

        // 1. Đổi token -> nhận cặp token mới
        JsonNode refreshed = json(refresh(oldRefresh)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty()));
        String newRefresh = refreshed.get("refreshToken").asText();
        assertThat(newRefresh).isNotEqualTo(oldRefresh);
        assertThat(refreshed.get("accessToken").asText()).isNotEqualTo(login.get("accessToken").asText());
        assertThat(refreshTokenRepository.findByToken(oldRefresh)).get()
                .extracting(RefreshToken::isRevoked).isEqualTo(true);

        // 2. Gửi lại token cũ -> 403
        refresh(oldRefresh)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("Refresh Token đã được sử dụng (đã bị xoay vòng)"));

        // 3. Reuse detection: token mới cấp ở bước 1 cũng bị thu hồi theo
        refresh(newRefresh).andExpect(status().isForbidden());
    }

    @Test
    void refresh_withUnknownToken_returns403() throws Exception {
        refresh("khong-ton-tai")
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("Refresh Token không tồn tại"));
    }

    @Test
    void refresh_withExpiredToken_returns403() throws Exception {
        refreshTokenRepository.save(RefreshToken.builder()
                .token("expired-token")
                .user(userRepository.findByUsername("instructor01").orElseThrow())
                .expiryDate(Instant.now().minusSeconds(60))
                .revoked(false)
                .build());

        refresh("expired-token")
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("Refresh Token đã hết hạn, vui lòng đăng nhập lại"));
    }

    @Test
    void refresh_withBlankToken_returns400() throws Exception {
        refresh("").andExpect(status().isBadRequest());
    }

    private ResultActions login(String username, String password) throws Exception {
        return mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                        java.util.Map.of("username", username, "password", password))));
    }

    private ResultActions refresh(String refreshToken) throws Exception {
        return mvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(java.util.Map.of("refreshToken", refreshToken))));
    }

    private JsonNode json(ResultActions result) throws Exception {
        return objectMapper.readTree(result.andReturn().getResponse().getContentAsString());
    }
}
