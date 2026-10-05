package com.rikkei.identity.config;

import com.rikkei.identity.entity.Role;
import com.rikkei.identity.entity.User;
import com.rikkei.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/** Tạo sẵn tài khoản mẫu (mật khẩu được băm BCrypt) để test API login */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataSeeder implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        seed("student01", "123456", Role.STUDENT);
        seed("instructor01", "123456", Role.INSTRUCTOR);
    }

    private void seed(String username, String rawPassword, Role role) {
        if (userRepository.existsByUsername(username)) {
            return;
        }
        userRepository.save(User.builder()
                .username(username)
                .password(passwordEncoder.encode(rawPassword))
                .role(role)
                .build());
        log.info("Seeded user '{}' with role {}", username, role);
    }
}
