package com.rikkei.course.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Đọc quyền trực tiếp từ header X-User-Role mà Gateway đã gắn vào sau khi validate JWT (Bài 2).
 * Course-Service KHÔNG giải mã JWT lại -> tin tưởng Gateway, vì vậy service này chỉ được
 * phép nhận traffic đi qua Gateway (không public port 8082 ra ngoài).
 */
public class HeaderRoleAuthenticationFilter extends OncePerRequestFilter {

    public static final String USER_ROLE_HEADER = "X-User-Role";
    private static final String PRINCIPAL = "gateway-user";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String role = request.getHeader(USER_ROLE_HEADER);

        if (StringUtils.hasText(role)) {
            // Authority = đúng tên role (không thêm tiền tố ROLE_) để khớp với hasAuthority('STUDENT')
            var authentication = new PreAuthenticatedAuthenticationToken(
                    PRINCIPAL, null, List.of(new SimpleGrantedAuthority(role.trim())));

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
        }

        chain.doFilter(request, response);
    }
}
