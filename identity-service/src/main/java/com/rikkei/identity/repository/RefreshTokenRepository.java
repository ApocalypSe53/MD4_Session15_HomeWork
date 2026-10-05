package com.rikkei.identity.repository;

import com.rikkei.identity.entity.RefreshToken;
import com.rikkei.identity.entity.User;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    /**
     * SELECT ... FOR UPDATE: khoá bản ghi để 2 request /refresh đồng thời với cùng một token
     * không thể cùng đổi thành công (request thứ 2 phải chờ và sẽ thấy token đã bị revoke).
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from RefreshToken r join fetch r.user where r.token = :token")
    Optional<RefreshToken> findByTokenForUpdate(@Param("token") String token);

    @Modifying
    @Query("update RefreshToken r set r.revoked = true where r.user = :user and r.revoked = false")
    int revokeAllByUser(@Param("user") User user);
}
