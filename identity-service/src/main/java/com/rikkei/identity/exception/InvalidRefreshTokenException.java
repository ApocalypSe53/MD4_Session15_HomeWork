package com.rikkei.identity.exception;

/** Refresh Token không tồn tại / hết hạn / đã bị xoay vòng -> 403 Forbidden */
public class InvalidRefreshTokenException extends RuntimeException {

    public InvalidRefreshTokenException(String message) {
        super(message);
    }
}
