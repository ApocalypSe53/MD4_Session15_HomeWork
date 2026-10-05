# MD4 - Session 15 Homework: JWT, API Gateway, RBAC & Token Rotation

| Service | Port | Mô tả |
|---|---|---|
| `identity-service` | 8081 | Login cấp Access Token (HS256, 15 phút, có `sub`/`role`/`jti`) + Refresh Token (7 ngày, lưu PostgreSQL); `POST /api/auth/refresh` với Token Rotation |
| `gateway-service` | 8080 | Spring Cloud Gateway, Global Filter validate JWT, gắn header `X-User-Role` rồi forward |
| `course-service` | 8082 | Resource Server, phân quyền `@PreAuthorize` dựa trên header `X-User-Role` |

## Chạy
1. PostgreSQL: `cd identity-service && docker compose up -d`
2. Mỗi service: `mvn spring-boot:run`
3. Tài khoản mẫu: `student01` / `123456` (STUDENT), `instructor01` / `123456` (INSTRUCTOR)

## Postman
Import các collection trong thư mục [`postman/`](postman/):
- `Identity-Service` – Bài 1 (login)
- `Gateway-Service` – Bài 2 (chặn token thiếu / hết hạn / sai chữ ký)
- `Course-Service-RBAC` – Bài 3 (STUDENT/INSTRUCTOR)
- `Token-Rotation` – Bài 4 (refresh + reuse bị từ chối 403)
