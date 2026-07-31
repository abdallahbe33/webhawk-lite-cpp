# WebHawk Lite C++

WebHawk Lite is a C++20 security middleware service built with Drogon and PostgreSQL. It scans requests for SQL injection and XSS, applies per-IP rate limiting, records security events, exposes analytics, and forwards allowed traffic to a registered backend.

## Docker quick start

Requirements: Docker Desktop with Docker Compose.

```bash
docker compose down -v --remove-orphans
docker compose up --build -d
docker compose ps
```

Services:

- WebHawk API: `http://localhost:8080`
- Vulnerable C++ demo backend: `http://localhost:5001`
- PostgreSQL host port: `5435`

Health checks:

```bash
curl http://localhost:8080/health
curl http://localhost:8080/db/health
curl http://localhost:5001/health
```

View container output:

```bash
docker compose logs --tail=100 webhawk
docker compose logs --tail=100 vulnerable-backend
```

Stop the project:

```bash
docker compose down
```

## Native macOS build

Install CMake, Drogon, OpenSSL, PostgreSQL, and libpqxx with Homebrew, then run:

```bash
cmake -S . -B build -DCMAKE_PREFIX_PATH="$(brew --prefix)" -DBUILD_TESTING=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

## Native Windows build

Use Visual Studio 2022, CMake, and vcpkg with the static x64 triplet:

```powershell
cmake -S . -B build-static `
  -G "Visual Studio 17 2022" `
  -A x64 `
  -DCMAKE_TOOLCHAIN_FILE=C:/Users/Lenovo/vcpkg/scripts/buildsystems/vcpkg.cmake `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static `
  -DBUILD_TESTING=ON

cmake --build build-static --config Debug
ctest --test-dir build-static -C Debug --output-on-failure
```

## Implemented modules

- User registration and password hashing
- JWT login, logout, and session management
- Backend registration and API-key management
- SQL injection and XSS detection
- Combined request scanner
- PostgreSQL rate limiting
- Security logs and analytics
- Secure reverse-proxy forwarding
- Dockerized PostgreSQL and vulnerable C++ demo backend

## Database tables

The schema creates the five required tables:

- `users`
- `user_sessions`
- `backend_registration`
- `security_logs`
- `rate_limit`

The database schema is initialized automatically from `database/schema.sql` when the PostgreSQL volume is created.