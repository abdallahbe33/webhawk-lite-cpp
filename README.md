# WebHawk Lite C++

WebHawk Lite is a small Web Application Firewall (WAF) written in C++20 using the Drogon framework and PostgreSQL.

The project works as a security layer between a client and a backend server:

```text
Client -> WebHawk Lite -> Backend Server
```

Every proxy request is checked before it reaches the real backend. Safe requests are forwarded, while dangerous requests are blocked and stored in the database.

## Team members

- Abdallah Beida
- Yazan Jaradat

This project was developed as a collaboration between both team members. We divided the project into parts and used Git branches and pull requests to combine and review our work.

## Main features

- User registration
- Secure password hashing
- JWT login authentication
- Active session management
- Logout and token invalidation
- Backend registration
- Unique API key generation
- SQL Injection detection
- XSS detection
- Rate limiting by IP and endpoint
- Reverse proxy forwarding
- Security request logging
- Analytics endpoints
- PostgreSQL database
- Vulnerable C++ demonstration backend
- Docker Compose setup
- Automated C++ tests
- Postman collection

## How WebHawk works

```text
1. The client sends a request to WebHawk.
2. WebHawk reads the API key.
3. WebHawk finds the registered backend.
4. The rate limiter checks the IP and endpoint.
5. The scanner checks the path, query, body, and headers.
6. Dangerous requests are blocked.
7. Safe requests are forwarded to the backend.
8. The result is stored in security_logs.
```

The proxy endpoint has this format:

```text
/proxy/{api_key}/{path}
```

Example:

```text
GET /proxy/webhawk_example_key/products
```

## Security checks

### SQL Injection

WebHawk looks for suspicious patterns such as:

```text
' OR 1=1 --
UNION SELECT
DROP TABLE
INSERT INTO
DELETE FROM
```

Example:

```text
GET /proxy/API_KEY/search?q=' OR 1=1 --
```

This request should be blocked before reaching the backend.

### XSS

WebHawk detects patterns such as:

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
javascript:
onclick=
onerror=
```

Example:

```json
{
  "comment": "<script>alert(1)</script>"
}
```

This request should also be blocked.

### Rate limiting

Rate limiting tracks requests using:

- Backend ID
- Client IP
- Endpoint
- Request count
- Time window

The default configuration allows 100 requests during a 60-second window.

## Project structure

```text
webhawk-lite-cpp/
|
|-- database/
|   `-- schema.sql
|
|-- include/
|   |-- config/
|   |-- controllers/
|   |-- database/
|   |-- models/
|   |-- proxy/
|   |-- repositories/
|   |-- security/
|   `-- services/
|
|-- src/
|   |-- config/
|   |-- controllers/
|   |-- database/
|   |-- models/
|   |-- proxy/
|   |-- repositories/
|   |-- security/
|   `-- services/
|
|-- tests/
|-- vulnerable_backend/
|-- CMakeLists.txt
|-- Dockerfile
|-- docker-compose.yml
|-- postman_collection.json
`-- README.md
```

## Database tables

The project uses the five required PostgreSQL tables.

### 1. users

Stores WebHawk user accounts.

Important columns:

- `id`
- `name`
- `email`
- `password_hash`
- `created_at`
- `updated_at`

### 2. user_sessions

Stores active login sessions.

Important columns:

- `id`
- `user_id`
- `token_hash`
- `ip_address`
- `created_at`
- `expires_at`
- `is_active`

Foreign key:

```text
user_id -> users.id
```

### 3. backend_registration

Stores backends registered by users.

Important columns:

- `id`
- `user_id`
- `service_name`
- `target_url`
- `api_key`
- `is_active`
- `created_at`
- `updated_at`

Foreign key:

```text
user_id -> users.id
```

### 4. security_logs

Stores allowed and blocked request information.

Important columns:

- `id`
- `backend_id`
- `ip_address`
- `method`
- `endpoint`
- `attack_type`
- `is_blocked`
- `request_data`
- `created_at`

Foreign key:

```text
backend_id -> backend_registration.id
```

### 5. rate_limit

Stores rate-limit counters.

Important columns:

- `id`
- `backend_id`
- `ip_address`
- `endpoint`
- `request_count`
- `window_start`
- `blocked_until`
- `is_blocked`

Foreign key:

```text
backend_id -> backend_registration.id
```

The schema is located in:

```text
database/schema.sql
```

Docker automatically creates the tables when PostgreSQL starts with a new database volume.

## API endpoints

### Health endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Check the WebHawk API |
| GET | `/db/health` | Check PostgreSQL and table counts |

### Authentication endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/auth/register` | Register a user |
| POST | `/auth/login` | Login and receive JWT |
| POST | `/auth/logout` | Deactivate the current session |
| GET | `/auth/sessions` | List active sessions |

### Backend endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/backends` | Register a backend |
| GET | `/backends` | List user backends |
| GET | `/backends/{id}` | Get one backend |
| PUT | `/backends/{id}` | Update a backend |
| DELETE | `/backends/{id}` | Disable a backend |

### Security endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/security/scan` | Scan for SQL Injection and XSS |
| POST | `/security/scan/sql-injection` | Run only SQL Injection detection |
| POST | `/security/rate-limit/check` | Check an IP rate limit |

### Proxy endpoint

| Method | Endpoint | Purpose |
|---|---|---|
| GET/POST/PUT/DELETE/PATCH | `/proxy/{api_key}/{path}` | Scan and forward requests |

### Logs and analytics

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/logs/security` | Display security logs |
| GET | `/analytics/summary` | Display request totals |
| GET | `/analytics/attacks-by-type` | Group attacks by type |
| GET | `/analytics/recent-attacks` | Display recent attacks |
| GET | `/analytics/attacks-over-time` | Display attacks over time |

## Run the project using Docker

Docker Desktop and Docker Compose are required.

From the project directory, run:

```bash
docker compose down -v --remove-orphans
docker compose up --build -d --wait
docker compose ps
```

The services are available at:

- WebHawk API: `http://localhost:8080`
- Vulnerable backend: `http://localhost:5001`
- PostgreSQL: `localhost:5435`

Check the services:

```bash
curl http://localhost:8080/health
curl http://localhost:8080/db/health
curl http://localhost:5001/health
```

Expected WebHawk response:

```json
{
  "service": "WebHawk Lite C++",
  "status": "ok",
  "version": "0.1.0"
}
```

Check the database tables:

```bash
docker compose exec db \
  psql -U webhawk -d webhawk_cpp -c "\dt"
```

The result should contain:

```text
users
user_sessions
backend_registration
security_logs
rate_limit
```

View container logs:

```bash
docker compose logs --tail=100 webhawk
docker compose logs --tail=100 vulnerable-backend
```

Stop the project:

```bash
docker compose down
```

## Postman collection

The project contains:

```text
postman_collection.json
```

Import this file into Postman.

Run the requests in this order:

1. Health Check
2. Database Health Check
3. Register
4. Login
5. Active Sessions
6. Register Backend
7. List Backends
8. Safe Security Scan
9. SQL Injection Scan
10. XSS Scan
11. Safe Proxy Request
12. Blocked SQL Injection Through Proxy
13. Blocked XSS Through Proxy
14. Security Logs
15. Analytics Summary
16. Attacks By Type
17. Recent Attacks
18. Attacks Over Time
19. Logout

The login request automatically saves the JWT token.

The backend registration request automatically saves:

- Backend ID
- API key

The registered target URL used inside Docker is:

```text
http://vulnerable-backend:5001
```

## Live demonstration

### 1. Register and login

Use Postman to register and log in.

Login returns a JWT access token.

### 2. Register the vulnerable backend

Use:

```json
{
  "service_name": "Demo Store Backend",
  "target_url": "http://vulnerable-backend:5001"
}
```

WebHawk generates an API key.

### 3. Safe proxy request

Send:

```text
GET http://localhost:8080/proxy/API_KEY/products?category=phones
```

The request should reach the vulnerable backend and return the products.

### 4. SQL Injection demonstration

Send:

```text
GET http://localhost:8080/proxy/API_KEY/search?q=' OR 1=1 --
```

Expected result:

```json
{
  "allowed": false,
  "attack_type": "SQL_INJECTION",
  "message": "Request blocked by WebHawk"
}
```

The HTTP status should be `403`.

### 5. XSS demonstration

Send:

```text
POST http://localhost:8080/proxy/API_KEY/comments
```

Body:

```json
{
  "comment": "<script>alert(1)</script>"
}
```

Expected result:

```json
{
  "allowed": false,
  "attack_type": "XSS",
  "message": "Request blocked by WebHawk"
}
```

### 6. Logs and analytics

Open these requests in Postman:

```text
GET /logs/security
GET /analytics/summary
GET /analytics/attacks-by-type
GET /analytics/recent-attacks
GET /analytics/attacks-over-time
```

The SQL Injection and XSS attempts should appear in the security logs and analytics.

## Build and test on macOS

Install Drogon, CMake, PostgreSQL, OpenSSL, and libpqxx through Homebrew.

Then run:

```bash
cmake --fresh -S . -B build-check \
  -DCMAKE_PREFIX_PATH="$(brew --prefix)" \
  -DBUILD_TESTING=ON

cmake --build build-check --parallel 2

ctest \
  --test-dir build-check \
  --output-on-failure
```

The tests cover:

- SQL Injection detector
- XSS detector
- Combined request scanner
- Rate-limit policy
- Security-log model
- Proxy utility functions

## Build and test on Windows

Use Visual Studio 2022, CMake, and vcpkg.

Run in PowerShell:

```powershell
cmake --fresh -S . -B build-static `
  -G "Visual Studio 17 2022" `
  -A x64 `
  -DCMAKE_TOOLCHAIN_FILE=C:/Users/Lenovo/vcpkg/scripts/buildsystems/vcpkg.cmake `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static `
  -DBUILD_TESTING=ON

cmake --build build-static --config Debug

ctest `
  --test-dir build-static `
  -C Debug `
  --output-on-failure
```

## Environment variables

The environment variables are documented in `.env.example`.

| Variable | Purpose |
|---|---|
| `PORT` | WebHawk server port |
| `DATABASE_HOST` | PostgreSQL hostname |
| `DATABASE_PORT` | PostgreSQL port |
| `DATABASE_NAME` | Database name |
| `DATABASE_USER` | Database username |
| `DATABASE_PASSWORD` | Database password |
| `JWT_SECRET_KEY` | JWT signing secret |
| `JWT_EXPIRATION_SECONDS` | JWT lifetime |
| `RATE_LIMIT_REQUESTS` | Maximum requests |
| `RATE_LIMIT_WINDOW_SECONDS` | Rate-limit window |
| `RATE_LIMIT_BLOCK_SECONDS` | Block duration |
| `PROXY_TIMEOUT_SECONDS` | Backend timeout |
| `PROXY_MAX_BODY_BYTES` | Maximum proxy body size |

## Security notes

- Passwords are stored as hashes.
- JWT tokens are stored as hashes in the database.
- Logout deactivates the current session.
- Protected endpoints require a Bearer token.
- Each backend receives a unique API key.
- Sensitive request headers are redacted from proxy scan data.
- Blocked requests are saved in PostgreSQL.

WebHawk Lite is an educational project and is not intended to replace a production WAF.

## Submission checklist

- [x] Complete C++ code on GitHub
- [x] Detailed README
- [x] Five PostgreSQL tables
- [x] Postman collection with all endpoints
- [x] Vulnerable C++ backend
- [x] SQL Injection demonstration
- [x] XSS demonstration
- [x] Security logs
- [x] Analytics
- [x] Docker Compose
- [x] Automated tests