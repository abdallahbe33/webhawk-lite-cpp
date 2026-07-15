CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    ip_address VARCHAR(45) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS backend_registration (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service_name VARCHAR(150) NOT NULL,
    target_url VARCHAR(2048) NOT NULL,
    api_key VARCHAR(100) NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS security_logs (
    id SERIAL PRIMARY KEY,
    backend_id INTEGER REFERENCES backend_registration(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    method VARCHAR(20) NOT NULL,
    endpoint VARCHAR(2048) NOT NULL,
    attack_type VARCHAR(100),
    is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    request_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rate_limit (
    id SERIAL PRIMARY KEY,
    backend_id INTEGER NOT NULL REFERENCES backend_registration(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    endpoint VARCHAR(2048) NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    blocked_until TIMESTAMPTZ,
    is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (backend_id, ip_address, endpoint)
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id
ON user_sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_backend_registration_user_id
ON backend_registration(user_id);

CREATE INDEX IF NOT EXISTS idx_security_logs_backend_id
ON security_logs(backend_id);

CREATE INDEX IF NOT EXISTS idx_security_logs_attack_type
ON security_logs(attack_type);

CREATE INDEX IF NOT EXISTS idx_security_logs_is_blocked
ON security_logs(is_blocked);

CREATE INDEX IF NOT EXISTS idx_rate_limit_backend_ip_endpoint
ON rate_limit(backend_id, ip_address, endpoint);