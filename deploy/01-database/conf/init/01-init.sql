-- ============================================
-- VT-AUDIT DATABASE INITIALIZATION SCRIPT
-- ============================================
-- File này chạy TỰ ĐỘNG khi PostgreSQL container khởi tạo lần đầu.
-- Password bên dưới là password TEST, KHỚP với các file .env.example
-- Khi deploy production: đổi password mạnh hơn!
-- ============================================

-- 1. Tạo Database riêng biệt (Clean Architecture)
CREATE DATABASE keycloak;
CREATE DATABASE stepca;
CREATE DATABASE vt_db;

-- ============================================
-- 2. TẠO USERS VÀ PHÂN QUYỀN
-- ============================================
-- Password phải KHỚP với các file .env:
-- - keycloak123 -> 03-admin-api/.env (KC_DB_PASSWORD)
-- - stepca123   -> 04-agent-api/.env (STEPCA_DB_PASSWORD)
-- - vtapp123    -> 03-admin-api/.env & 04-agent-api/.env (DB_PASS)

-- User cho Keycloak
CREATE USER keycloak WITH PASSWORD 'keycloak123';
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;

-- User cho StepCA (Optional - hiện dùng file-based)
CREATE USER stepca WITH PASSWORD 'stepca123';
GRANT ALL PRIVILEGES ON DATABASE stepca TO stepca;

-- User cho VT-Audit Application
CREATE USER vt_app WITH PASSWORD 'vtapp123';
GRANT ALL PRIVILEGES ON DATABASE vt_db TO vt_app;

-- 3. Chuyển sang DB nghiệp vụ để tạo schema
\c vt_db;

-- 4. Tạo Schema
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS policy;

-- 5. Grant quyền trên schemas
\c keycloak;
GRANT ALL ON SCHEMA public TO keycloak;

\c stepca;
GRANT ALL ON SCHEMA public TO stepca;

\c vt_db;
GRANT ALL ON SCHEMA public TO vt_app;
GRANT ALL ON SCHEMA audit TO vt_app;
GRANT ALL ON SCHEMA policy TO vt_app;

-- 6. Bảng AGENTS
CREATE TABLE IF NOT EXISTS audit.agents (
    agent_id     TEXT PRIMARY KEY,
    agent_secret TEXT,
    hostname     TEXT,
    os           TEXT,
    fingerprint  TEXT UNIQUE,
    cert_cn      TEXT,
    cert_serial  TEXT,
    enrolled_at  TIMESTAMPTZ DEFAULT now(),
    last_seen    TIMESTAMPTZ DEFAULT now()
);

-- 7. Bảng RESULTS_FLAT
CREATE TABLE IF NOT EXISTS audit.results_flat (
    id           BIGSERIAL PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    hostname     TEXT,
    os           TEXT,
    run_id       TEXT,
    received_at  BIGINT,
    policy_title TEXT,
    status       TEXT,
    expected     TEXT,
    reason       TEXT,
    fix          TEXT
);

CREATE INDEX IF NOT EXISTS idx_results_flat_agent_time ON audit.results_flat(agent_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_results_flat_hostname ON audit.results_flat(hostname);

-- 8. Bảng POLICY
CREATE TABLE IF NOT EXISTS policy.policy_versions (
    policy_id  TEXT NOT NULL,
    os         TEXT NOT NULL,
    version    INTEGER NOT NULL,
    config     TEXT NOT NULL,
    hash       TEXT NOT NULL,
    yaml_src   TEXT,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY(policy_id, os, version)
);

CREATE TABLE IF NOT EXISTS policy.policy_heads (
    os         TEXT PRIMARY KEY,
    policy_id  TEXT NOT NULL,
    version    INTEGER NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy.policy_rules (
    id         SERIAL PRIMARY KEY,
    policy_id  TEXT NOT NULL,
    version    INTEGER NOT NULL,
    rule_id    TEXT NOT NULL,
    title      TEXT NOT NULL,
    description TEXT,
    severity   TEXT NOT NULL,
    check_cmd  TEXT NOT NULL,
    expected   TEXT NOT NULL,
    fix        TEXT,
    tags       TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(policy_id, version, rule_id)
);

-- 9. GRANT quyền trên tất cả tables
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA audit TO vt_app;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA audit TO vt_app;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA policy TO vt_app;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA policy TO vt_app;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO vt_app;

-- Set default privileges cho tables tương lai
ALTER DEFAULT PRIVILEGES IN SCHEMA audit GRANT ALL ON TABLES TO vt_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit GRANT ALL ON SEQUENCES TO vt_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA policy GRANT ALL ON TABLES TO vt_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA policy GRANT ALL ON SEQUENCES TO vt_app;

-- 10. View tương thích (Optional)
CREATE OR REPLACE VIEW public.policy_versions AS SELECT * FROM policy.policy_versions;
