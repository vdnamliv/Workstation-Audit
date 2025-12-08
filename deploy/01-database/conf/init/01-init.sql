-- ============================================
-- VT-AUDIT DATABASE INITIALIZATION SCRIPT
-- ============================================
-- LƯU Ý QUAN TRỌNG: 
-- PHẢI thay đổi password bên dưới TRƯỚC KHI deploy!
-- Password phải khớp với .env của các service khác!
-- ============================================

-- 1. Tạo Database riêng biệt (Clean Architecture)
CREATE DATABASE keycloak;
CREATE DATABASE stepca;
CREATE DATABASE vt_db;

-- ============================================
-- 2. TẠO USERS VÀ PHÂN QUYỀN
-- ============================================
-- ⚠️ THAY ĐỔI PASSWORD BÊN DƯỚI! ⚠️

-- User cho Keycloak (dùng trên server .49/.50)
-- Password này phải khớp với KC_DB_PASSWORD trong 03-admin-api/.env
CREATE USER keycloak WITH PASSWORD 'CHANGE_ME_Keycloak_DB_Pass!';
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;

-- User cho StepCA (dùng trên server .47/.48) - Optional nếu dùng file-based
CREATE USER stepca WITH PASSWORD 'CHANGE_ME_StepCA_DB_Pass!';
GRANT ALL PRIVILEGES ON DATABASE stepca TO stepca;

-- User cho VT-Audit Application (dùng trên server .47/.48/.49/.50)
-- Password này phải khớp với DB_PASS trong 03-admin-api/.env và 04-agent-api/.env
CREATE USER vt_app WITH PASSWORD 'CHANGE_ME_VT_App_DB_Pass!';
GRANT ALL PRIVILEGES ON DATABASE vt_db TO vt_app;

-- 2. Chuyển sang DB nghiệp vụ để tạo schema TRƯỚC
\c vt_db;

-- 3. Tạo Schema TRƯỚC KHI GRANT
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS policy;

-- 4. Cho phép users này connect vào DB owner schemas
\c keycloak;
GRANT ALL ON SCHEMA public TO keycloak;

\c stepca;
GRANT ALL ON SCHEMA public TO stepca;

\c vt_db;
GRANT ALL ON SCHEMA public TO vt_app;
GRANT ALL ON SCHEMA audit TO vt_app;
GRANT ALL ON SCHEMA policy TO vt_app;

-- 4. Bảng AGENTS (Đã fix lỗi thiếu cột và nullable secret)
CREATE TABLE IF NOT EXISTS audit.agents (
    agent_id     TEXT PRIMARY KEY,
    -- Cho phép NULL vì mTLS agent không dùng secret
    agent_secret TEXT, 
    hostname     TEXT,
    os           TEXT,
    fingerprint  TEXT UNIQUE,
    -- Thêm 2 cột này để khớp với code UpsertAgent
    cert_cn      TEXT,
    cert_serial  TEXT,
    enrolled_at  TIMESTAMPTZ DEFAULT now(), -- Sửa thành TimeStamp cho chuẩn PostgreSQL
    last_seen    TIMESTAMPTZ DEFAULT now()
);

-- 5. Bảng RESULTS_FLAT (Bảng chính lưu kết quả)
CREATE TABLE IF NOT EXISTS audit.results_flat (
    id           BIGSERIAL PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    hostname     TEXT,
    os           TEXT,
    run_id       TEXT,
    -- Lưu bigint (epoch) để khớp với code Go hiện tại, 
    -- dù dùng timestamptz sẽ tốt hơn cho việc query trực tiếp trong DB
    received_at  BIGINT, 
    policy_title TEXT,
    status       TEXT,
    expected     TEXT,
    reason       TEXT,
    fix          TEXT
);
-- Index quan trọng cho dashboard
CREATE INDEX IF NOT EXISTS idx_results_flat_agent_time ON audit.results_flat(agent_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_results_flat_hostname ON audit.results_flat(hostname);

-- 6. Bảng POLICY (Giữ nguyên logic code)
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

-- 7. GRANT quyền trên tất cả tables cho vt_app
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

-- 8. View tương thích (Nếu backend vẫn query schema public - optional)
CREATE OR REPLACE VIEW public.policy_versions AS SELECT * FROM policy.policy_versions;