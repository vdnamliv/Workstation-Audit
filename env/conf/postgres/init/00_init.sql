CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS policy;
CREATE SCHEMA IF NOT EXISTS admin; -- (tuỳ chọn cho view/dashboard)

-- 1. Agents
CREATE TABLE audit.agents (
  agent_id      TEXT PRIMARY KEY,       -- lấy từ cert CN hoặc SAN
  hostname      TEXT NOT NULL,
  os            TEXT NOT NULL,
  fingerprint   TEXT UNIQUE,            -- optional: machine fingerprint
  cert_cn       TEXT NOT NULL,          -- lưu CN trong cert
  cert_serial   TEXT NOT NULL,          -- serial number cert để detect revoke/rotate
  enrolled_at   TIMESTAMPTZ DEFAULT now(),
  last_seen     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_agents_host ON audit.agents(LOWER(hostname));
CREATE INDEX IF NOT EXISTS idx_agents_os   ON audit.agents(os);

-- 2. 1 run = 1 lần agent gửi kết quả
CREATE TABLE IF NOT EXISTS audit.runs (
  run_id       TEXT PRIMARY KEY,
  agent_id     TEXT NOT NULL REFERENCES audit.agents(agent_id) ON DELETE CASCADE,
  policy_id    TEXT NOT NULL,
  policy_ver   INT  NOT NULL,
  received_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_runs_agent_time ON audit.runs(agent_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_policy     ON audit.runs(policy_id, policy_ver);

-- 3. Mỗi run sinh nhiều check (rule). Lưu kết quả từng check để lọc/search và thống kê.
CREATE TABLE IF NOT EXISTS audit.check_results (
  id           BIGSERIAL PRIMARY KEY,
  run_id       TEXT NOT NULL REFERENCES audit.runs(run_id) ON DELETE CASCADE,
  agent_id     TEXT NOT NULL,        -- denormalize để join nhanh
  hostname     TEXT NOT NULL,
  os           TEXT NOT NULL,
  rule_id      TEXT NOT NULL,        -- định danh rule (stable)
  rule_title   TEXT NOT NULL,        -- human title (policy_title cũ)
  status       TEXT NOT NULL CHECK (status IN ('PASS','FAIL','WARN')),
  expected     TEXT,
  reason       TEXT,
  fix          TEXT
);

CREATE INDEX IF NOT EXISTS idx_chk_agent ON audit.check_results(agent_id);
CREATE INDEX IF NOT EXISTS idx_chk_rule  ON audit.check_results(rule_id);
CREATE INDEX IF NOT EXISTS idx_chk_host  ON audit.check_results(LOWER(hostname));
CREATE INDEX IF NOT EXISTS idx_chk_stat  ON audit.check_results(status);

-- 4. Snapshot mới nhất cho mỗi agent (gộp/đếm sẵn)
CREATE TABLE IF NOT EXISTS audit.agent_snapshot (
  agent_id       TEXT PRIMARY KEY REFERENCES audit.agents(agent_id) ON DELETE CASCADE,
  last_run_id    TEXT NOT NULL,
  last_time      TIMESTAMPTZ NOT NULL,
  total_checks   INT NOT NULL,
  pass_count     INT NOT NULL,
  fail_count     INT NOT NULL,
  warn_count     INT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_snap_fail ON audit.agent_snapshot(fail_count DESC);

-- 5. Policy versions (khớp với code)
CREATE TABLE IF NOT EXISTS policy.policy_versions (
  policy_id   TEXT NOT NULL,
  os          TEXT NOT NULL,
  version     INT  NOT NULL,
  hash        TEXT NOT NULL,
  config      JSONB NOT NULL,   -- bạn có thể giữ TEXT, nhưng JSONB dễ query hơn
  yaml_src    TEXT,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (policy_id, os, version)
);

-- Active head per OS
CREATE TABLE IF NOT EXISTS policy.policy_heads (
  os          TEXT PRIMARY KEY,
  policy_id   TEXT NOT NULL,
  version     INT  NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);