-- Schemas
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS policy;
CREATE SCHEMA IF NOT EXISTS admin;

-- Agents
CREATE TABLE audit.agents (
  agent_id      TEXT PRIMARY KEY,
  hostname      TEXT NOT NULL,
  os            TEXT NOT NULL,
  fingerprint   TEXT UNIQUE,
  cert_cn       TEXT NOT NULL,
  cert_serial   TEXT NOT NULL,
  enrolled_at   TIMESTAMPTZ DEFAULT now(),
  last_seen     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_agents_host ON audit.agents(LOWER(hostname));
CREATE INDEX IF NOT EXISTS idx_agents_os   ON audit.agents(os);

-- Runs
CREATE TABLE audit.runs (
  run_id       TEXT PRIMARY KEY,
  agent_id     TEXT NOT NULL REFERENCES audit.agents(agent_id) ON DELETE CASCADE,
  policy_id    TEXT NOT NULL,
  policy_ver   INT NOT NULL,
  received_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_runs_agent_time ON audit.runs(agent_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_policy     ON audit.runs(policy_id, policy_ver);

-- Check Results
CREATE TABLE audit.check_results (
  id           BIGSERIAL PRIMARY KEY,
  run_id       TEXT NOT NULL REFERENCES audit.runs(run_id) ON DELETE CASCADE,
  agent_id     TEXT NOT NULL,
  hostname     TEXT NOT NULL,
  os           TEXT NOT NULL,
  rule_id      TEXT NOT NULL,
  rule_title   TEXT NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('PASS','FAIL','WARN')),
  expected     TEXT,
  reason       TEXT,
  fix          TEXT
);
CREATE INDEX IF NOT EXISTS idx_chk_agent ON audit.check_results(agent_id);
CREATE INDEX IF NOT EXISTS idx_chk_rule  ON audit.check_results(rule_id);
CREATE INDEX IF NOT EXISTS idx_chk_host  ON audit.check_results(LOWER(hostname));
CREATE INDEX IF NOT EXISTS idx_chk_stat  ON audit.check_results(status);

-- Agent Snapshot
CREATE TABLE audit.agent_snapshot (
  agent_id       TEXT PRIMARY KEY REFERENCES audit.agents(agent_id) ON DELETE CASCADE,
  last_run_id    TEXT NOT NULL,
  last_time      TIMESTAMPTZ NOT NULL,
  total_checks   INT NOT NULL,
  pass_count     INT NOT NULL,
  fail_count     INT NOT NULL,
  warn_count     INT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snap_fail ON audit.agent_snapshot(fail_count DESC);

-- Policy Versions
CREATE TABLE policy.policy_versions (
  policy_id   TEXT NOT NULL,
  os          TEXT NOT NULL,
  version     INT  NOT NULL,
  hash        TEXT NOT NULL,
  config      JSONB NOT NULL,
  yaml_src    TEXT,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (policy_id, os, version)
);

-- Policy Heads
CREATE TABLE policy.policy_heads (
  os          TEXT PRIMARY KEY,
  policy_id   TEXT NOT NULL,
  version     INT NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
