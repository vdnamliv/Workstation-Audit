-- Devices (one row per agent)
CREATE TABLE devices (
  device_id        UUID PRIMARY KEY,
  identity_uri     TEXT UNIQUE,                 -- from mTLS cert (SPIFFE/URI SAN) or CN
  hostname         TEXT,
  serial_number    TEXT,
  os_name          TEXT,
  os_version       TEXT,
  enrolled_at      TIMESTAMPTZ DEFAULT now(),
  last_seen_at     TIMESTAMPTZ,
  tags             JSONB DEFAULT '{}'::jonb,   -- e.g. {"dept":"it","site":"bkk"}
  attrs            JSONB DEFAULT '{}'::jsonb    -- freeform facts (CPU, RAM, etc.)
);
CREATE INDEX idx_devices_last_seen   ON devices(last_seen_at DESC);
CREATE INDEX idx_devices_hostname_trgm ON devices USING gin (hostname gin_trgm_ops);
CREATE INDEX idx_devices_tags_gin    ON devices USING gin (tags);
CREATE INDEX idx_devices_attrs_gin   ON devices USING gin (attrs);

-- Baselines (a set of policies)
CREATE TABLE baselines (
  baseline_id   UUID PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  description   TEXT,
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Policies with versioning (immutable versions)
CREATE TABLE policies (
  policy_id     UUID PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  description   TEXT
);

CREATE TABLE policy_versions (
  policy_version_id UUID PRIMARY KEY,
  policy_id         UUID NOT NULL REFERENCES policies(policy_id),
  version           INTEGER NOT NULL,
  severity          TEXT CHECK (severity IN ('low','medium','high','critical')) NOT NULL DEFAULT 'medium',
  check_type        TEXT,        -- e.g. "command","registry","file","script"
  command_template  TEXT,        -- how agent/server checks
  reason            TEXT,        -- why policy exists
  remediation       TEXT,        -- recommended fix
  definition        JSONB,       -- extra fields if needed
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (policy_id, version)
);

-- Which policy versions are part of a baseline (explicit version pin)
CREATE TABLE baseline_policy_versions (
  baseline_id        UUID NOT NULL REFERENCES baselines(baseline_id) ON DELETE CASCADE,
  policy_version_id  UUID NOT NULL REFERENCES policy_versions(policy_version_id) ON DELETE RESTRICT,
  order_index        INTEGER NOT NULL DEFAULT 0,
  required           BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY (baseline_id, policy_version_id)
);
CREATE INDEX idx_bp_order ON baseline_policy_versions(baseline_id, order_index);

-- One evaluation run per report push from agent
-- Tip: range partition by month if you expect lots of history.
CREATE TABLE eval_runs (
  eval_id        UUID PRIMARY KEY,
  device_id      UUID NOT NULL REFERENCES devices(device_id),
  baseline_id    UUID REFERENCES baselines(baseline_id),
  started_at     TIMESTAMPTZ NOT NULL,
  finished_at    TIMESTAMPTZ,
  pass_count     INTEGER NOT NULL DEFAULT 0,
  fail_count     INTEGER NOT NULL DEFAULT 0,
  agent_version  TEXT,
  UNIQUE(device_id, started_at)           -- idempotency helper
);
CREATE INDEX idx_eval_runs_device_time ON eval_runs(device_id, started_at DESC);
CREATE INDEX idx_eval_runs_baseline    ON eval_runs(baseline_id, started_at DESC);

-- Findings inside an eval (one row per policy checked)
CREATE TABLE eval_findings (
  finding_id         BIGSERIAL PRIMARY KEY,
  eval_id            UUID NOT NULL REFERENCES eval_runs(eval_id) ON DELETE CASCADE,
  policy_version_id  UUID NOT NULL REFERENCES policy_versions(policy_version_id),
  status             TEXT NOT NULL CHECK (status IN ('PASS','FAIL','ERROR','SKIP')),
  reason             TEXT,             -- concrete fail reason from agent
  observed_value     JSONB,            -- raw config snapshot for this check
  duration_ms        INTEGER,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_findings_eval        ON eval_findings(eval_id);
CREATE INDEX idx_findings_policy      ON eval_findings(policy_version_id);
CREATE INDEX idx_findings_fail_policy ON eval_findings(policy_version_id) WHERE status='FAIL';
CREATE INDEX idx_findings_observed_gin ON eval_findings USING gin (observed_value);

-- Current compliance snapshot per device (overwrite on each new eval)
CREATE TABLE device_compliance_snapshot (
  device_id       UUID PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
  baseline_id     UUID REFERENCES baselines(baseline_id),
  compliant       BOOLEAN NOT NULL,
  pass_count      INTEGER NOT NULL DEFAULT 0,
  fail_count      INTEGER NOT NULL DEFAULT 0,
  last_eval_id    UUID REFERENCES eval_runs(eval_id),
  last_eval_at    TIMESTAMPTZ,
  top_fail_policies UUID[],           -- small array of "worst" failing policy_version_ids
  fail_reasons    JSONB               -- compacted reasons (e.g., [{"policy":"...","reason":"..."}])
);
CREATE INDEX idx_snapshot_compliance   ON device_compliance_snapshot(compliant);
CREATE INDEX idx_snapshot_baseline_nc  ON device_compliance_snapshot(baseline_id) WHERE compliant = FALSE;

-- Optional: daily counts for dashboards (pre-aggregated)
CREATE TABLE policy_stats_daily (
  day               DATE NOT NULL,
  baseline_id       UUID,
  policy_version_id UUID,
  noncompliant_devices INTEGER NOT NULL,
  computed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (day, baseline_id, policy_version_id)
);
