CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS policy;

CREATE TABLE IF NOT EXISTS audit.agents (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    os TEXT NOT NULL,
    fingerprint TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit.results (
    agent_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    received_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY(agent_id, run_id)
);

CREATE TABLE IF NOT EXISTS policy.versions (
    policy_id TEXT NOT NULL,
    version INT NOT NULL,
    hash TEXT NOT NULL,
    config JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY(policy_id, version)
);
