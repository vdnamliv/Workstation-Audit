CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS policy;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'keycloak') THEN
        CREATE ROLE keycloak LOGIN PASSWORD 'ChangeMe123!';
    ELSE
        ALTER ROLE keycloak WITH LOGIN PASSWORD 'ChangeMe123!';
    END IF;
END
$$;

GRANT ALL PRIVILEGES ON DATABASE audit TO keycloak;
GRANT USAGE, CREATE ON SCHEMA public TO keycloak;
GRANT USAGE ON SCHEMA audit TO keycloak;
GRANT USAGE ON SCHEMA policy TO keycloak;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO keycloak;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO keycloak;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO keycloak;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO keycloak;

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
