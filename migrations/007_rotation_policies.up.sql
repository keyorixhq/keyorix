-- Requires 006_rename_namespace_to_project to have already run: `project_id`
-- below references the `projects` table, which only exists after that rename
-- (see #201 — this migration was previously numbered 006 and ran before the
-- rename existed, which failed outright against a real migration runner).
CREATE TABLE rotation_policies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL, -- NOSONAR -- plsql:VarcharUsageCheck false positive: SQLite (not Oracle) uses VARCHAR
    description TEXT,
    scope VARCHAR(20) NOT NULL DEFAULT 'environment', -- NOSONAR -- plsql:VarcharUsageCheck false positive: SQLite uses VARCHAR
    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    environment_id INTEGER REFERENCES environments(id) ON DELETE CASCADE,
    interval_days INTEGER NOT NULL,
    alert_days_before INTEGER NOT NULL DEFAULT 7,
    notify_on_breach BOOLEAN NOT NULL DEFAULT true,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_by VARCHAR(255) NOT NULL, -- NOSONAR -- plsql:VarcharUsageCheck false positive: SQLite uses VARCHAR
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE INDEX idx_rotation_policies_project
    ON rotation_policies(project_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_rotation_policies_environment
    ON rotation_policies(environment_id) WHERE deleted_at IS NULL;
