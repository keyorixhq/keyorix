-- Requires 006_rename_namespace_to_project to have already run: `project_id`
-- below references the `projects` table, which only exists after that rename
-- (see #201 — this migration was previously numbered 006 and ran before the
-- rename existed, which failed outright against a real migration runner).
--
-- #G52: project_id/environment_id deliberately do NOT cascade. A raw
-- `DELETE FROM projects`/`DELETE FROM environments` (or the DB engine's own
-- CASCADE machinery for ANY other FK someone later adds) must not be able to
-- silently take rotation_policies rows down with it, with no application
-- involvement, no authorization check, and no audit trail — rotation policy
-- removal is a deliberate action the live schema (internal/storage/factory.go's
-- GORM AutoMigrate, which defines NO FK constraint here at all, so this
-- exposure never existed there) always routes through application code.
-- ON DELETE RESTRICT means the raw delete is refused outright rather than
-- cascading, forcing whoever performs it to handle the dependent rotation
-- policies explicitly first.
CREATE TABLE rotation_policies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL, -- NOSONAR -- plsql:VarcharUsageCheck false positive: SQLite (not Oracle) uses VARCHAR
    description TEXT,
    scope VARCHAR(20) NOT NULL DEFAULT 'environment', -- NOSONAR -- plsql:VarcharUsageCheck false positive: SQLite uses VARCHAR
    project_id INTEGER REFERENCES projects(id) ON DELETE RESTRICT,
    environment_id INTEGER REFERENCES environments(id) ON DELETE RESTRICT,
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
