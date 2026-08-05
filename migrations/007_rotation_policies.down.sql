-- Rollback Rotation Policies Migration
--
-- WARNING — DATA LOSS AFTER A GRACE WINDOW: before the `DROP TABLE IF EXISTS
-- rotation_policies` below, every row is copied into `rotation_policies_backup`
-- so that rolling back does not silently destroy compliance-relevant data —
-- which secrets require rotation, their alert thresholds, and the
-- `created_by` accountability trail for who configured them. That backup
-- table is a TEMPORARY safety net only — it is not part of the live schema,
-- is not cleaned up automatically, and should be exported/archived and
-- dropped explicitly by an operator once the rollback is confirmed safe. The
-- backup insert is safe to re-run across repeated rollback/re-upgrade
-- /rollback cycles (it accumulates timestamped snapshots rather than
-- colliding with an earlier backup).

-- Drop indexes
DROP INDEX IF EXISTS idx_rotation_policies_project;
DROP INDEX IF EXISTS idx_rotation_policies_environment;

-- Back up rotation_policies before dropping it. See warning above: this is a
-- temporary safety net, not permanent storage.
CREATE TABLE IF NOT EXISTS rotation_policies_backup (
  backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
  id INTEGER,
  name TEXT,
  description TEXT,
  scope TEXT,
  project_id INTEGER,
  environment_id INTEGER,
  interval_days INTEGER,
  alert_days_before INTEGER,
  notify_on_breach BOOLEAN,
  is_active BOOLEAN,
  created_by TEXT,
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  deleted_at TIMESTAMP,
  backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO rotation_policies_backup (id, name, description, scope, project_id, environment_id, interval_days, alert_days_before, notify_on_breach, is_active, created_by, created_at, updated_at, deleted_at)
  SELECT id, name, description, scope, project_id, environment_id, interval_days, alert_days_before, notify_on_breach, is_active, created_by, created_at, updated_at, deleted_at FROM rotation_policies;

-- Drop rotation_policies table
DROP TABLE IF EXISTS rotation_policies;
