-- Rollback RBAC Enhancements Migration
--
-- WARNING — DATA LOSS AFTER A GRACE WINDOW: before the `DROP TABLE IF EXISTS
-- rbac_audit_log` below, every row is copied into `rbac_audit_log_backup` so
-- that recovering from a bad RBAC deploy does not also erase the evidence of
-- what happened during it. That backup table is a TEMPORARY safety net only
-- — it is not cleaned up automatically, is not part of the live schema, and
-- should be exported/archived and dropped explicitly by an operator once the
-- rollback is confirmed safe; treat it as scratch, not permanent retained
-- storage. The backup insert is safe to re-run across repeated
-- rollback/re-upgrade/rollback cycles (it accumulates timestamped snapshots
-- rather than colliding with an earlier backup).

-- Drop indexes
DROP INDEX IF EXISTS idx_role_permissions_permission_id;
DROP INDEX IF EXISTS idx_role_permissions_role_id;
DROP INDEX IF EXISTS idx_permissions_action;
DROP INDEX IF EXISTS idx_permissions_resource;
DROP INDEX IF EXISTS idx_rbac_audit_log_created_at;
DROP INDEX IF EXISTS idx_rbac_audit_log_target;
DROP INDEX IF EXISTS idx_rbac_audit_log_actor;
DROP INDEX IF EXISTS idx_rbac_audit_log_action;
DROP INDEX IF EXISTS idx_group_roles_namespace_id;
DROP INDEX IF EXISTS idx_group_roles_role_id;
DROP INDEX IF EXISTS idx_group_roles_group_id;
DROP INDEX IF EXISTS idx_user_groups_group_id;
DROP INDEX IF EXISTS idx_user_groups_user_id;
DROP INDEX IF EXISTS idx_roles_name;
DROP INDEX IF EXISTS idx_users_username;
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_user_roles_namespace_id;
DROP INDEX IF EXISTS idx_user_roles_role_id;
DROP INDEX IF EXISTS idx_user_roles_user_id;

-- Back up the RBAC audit trail before it is dropped. See warning above:
-- this is a temporary safety net, not permanent storage.
CREATE TABLE IF NOT EXISTS rbac_audit_log_backup (
  backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
  id INTEGER,
  action TEXT,
  actor_user_id INTEGER,
  target_user_id INTEGER,
  role_id INTEGER,
  namespace_id INTEGER,
  details TEXT,
  created_at TIMESTAMP,
  backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO rbac_audit_log_backup (id, action, actor_user_id, target_user_id, role_id, namespace_id, details, created_at)
  SELECT id, action, actor_user_id, target_user_id, role_id, namespace_id, details, created_at FROM rbac_audit_log;

-- Drop tables
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS role_hierarchy;
DROP TABLE IF EXISTS rbac_audit_log;