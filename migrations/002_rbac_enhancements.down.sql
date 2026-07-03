-- Rollback RBAC Enhancements Migration
--
-- WARNING — IRREVERSIBLE DATA LOSS: `DROP TABLE IF EXISTS rbac_audit_log`
-- below permanently destroys the RBAC audit trail — using this rollback to
-- recover from a bad RBAC deploy also erases the evidence of what happened
-- during it. BACK UP rbac_audit_log (or export it to a backup table) before
-- running this rollback.

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

-- Drop tables
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS role_hierarchy;
DROP TABLE IF EXISTS rbac_audit_log;