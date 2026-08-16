-- Corrective migration: revoke the over-broad 'audit.admin' grant from the
-- legacy 'auditor' role.
--
-- 003_rbac_seed_data.up.sql defines 'auditor' as "Can view audit logs and
-- system information" (read-only intent) but then granted it BOTH
-- 'audit.read' and 'audit.admin' -- where 'audit.admin' is separately
-- documented in that same seed data as "Full administrative access to audit
-- system". That is inconsistent with the live application's canonical
-- auditor definitions (internal/core/auth_bootstrap.go's system_auditor /
-- project_auditor roles), which grant only 'audit.read', never an
-- admin-tier audit permission.
--
-- Per migrations/README.md, the authoritative schema mechanism is GORM
-- AutoMigrate, which is strictly additive on existing databases -- it never
-- removes or downgrades a previously granted role_permissions row. Any
-- database originally bootstrapped from migrations 001-003 therefore keeps
-- this over-grant forever unless it is explicitly revoked, which is what
-- this migration does. Editing 003 in place would only affect fresh installs
-- and would rewrite already-applied migration history; this migration
-- instead corrects the grant going forward for already-seeded databases,
-- and is idempotent (a re-run after the grant is already gone is a no-op).
--
-- Only the 'auditor' role is targeted: 'super_admin' is intentionally
-- granted every permission, and 'admin' was never granted 'audit.admin' by
-- 003 in the first place (it only ever received 'audit.read').
DELETE FROM role_permissions
WHERE role_id = (SELECT id FROM roles WHERE name = 'auditor')
  AND permission_id = (SELECT id FROM permissions WHERE name = 'audit.admin');
