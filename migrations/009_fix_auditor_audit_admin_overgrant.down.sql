-- Revert 009_fix_auditor_audit_admin_overgrant.up.sql: restore the
-- 'audit.admin' grant on the 'auditor' role.
--
-- WARNING: this recreates the original, over-broad grant that
-- findings-unreviewed/migrations.json#1 flags (medium severity) -- the
-- 'auditor' role, documented as read-only, regaining "Full administrative
-- access to audit system". This down-migration exists only for symmetry
-- with the rest of this directory's reversible migrations (see
-- migrations/README.md); do not apply it to a production database without
-- understanding that it reintroduces the finding.
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'auditor' AND p.name = 'audit.admin';
