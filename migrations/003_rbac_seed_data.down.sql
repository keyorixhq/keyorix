-- Rollback RBAC Seed Data Migration
--
-- WARNING — DATA LOSS AFTER A GRACE WINDOW: before each DELETE below, the
-- rows about to be removed are copied into a same-database `*_backup` table,
-- matching the pattern already established by 002/004/005/007/008's
-- down-migrations (see their own header comments for the full rationale) --
-- this file previously deleted seed roles/permissions/role_permissions/
-- namespaces/zones/environments with no such safety net, unlike its
-- siblings. These backup tables are a TEMPORARY safety net only -- they are
-- not part of the live schema, are not cleaned up automatically, and are not
-- a substitute for a real external backup; export/archive them and drop them
-- explicitly once the rollback is confirmed safe. The backup inserts are
-- safe to re-run across repeated rollback/re-upgrade/rollback cycles (they
-- accumulate timestamped snapshots rather than colliding with an earlier
-- backup).
--
-- Note: this rollback can still fail outright (not just lose data silently)
-- if any of these rows are still referenced elsewhere with an enforced
-- foreign key -- e.g. deleting a namespace that still has secret_nodes rows
-- pointing at it, or user_roles/group_roles rows still pointing at a role
-- about to be deleted (neither is CASCADE). That failure aborts the whole
-- migration transaction before anything is left partially applied, so the
-- backups below exist for the case where the deletes DO succeed, not to
-- paper over that separate failure mode.

-- Back up and remove default role permissions
CREATE TABLE IF NOT EXISTS role_permissions_backup (
  backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
  role_id INTEGER,
  permission_id INTEGER,
  backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO role_permissions_backup (role_id, permission_id)
  SELECT role_id, permission_id FROM role_permissions WHERE role_id IN (
    SELECT id FROM roles WHERE name IN ('super_admin', 'admin', 'editor', 'viewer', 'auditor')
  );
DELETE FROM role_permissions WHERE role_id IN (
  SELECT id FROM roles WHERE name IN ('super_admin', 'admin', 'editor', 'viewer', 'auditor')
);

-- Back up and remove default permissions
CREATE TABLE IF NOT EXISTS permissions_backup (
  backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
  id INTEGER,
  name TEXT,
  description TEXT,
  resource TEXT,
  action TEXT,
  created_at TIMESTAMP,
  backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO permissions_backup (id, name, description, resource, action, created_at)
  SELECT id, name, description, resource, action, created_at FROM permissions
  WHERE resource IN ('secrets', 'users', 'roles', 'system', 'audit', 'namespaces');
DELETE FROM permissions WHERE resource IN ('secrets', 'users', 'roles', 'system', 'audit', 'namespaces');

-- Back up and remove default roles
CREATE TABLE IF NOT EXISTS roles_backup (
  backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
  id INTEGER,
  name TEXT,
  description TEXT,
  backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO roles_backup (id, name, description)
  SELECT id, name, description FROM roles WHERE name IN ('super_admin', 'admin', 'editor', 'viewer', 'auditor');
DELETE FROM roles WHERE name IN ('super_admin', 'admin', 'editor', 'viewer', 'auditor');

-- Back up and remove default environments
CREATE TABLE IF NOT EXISTS environments_backup (
  backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
  id INTEGER,
  name TEXT,
  backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO environments_backup (id, name)
  SELECT id, name FROM environments WHERE name IN ('production', 'staging', 'development', 'testing');
DELETE FROM environments WHERE name IN ('production', 'staging', 'development', 'testing');

-- Back up and remove default zones
CREATE TABLE IF NOT EXISTS zones_backup (
  backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
  id INTEGER,
  name TEXT,
  description TEXT,
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO zones_backup (id, name, description, created_at, updated_at)
  SELECT id, name, description, created_at, updated_at FROM zones
  WHERE name IN ('global', 'us-east-1', 'us-west-2', 'eu-west-1');
DELETE FROM zones WHERE name IN ('global', 'us-east-1', 'us-west-2', 'eu-west-1');

-- Back up and remove default namespaces
CREATE TABLE IF NOT EXISTS namespaces_backup (
  backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
  id INTEGER,
  name TEXT,
  description TEXT,
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  deleted_at TIMESTAMP,
  backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO namespaces_backup (id, name, description, created_at, updated_at, deleted_at)
  SELECT id, name, description, created_at, updated_at, deleted_at FROM namespaces
  WHERE name IN ('default', 'production', 'staging', 'development');
DELETE FROM namespaces WHERE name IN ('default', 'production', 'staging', 'development');
