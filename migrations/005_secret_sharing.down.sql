-- Migration: Remove secret sharing schema
-- Version: 005
--
-- WARNING — DATA LOSS AFTER A GRACE WINDOW: before the
-- `DROP TABLE IF EXISTS share_records` below, every row is copied into
-- `share_records_backup` so that rolling back does not permanently destroy
-- the record of who shared what secret with whom, and when. That backup
-- table is a TEMPORARY safety net only — it is not part of the live schema
-- and is not cleaned up automatically; an operator should export/archive it
-- and drop it explicitly once the rollback is confirmed safe. The backup
-- insert is safe to re-run across repeated rollback/re-upgrade/rollback
-- cycles (it accumulates timestamped snapshots rather than colliding with an
-- earlier backup).

-- Drop triggers
DROP TRIGGER IF EXISTS update_secret_shared_status_insert;
DROP TRIGGER IF EXISTS update_secret_shared_status_delete;

-- Back up share_records before dropping it. See warning above: this is a
-- temporary safety net, not permanent storage.
CREATE TABLE IF NOT EXISTS share_records_backup (
  backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
  id INTEGER,
  secret_id INTEGER,
  owner_id INTEGER,
  recipient_id INTEGER,
  is_group BOOLEAN,
  permission TEXT,
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  deleted_at TIMESTAMP,
  backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO share_records_backup (id, secret_id, owner_id, recipient_id, is_group, permission, created_at, updated_at, deleted_at)
  SELECT id, secret_id, owner_id, recipient_id, is_group, permission, created_at, updated_at, deleted_at FROM share_records;

-- Drop share_records table and its indexes
DROP INDEX IF EXISTS idx_share_records_secret_id;
DROP INDEX IF EXISTS idx_share_records_owner_id;
DROP INDEX IF EXISTS idx_share_records_recipient_id;
DROP INDEX IF EXISTS idx_share_records_deleted_at;
DROP TABLE IF EXISTS share_records;

-- Remove the sharing-specific column from secret_nodes.
--
-- DELIBERATE DEVIATION from a literal "undo everything this migration added"
-- reading: the up-migration added TWO columns to secret_nodes, `owner_id` and
-- `is_shared`, but only `is_shared` is dropped here. `owner_id` started as
-- sharing-support metadata in this migration, but it has since become load
-- bearing for core secret ownership tracking that has nothing to do with the
-- "sharing" feature specifically: internal/core/secret_ownership.go's
-- TransferSecretOwnership flow, internal/core/permissions.go's
-- CheckSecretPermission (the owner gets PermissionOwner — the highest
-- permission level, independent of any share), access reviews
-- (access_review.go/access_review_revoke.go), blast-radius analysis
-- (blast_radius.go), secret risk scoring (secret_risk.go), and the secret
-- inventory report (secret_inventory.go) all key off `SecretNode.OwnerID`.
-- Dropping it here would silently blow away who owns every secret in the
-- system — a far larger, wrong-scoped removal than "undo secret sharing",
-- and would break all of the above on any code path that still expects the
-- column/model field to exist. `is_shared`, by contrast, only ever feeds
-- sharing-specific list/filter/display logic (secret_listing_sharing.go,
-- the `ShowSharedOnly` filter in secret_listing_query.go, and the CLI's
-- `secret info --shared` line) and is entirely recomputed from
-- `share_records` by the two triggers above — it carries no data that
-- doesn't already live in `share_records_backup`, so it is safe to drop with
-- no separate backup of its own.
--
-- SQLite doesn't support dropping a column with data preserved elsewhere in
-- the same statement (nor, prior to 3.35, at all), so the table is recreated
-- without `is_shared`, keeping every other column — including `owner_id` —
-- intact. Note: by the time this file runs in a normal sequential rollback
-- (golang-migrate always applies down-migrations in descending order, i.e.
-- 008 -> 007 -> 006 -> 005), 006's down-migration has already renamed
-- `project_id` back to `namespace_id`, so `namespace_id` (not `project_id`)
-- is the correct column name here — matching what 001_init.sql originally
-- created and what 006's down-migration restores.
PRAGMA foreign_keys=off;

CREATE TABLE secret_nodes_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  parent_id INTEGER REFERENCES secret_nodes_new(id) ON DELETE CASCADE,
  namespace_id INTEGER NOT NULL REFERENCES namespaces(id),
  zone_id INTEGER NOT NULL REFERENCES zones(id),
  environment_id INTEGER NOT NULL REFERENCES environments(id),
  name TEXT NOT NULL,
  is_secret BOOLEAN NOT NULL DEFAULT 0,
  type TEXT,
  max_reads INTEGER,
  expiration TIMESTAMP,
  metadata TEXT,
  status TEXT DEFAULT 'active',
  created_by TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  owner_id INTEGER REFERENCES users(id)
);

INSERT INTO secret_nodes_new (id, parent_id, namespace_id, zone_id, environment_id, name, is_secret, type, max_reads, expiration, metadata, status, created_by, created_at, updated_at, owner_id)
  SELECT id, parent_id, namespace_id, zone_id, environment_id, name, is_secret, type, max_reads, expiration, metadata, status, created_by, created_at, updated_at, owner_id FROM secret_nodes;

DROP INDEX IF EXISTS idx_secret_nodes_owner_id;
DROP TABLE secret_nodes;
ALTER TABLE secret_nodes_new RENAME TO secret_nodes;

-- owner_id survives the rebuild, so its index is recreated (unlike a column
-- that's genuinely being removed, this one still needs to be queried).
CREATE INDEX idx_secret_nodes_owner_id ON secret_nodes(owner_id);

PRAGMA foreign_keys=on;
