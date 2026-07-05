-- Rollback migration for authentication encryption fields
--
-- Target engine: SQLite (see scripts/run_migrations.sh, `sqlite3://` DSN).
-- SQLite's ALTER TABLE supports DROP COLUMN (3.35.0+) but only one action per
-- statement and has no IF EXISTS modifier, so each column drop is its own
-- statement, run only against a database that actually has the up-migration's
-- columns applied.
--
-- WARNING — DATA LOSS AFTER A GRACE WINDOW: this rollback DROPs the encrypted
-- credential columns themselves (encrypted_client_secret / encrypted_token /
-- encrypted_session_token and their metadata sidecars), not just schema. Each
-- column's values are copied into `auth_encryption_columns_backup` (keyed by
-- source table/row id/column name) immediately before that column is
-- dropped, so a forward migration back to 004 does not have to find those
-- rows credential-less — but that backup table is a TEMPORARY safety net
-- only. It is not restored automatically, is not part of the live schema, and
-- should be exported/archived and dropped explicitly by an operator once the
-- rollback is confirmed safe; do not treat it as permanent retained storage.
-- The backup inserts are safe to re-run across repeated
-- rollback/re-upgrade/rollback cycles (they accumulate timestamped snapshots
-- rather than colliding with an earlier backup).

-- Drop indexes
DROP INDEX IF EXISTS idx_password_resets_encrypted_token;
DROP INDEX IF EXISTS idx_api_tokens_encrypted_token;
DROP INDEX IF EXISTS idx_sessions_encrypted_token;
DROP INDEX IF EXISTS idx_api_clients_encrypted_secret;

-- Shared backup table for every encrypted_* / *_metadata column dropped
-- below. See warning above: this is a temporary safety net, not permanent
-- storage.
CREATE TABLE IF NOT EXISTS auth_encryption_columns_backup (
  backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_table TEXT NOT NULL,
  source_id INTEGER NOT NULL,
  column_name TEXT NOT NULL,
  column_value BLOB,
  backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Remove encrypted fields from password_resets table
INSERT INTO auth_encryption_columns_backup (source_table, source_id, column_name, column_value)
  SELECT 'password_resets', id, 'token_metadata', token_metadata FROM password_resets;
INSERT INTO auth_encryption_columns_backup (source_table, source_id, column_name, column_value)
  SELECT 'password_resets', id, 'encrypted_token', encrypted_token FROM password_resets;
ALTER TABLE password_resets DROP COLUMN token_metadata;
ALTER TABLE password_resets DROP COLUMN encrypted_token;

-- Remove encrypted fields from api_tokens table
INSERT INTO auth_encryption_columns_backup (source_table, source_id, column_name, column_value)
  SELECT 'api_tokens', id, 'token_metadata', token_metadata FROM api_tokens;
INSERT INTO auth_encryption_columns_backup (source_table, source_id, column_name, column_value)
  SELECT 'api_tokens', id, 'encrypted_token', encrypted_token FROM api_tokens;
ALTER TABLE api_tokens DROP COLUMN token_metadata;
ALTER TABLE api_tokens DROP COLUMN encrypted_token;

-- Remove encrypted fields from sessions table
INSERT INTO auth_encryption_columns_backup (source_table, source_id, column_name, column_value)
  SELECT 'sessions', id, 'session_token_metadata', session_token_metadata FROM sessions;
INSERT INTO auth_encryption_columns_backup (source_table, source_id, column_name, column_value)
  SELECT 'sessions', id, 'encrypted_session_token', encrypted_session_token FROM sessions;
ALTER TABLE sessions DROP COLUMN session_token_metadata;
ALTER TABLE sessions DROP COLUMN encrypted_session_token;

-- Remove encrypted fields from api_clients table
INSERT INTO auth_encryption_columns_backup (source_table, source_id, column_name, column_value)
  SELECT 'api_clients', id, 'client_secret_metadata', client_secret_metadata FROM api_clients;
INSERT INTO auth_encryption_columns_backup (source_table, source_id, column_name, column_value)
  SELECT 'api_clients', id, 'encrypted_client_secret', encrypted_client_secret FROM api_clients;
ALTER TABLE api_clients DROP COLUMN client_secret_metadata;
ALTER TABLE api_clients DROP COLUMN encrypted_client_secret;
