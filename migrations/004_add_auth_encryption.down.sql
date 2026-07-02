-- Rollback migration for authentication encryption fields
--
-- Target engine: SQLite (see scripts/run_migrations.sh, `sqlite3://` DSN).
-- SQLite's ALTER TABLE supports DROP COLUMN (3.35.0+) but only one action per
-- statement and has no IF EXISTS modifier, so each column drop is its own
-- statement, run only against a database that actually has the up-migration's
-- columns applied.

-- Drop indexes
DROP INDEX IF EXISTS idx_password_resets_encrypted_token;
DROP INDEX IF EXISTS idx_api_tokens_encrypted_token;
DROP INDEX IF EXISTS idx_sessions_encrypted_token;
DROP INDEX IF EXISTS idx_api_clients_encrypted_secret;

-- Remove encrypted fields from password_resets table
ALTER TABLE password_resets DROP COLUMN token_metadata;
ALTER TABLE password_resets DROP COLUMN encrypted_token;

-- Remove encrypted fields from api_tokens table
ALTER TABLE api_tokens DROP COLUMN token_metadata;
ALTER TABLE api_tokens DROP COLUMN encrypted_token;

-- Remove encrypted fields from sessions table
ALTER TABLE sessions DROP COLUMN session_token_metadata;
ALTER TABLE sessions DROP COLUMN encrypted_session_token;

-- Remove encrypted fields from api_clients table
ALTER TABLE api_clients DROP COLUMN client_secret_metadata;
ALTER TABLE api_clients DROP COLUMN encrypted_client_secret;
