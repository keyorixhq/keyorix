-- Drop sessions' dead reversible-encryption columns (#1641).
--
-- Target engine: SQLite (see scripts/run_migrations.sh, `sqlite3://` DSN).
-- SQLite's ALTER TABLE supports DROP COLUMN (3.35.0+) but only one action per
-- statement and has no IF EXISTS modifier.
--
-- Verified dead, not merely unused: the live session-creation write path
-- (CreateSession, internal/storage/store/local_auth.go) has only ever
-- populated sessions.session_token with a SHA-256 hash -- never
-- encrypted_session_token. No code path in this repo's history has ever
-- written that column, so there is no legacy plaintext-recoverable data to
-- preserve. Contrast with api_clients.encrypted_client_secret and
-- api_tokens.encrypted_token, which DO have real legacy rows from before the
-- admin-managed API-client/API-token issuance routes were removed
-- (server/http/router.go, finding #131) -- those two tables' columns and
-- their DEK-rotation sweep (sweepAPITokens/sweepAPIClients,
-- internal/encryption/sweep_auth.go) are deliberately KEPT, not dropped here.
--
-- A backup table is still populated before the drop, matching 004's own
-- destructive-drop convention (#203) as defense in depth in case any
-- out-of-band row was ever written outside this repo's own code.
DROP INDEX IF EXISTS idx_sessions_encrypted_token;

CREATE TABLE IF NOT EXISTS auth_encryption_columns_backup (
  backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_table TEXT NOT NULL,
  source_id INTEGER NOT NULL,
  column_name TEXT NOT NULL,
  column_value BLOB,
  backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO auth_encryption_columns_backup (source_table, source_id, column_name, column_value)
  SELECT 'sessions', id, 'session_token_metadata', session_token_metadata FROM sessions
  WHERE session_token_metadata IS NOT NULL;
INSERT INTO auth_encryption_columns_backup (source_table, source_id, column_name, column_value)
  SELECT 'sessions', id, 'encrypted_session_token', encrypted_session_token FROM sessions
  WHERE encrypted_session_token IS NOT NULL;

ALTER TABLE sessions DROP COLUMN session_token_metadata;
ALTER TABLE sessions DROP COLUMN encrypted_session_token;
