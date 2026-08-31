-- Rollback for 011: re-add sessions' dropped reversible-encryption columns,
-- restoring any backed-up values from auth_encryption_columns_backup.
--
-- Target engine: SQLite (see scripts/run_migrations.sh, `sqlite3://` DSN).

ALTER TABLE sessions ADD COLUMN encrypted_session_token BLOB;
ALTER TABLE sessions ADD COLUMN session_token_metadata JSON;

CREATE INDEX IF NOT EXISTS idx_sessions_encrypted_token ON sessions(encrypted_session_token);

UPDATE sessions
SET encrypted_session_token = (
  SELECT column_value FROM auth_encryption_columns_backup
  WHERE source_table = 'sessions' AND column_name = 'encrypted_session_token' AND source_id = sessions.id
  ORDER BY backed_up_at DESC LIMIT 1
)
WHERE EXISTS (
  SELECT 1 FROM auth_encryption_columns_backup
  WHERE source_table = 'sessions' AND column_name = 'encrypted_session_token' AND source_id = sessions.id
);

UPDATE sessions
SET session_token_metadata = (
  SELECT column_value FROM auth_encryption_columns_backup
  WHERE source_table = 'sessions' AND column_name = 'session_token_metadata' AND source_id = sessions.id
  ORDER BY backed_up_at DESC LIMIT 1
)
WHERE EXISTS (
  SELECT 1 FROM auth_encryption_columns_backup
  WHERE source_table = 'sessions' AND column_name = 'session_token_metadata' AND source_id = sessions.id
);
