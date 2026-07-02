-- Migration to add encrypted fields for authentication data
-- This migration adds encrypted storage for API secrets, session tokens, and password reset tokens
--
-- Target engine: SQLite. scripts/run_migrations.sh (the only path that actually
-- executes files in this directory) points golang-migrate at a `sqlite3://` DSN,
-- so every statement here must be valid SQLite. SQLite's ALTER TABLE only
-- supports one action per statement (no comma-separated multi-column ADD),
-- has no prefix-length index syntax (`col(255)`), and has no COMMENT ON —
-- column documentation is captured in SQL comments instead.

-- Add encrypted fields to api_clients table
-- encrypted_client_secret: AES-256-GCM encrypted client secret
ALTER TABLE api_clients ADD COLUMN encrypted_client_secret BLOB;
-- client_secret_metadata: encryption metadata (algorithm, nonce, key version)
ALTER TABLE api_clients ADD COLUMN client_secret_metadata JSON;

-- Add encrypted fields to sessions table
-- encrypted_session_token: AES-256-GCM encrypted session token
ALTER TABLE sessions ADD COLUMN encrypted_session_token BLOB;
-- session_token_metadata: encryption metadata (algorithm, nonce, key version)
ALTER TABLE sessions ADD COLUMN session_token_metadata JSON;

-- Add encrypted fields to api_tokens table
-- encrypted_token: AES-256-GCM encrypted API token
ALTER TABLE api_tokens ADD COLUMN encrypted_token BLOB;
-- token_metadata: encryption metadata (algorithm, nonce, key version)
ALTER TABLE api_tokens ADD COLUMN token_metadata JSON;

-- Add encrypted fields to password_resets table
-- encrypted_token: AES-256-GCM encrypted password reset token
ALTER TABLE password_resets ADD COLUMN encrypted_token BLOB;
-- token_metadata: encryption metadata (algorithm, nonce, key version)
ALTER TABLE password_resets ADD COLUMN token_metadata JSON;

-- Create indexes for better performance on encrypted fields.
-- SQLite has no prefix-length index syntax, so the full column is indexed.
CREATE INDEX idx_api_clients_encrypted_secret ON api_clients(encrypted_client_secret);
CREATE INDEX idx_sessions_encrypted_token ON sessions(encrypted_session_token);
CREATE INDEX idx_api_tokens_encrypted_token ON api_tokens(encrypted_token);
CREATE INDEX idx_password_resets_encrypted_token ON password_resets(encrypted_token);
