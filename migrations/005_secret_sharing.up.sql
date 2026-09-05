-- Migration: Add secret sharing schema
-- Version: 005

-- Add owner_id and is_shared columns to secret_nodes table
ALTER TABLE secret_nodes ADD COLUMN owner_id INTEGER REFERENCES users(id);
ALTER TABLE secret_nodes ADD COLUMN is_shared BOOLEAN DEFAULT FALSE;

-- Create index on owner_id for better query performance
CREATE INDEX idx_secret_nodes_owner_id ON secret_nodes(owner_id);

-- Create share_records table
CREATE TABLE share_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id INTEGER NOT NULL,
    owner_id INTEGER NOT NULL,
    -- recipient_id is polymorphic: a users(id) value when is_group=0, a
    -- groups(id) value when is_group=1 (see internal/storage/store/
    -- local_sharing.go, which resolves it against models.Group or models.User
    -- depending on the is_group flag below). A single-column FK can't
    -- reference two different tables depending on another column's value, so
    -- none is declared here -- matching the live GORM model
    -- (models.ShareRecord.RecipientID carries no FK tag, for the same
    -- reason). A hard FK to users(id) here would reject every group share
    -- whose recipient_id is a groups(id) value that doesn't happen to also
    -- collide with a users(id) value.
    recipient_id INTEGER NOT NULL,
    is_group BOOLEAN DEFAULT FALSE,
    permission TEXT DEFAULT 'read',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP,
    FOREIGN KEY (secret_id) REFERENCES secret_nodes(id),
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- Create indexes for better query performance
CREATE INDEX idx_share_records_secret_id ON share_records(secret_id);
CREATE INDEX idx_share_records_owner_id ON share_records(owner_id);
CREATE INDEX idx_share_records_recipient_id ON share_records(recipient_id);
CREATE INDEX idx_share_records_deleted_at ON share_records(deleted_at);

-- Update existing secrets to attribute ownership to their actual creator.
-- secret_nodes.created_by already records the username of whoever created the
-- row (see internal/core, e.g. secrets.go/secret_copy.go), so match against
-- that instead of guessing a single account for every unowned secret. A
-- hardcoded 'admin' would silently reassign ownership of every pre-existing
-- secret to whichever account happens to be named exactly "admin" (or leave
-- owner_id NULL forever if none exists), regardless of who actually created
-- it — a real attribution/authorization bug, not just a cosmetic default.
-- Rows whose created_by is blank, or whose creating account no longer
-- exists, are intentionally left with owner_id NULL: an explicit unowned
-- state is safer than guessing, since misattributing ownership would grant
-- an unrelated account sharing/management rights over a secret it never
-- created.
UPDATE secret_nodes SET owner_id = (
    SELECT id FROM users WHERE users.username = secret_nodes.created_by
) WHERE owner_id IS NULL AND created_by IS NOT NULL AND created_by != ''; -- NOSONAR -- plsql:NullComparison false positive: IS NULL/IS NOT NULL is correct SQLite syntax

-- Add a trigger to automatically set is_shared flag when shares are created
CREATE TRIGGER update_secret_shared_status_insert
AFTER INSERT ON share_records
BEGIN
    UPDATE secret_nodes SET is_shared = TRUE WHERE id = NEW.secret_id;
END;

-- Add a trigger to update is_shared flag when all shares are deleted
CREATE TRIGGER update_secret_shared_status_delete
AFTER DELETE ON share_records
BEGIN
    UPDATE secret_nodes SET is_shared = (
        SELECT EXISTS(SELECT 1 FROM share_records WHERE secret_id = OLD.secret_id AND deleted_at IS NULL)
    ) WHERE id = OLD.secret_id;
END;