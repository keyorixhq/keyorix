-- Corrective migration: keep secret_nodes.is_shared synchronized with real
-- share revocations performed through a soft delete, not just a raw SQL
-- DELETE.
--
-- 005_secret_sharing.up.sql's update_secret_shared_status_delete trigger
-- fires AFTER DELETE ON share_records and recomputes secret_nodes.is_shared.
-- But share_records has its own deleted_at soft-delete column, and the
-- application's actual revoke/expiry paths (internal/storage/store/
-- local_sharing.go's DeleteShareRecord and DeleteExpiredShareRecords) both
-- perform a GORM soft delete -- an UPDATE setting deleted_at -- never a raw
-- SQL DELETE, by that file's own doc comments. So the AFTER DELETE trigger
-- never fires under normal application usage: once a secret is shared
-- (is_shared flips to TRUE via the sibling AFTER INSERT trigger, which DOES
-- fire on GORM Create) and every share on it is later revoked, is_shared
-- never flips back to FALSE.
--
-- Per migrations/README.md, GORM AutoMigrate is the live, authoritative
-- schema mechanism, and it never creates or manages SQL triggers -- it only
-- adds missing tables/columns/indexes. A fresh/AutoMigrate-only install
-- never runs these legacy *.sql files at all, so it never has either
-- trigger (or this bug) in the first place. This migration only matters for
-- a database originally bootstrapped from migrations 001-005 (before
-- AutoMigrate existed): AutoMigrate being additive-only means it can never
-- retire that database's stale 005 trigger, so the gap persists forever on
-- such a database unless corrected here -- the same reasoning
-- 009_fix_auditor_audit_admin_overgrant applied to the legacy 001-003 seed
-- data.
--
-- Fix: add a trigger that also fires on the soft-delete UPDATE path and
-- recomputes is_shared the same way the existing AFTER DELETE trigger does.
-- That AFTER DELETE trigger is left in place -- harmless, and still correct
-- if a hard DELETE is ever issued directly against share_records.
CREATE TRIGGER update_secret_shared_status_soft_delete
AFTER UPDATE OF deleted_at ON share_records
BEGIN
    UPDATE secret_nodes SET is_shared = (
        SELECT EXISTS(SELECT 1 FROM share_records WHERE secret_id = NEW.secret_id AND deleted_at IS NULL)
    ) WHERE id = NEW.secret_id;
END;
