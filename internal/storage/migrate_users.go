package storage

// migrateDatabase steps for users, password_histories and setup_tokens.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// alterUsers is one of migrateDatabase's ordered steps (factory.go).
func alterUsers(db *gorm.DB, exec func(string) error) error {
	// Timestamp ALTERs below: unreachable from a supported upgrade source; see sqlTimestampType (#3440).
	// Track last successful login per user (nil = never logged in).
	if tableExists(db, "users") && !columnExists(db, "users", "last_login_at") {
		if err := exec("ALTER TABLE users ADD COLUMN last_login_at " + sqlTimestampType(db)); err != nil {
			return err
		}
	}

	// Track when the current password was set, for max-age expiry (ADR-025).
	if tableExists(db, "users") && !columnExists(db, "users", "password_changed_at") {
		if err := exec("ALTER TABLE users ADD COLUMN password_changed_at " + sqlTimestampType(db)); err != nil {
			return err
		}
	}

	// Account lifecycle state (ADR-025). Existing rows default to active.
	if tableExists(db, "users") && !columnExists(db, "users", "account_state") {
		if err := exec("ALTER TABLE users ADD COLUMN account_state TEXT NOT NULL DEFAULT 'active'"); err != nil {
			return err
		}
	}

	// MFA/TOTP opt-in flag. Existing rows default to false (MFA off).
	if tableExists(db, "users") && !columnExists(db, "users", "mfa_enabled") {
		if err := exec("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT false"); err != nil {
			return err
		}
	}

	// SCIM external ID (RFC 7644). Additive; empty for locally-created users.
	if tableExists(db, "users") && !columnExists(db, "users", "external_id") {
		if err := exec("ALTER TABLE users ADD COLUMN external_id TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}

	// Per-account login lockout (brute-force protection). Additive; safe on existing DBs.
	if tableExists(db, "users") {
		if !columnExists(db, "users", "failed_login_attempts") {
			if err := exec("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0"); err != nil {
				return err
			}
		}
		if !columnExists(db, "users", "last_failed_login_at") {
			if err := exec("ALTER TABLE users ADD COLUMN last_failed_login_at " + sqlTimestampType(db)); err != nil {
				return err
			}
		}
		if !columnExists(db, "users", "login_locked_until") {
			if err := exec("ALTER TABLE users ADD COLUMN login_locked_until " + sqlTimestampType(db)); err != nil {
				return err
			}
		}
		if !columnExists(db, "users", "login_lockout_count") {
			if err := exec("ALTER TABLE users ADD COLUMN login_lockout_count INTEGER NOT NULL DEFAULT 0"); err != nil {
				return err
			}
		}
	}

	// One-time-password expiry (OTP-EXPIRY-1). Adding the column and the one-off
	// legacy backfill share one transaction, so a crash between them cannot leave the
	// column present with the backfill never run (the column's absence is what
	// gates the backfill, so it must not be re-runnable on a later boot).
	if tableExists(db, "users") && !columnExists(db, "users", "one_time_password_expires_at") {
		if err := db.Transaction(func(tx *gorm.DB) error {
			// Via the Migrator, not a hand-written ALTER: it picks the dialect's own
			// timestamp type (datetime on SQLite, timestamptz on Postgres). A literal
			// "TIMESTAMP WITH TIME ZONE" makes the SQLite driver hand the value back as
			// a string that cannot be scanned into the model's *time.Time, which would
			// fail every login of an account carrying a backfilled expiry.
			if err := tx.Migrator().AddColumn(&models.User{}, "OneTimePasswordExpiresAt"); err != nil {
				return err
			}
			return backfillLegacyOneTimePasswordExpiry(tx, time.Now().UTC())
		}); err != nil {
			return fmt.Errorf("failed to add users.one_time_password_expires_at: %w", err)
		}
	}

	// Administrator MFA reset (RECOVERY-MFA-RESET-1). Existing rows default to false:
	// nobody owes an enrolment they were never reset into.
	if tableExists(db, "users") && !columnExists(db, "users", "mfa_enrolment_required") {
		if err := exec("ALTER TABLE users ADD COLUMN mfa_enrolment_required BOOLEAN NOT NULL DEFAULT false"); err != nil {
			return err
		}
	}
	return nil
}

// createPasswordHistories is one of migrateDatabase's ordered steps (factory.go).
func createPasswordHistories(db *gorm.DB, pwHistExists bool) error {
	// Create password_histories if missing (ADR-025 history_count, additive).
	if !pwHistExists {
		if err := db.AutoMigrate(&models.PasswordHistory{}); err != nil {
			return fmt.Errorf("failed to migrate password_histories table: %w", err)
		}
	}
	return nil
}

// createSetupTokens is one of migrateDatabase's ordered steps (factory.go).
func createSetupTokens(db *gorm.DB, setupTokenExists bool) error {
	// Create setup_tokens if missing (ADR-028 credential delivery, additive).
	if !setupTokenExists {
		if err := db.AutoMigrate(&models.SetupToken{}); err != nil {
			return fmt.Errorf("failed to migrate setup_tokens table: %w", err)
		}
	}
	return nil
}

// alterUserIdentityIndexes is one of migrateDatabase's ordered steps (factory.go).
func alterUserIdentityIndexes(db *gorm.DB, exec func(string) error) error {
	// Swap the plain unique index on users.username for a partial one (live rows only),
	// so a SCIM-deprovisioned username can be re-provisioned. Additive + idempotent; the
	// full AutoMigrate below covers fresh DBs.
	if tableExists(db, "users") {
		// users.username_folded and users.email_folded (#1642) -- the same
		// missing-column shape as groups.name_folded above and roles.name_folded
		// below. ensureUserNameIndex/ensureUserEmailIndex each call
		// backfillFoldedColumn, which reads the folded column before anything has
		// created it. groups fails first on a pre-#1642 database, so these two
		// were still queued behind it when the groups failure was found;
		// confirmed absent on the same real database (information_schema showed
		// no *_folded column on users at all). Fixing only the column that
		// happens to error first would have moved the crash one line down.
		if !columnExists(db, "users", "username_folded") {
			if err := exec("ALTER TABLE users ADD COLUMN username_folded TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
		if !columnExists(db, "users", "email_folded") {
			if err := exec("ALTER TABLE users ADD COLUMN email_folded TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
		if err := ensureUserNameIndex(db); err != nil {
			return err
		}
		// Add a DB-level, case-insensitive, live-rows-only unique index on users.email
		// (#117): CreateUser/signup/invite-accept/SCIM provisioning previously enforced
		// email uniqueness only via a check-then-act read, letting concurrent creates for
		// the identical email all succeed and leaving GetUserByEmail to resolve to an
		// arbitrary one of the resulting rows. Additive + idempotent; the full AutoMigrate
		// below covers fresh DBs.
		if err := ensureUserEmailIndex(db); err != nil {
			return err
		}
		// Same DB-level protection for users.external_id (#117): the SCIM/IdP-asserted
		// identifier was indexed but NOT unique, so two different users could share the
		// same non-empty external_id — an ambiguity GetUserByExternalID (SSO/SCIM login
		// resolution) must not tolerate. Additive + idempotent; the full AutoMigrate
		// below covers fresh DBs.
		if err := ensureUserExternalIDIndex(db); err != nil {
			return err
		}
	}
	return nil
}
