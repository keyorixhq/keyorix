package storage

// migrateDatabase steps for personal access tokens, MFA, WebAuthn, login attempts, recovery keys and SSO login state.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// createPersonalAccessTokens is one of migrateDatabase's ordered steps (factory.go).
func createPersonalAccessTokens(db *gorm.DB, patExists bool) error {
	// Create personal_access_tokens if missing (ADR-027, additive, safe on existing DBs);
	// otherwise add only the ADR-042 per-token scoping columns via the Migrator (same
	// pgx hazard as the notifications/invitations blocks — never full-AutoMigrate an
	// existing table here). Defaults leave existing tokens unrestricted (back-compat).
	if !patExists {
		if err := db.AutoMigrate(&models.PersonalAccessToken{}); err != nil {
			return fmt.Errorf("failed to migrate personal_access_tokens table: %w", err)
		}
	} else {
		m := db.Migrator()
		for _, col := range []string{"Scopes", "ProjectScope", "EnvironmentScope"} {
			if !m.HasColumn(&models.PersonalAccessToken{}, col) {
				if err := m.AddColumn(&models.PersonalAccessToken{}, col); err != nil {
					return fmt.Errorf("failed to add personal_access_tokens.%s column: %w", col, err)
				}
			}
		}
	}
	return nil
}

// createMFATables is one of migrateDatabase's ordered steps (factory.go).
func createMFATables(db *gorm.DB, mfaSecretExists, mfaRecoveryExists, mfaChallengeExists, mfaStepUpGrantExists bool) error {
	// Create the MFA tables if missing (TOTP MFA, additive, safe on existing DBs).
	if !mfaSecretExists {
		if err := db.AutoMigrate(&models.MFASecret{}); err != nil {
			return fmt.Errorf("failed to migrate mfa_secrets table: %w", err)
		}
	}
	if !mfaRecoveryExists {
		if err := db.AutoMigrate(&models.MFARecoveryCode{}); err != nil {
			return fmt.Errorf("failed to migrate mfa_recovery_codes table: %w", err)
		}
	}
	if !mfaChallengeExists {
		if err := db.AutoMigrate(&models.MFAChallenge{}); err != nil {
			return fmt.Errorf("failed to migrate mfa_challenges table: %w", err)
		}
	} else if m := db.Migrator(); !m.HasColumn(&models.MFAChallenge{}, "LoginAttemptID") {
		// #2936 item 4: the login-budget slot the password step keeps. Additive
		// and nullable (nil = nothing to hand back), via the Migrator like the
		// other columns added to existing tables here.
		if err := m.AddColumn(&models.MFAChallenge{}, "LoginAttemptID"); err != nil {
			return fmt.Errorf("failed to add mfa_challenges.login_attempt_id column: %w", err)
		}
	}
	// mfa_step_up_grants. store-mfa-002 found that MFAStepUpGrant "was never
	// migrated anywhere" and fixed it by adding the model to the bulk
	// AutoMigrate list -- which sits AFTER `if projectsExists { return nil }`,
	// so the fix only ever reached fresh installs. The original finding was
	// that the table did not exist on any database; it still does not exist on
	// any UPGRADED one. Same shape as #1642's folded columns: a fresh-DB-only
	// remedy for an every-install problem.
	//
	// Consequence on an upgraded install, confirmed against the DAST rig's real
	// Postgres volume (2026-09-11), where this table is the only one of the
	// fresh-path models absent:
	//
	//   Create/GetActiveMFAStepUpGrant and PruneMFAStepUpGrants all fail with
	//   "relation \"mfa_step_up_grants\" does not exist", so the
	//   mfa_stepup_grant_prune scheduler errors every cycle, and -- with
	//   classification.restricted_requires_mfa_step_up enabled --
	//   checkRestrictedMFAGate turns that error into
	//   "secret %q is restricted: could not verify MFA step-up: ...".
	//
	// That gate fails CLOSED, so this is not a bypass: restricted secrets
	// become unreadable rather than readable without a second factor. It is
	// still a total functional break of the protection tier meant for the most
	// sensitive secrets, and unrecoverable in place, since minting a grant
	// needs the same missing table.
	if !mfaStepUpGrantExists {
		if err := db.AutoMigrate(&models.MFAStepUpGrant{}); err != nil {
			return fmt.Errorf("failed to migrate mfa_step_up_grants table: %w", err)
		}
	}
	return nil
}

// createWebAuthnTables is one of migrateDatabase's ordered steps (factory.go).
func createWebAuthnTables(db *gorm.DB, webauthnCredExists, webauthnSessExists bool) error {
	// Create the WebAuthn tables if missing (ADR-036, additive, safe on existing DBs).
	if !webauthnCredExists {
		if err := db.AutoMigrate(&models.WebAuthnCredential{}); err != nil {
			return fmt.Errorf("failed to migrate web_authn_credentials table: %w", err)
		}
	}
	if !webauthnSessExists {
		if err := db.AutoMigrate(&models.WebAuthnSession{}); err != nil {
			return fmt.Errorf("failed to migrate web_authn_sessions table: %w", err)
		}
	} else if m := db.Migrator(); !m.HasColumn(&models.WebAuthnSession{}, "LoginAttemptID") {
		// #2936 review: the login-budget slot a WebAuthn Begin keeps. Additive
		// and nullable, as for mfa_challenges above.
		if err := m.AddColumn(&models.WebAuthnSession{}, "LoginAttemptID"); err != nil {
			return fmt.Errorf("failed to add web_authn_sessions.login_attempt_id column: %w", err)
		}
	}
	return nil
}

// createLoginAttempts is one of migrateDatabase's ordered steps (factory.go).
func createLoginAttempts(db *gorm.DB, loginAttemptExists bool) error {
	// Create the login_attempts table if missing (ADR-040 rate limiting, additive).
	if !loginAttemptExists {
		if err := db.AutoMigrate(&models.LoginAttempt{}); err != nil {
			return fmt.Errorf("failed to migrate login_attempts table: %w", err)
		}
	} else if m := db.Migrator(); !m.HasColumn(&models.LoginAttempt{}, "ReservationKey") {
		// Identifiable login-budget reservations (#2956 follow-up). Additive and
		// nullable (existing rows were never reservations), plus its unique index.
		if err := m.AddColumn(&models.LoginAttempt{}, "ReservationKey"); err != nil {
			return fmt.Errorf("failed to add login_attempts.reservation_key column: %w", err)
		}
		if err := m.CreateIndex(&models.LoginAttempt{}, "idx_login_attempt_reservation_key"); err != nil {
			return fmt.Errorf("failed to index login_attempts.reservation_key: %w", err)
		}
	}
	return nil
}

// createRecoveryKeyRecords is one of migrateDatabase's ordered steps (factory.go).
func createRecoveryKeyRecords(db *gorm.DB) error {
	// Recovery-key verifier record (design-b2-recover-admin.md §2). Additive,
	// safe on existing DBs: a singleton table, empty until `keyorix-server
	// admin recovery-key rotate` (or recover-admin's own retrofit path)
	// generates the first key.
	if err := db.AutoMigrate(&models.RecoveryKeyRecord{}); err != nil {
		return fmt.Errorf("failed to migrate recovery_key_records table: %w", err)
	}
	return nil
}

// createSSOLoginStates is one of migrateDatabase's ordered steps (factory.go).
func createSSOLoginStates(db *gorm.DB, ssoLoginStateExists bool) error {
	// Create the SSO-login-state table if missing (OIDC human SSO, additive).
	if !ssoLoginStateExists {
		if err := db.AutoMigrate(&models.SSOLoginState{}); err != nil {
			return fmt.Errorf("failed to migrate sso_login_states table: %w", err)
		}
	}
	return nil
}
