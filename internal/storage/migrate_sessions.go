package storage

// migrateDatabase steps for sessions.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"gorm.io/gorm"
)

// alterSessionDeviceColumns is one of migrateDatabase's ordered steps (factory.go).
func alterSessionDeviceColumns(db *gorm.DB, exec func(string) error) error {
	// Timestamp ALTERs below: unreachable from a supported upgrade source; see sqlTimestampType (#3440).
	// Enrich sessions for the My Account "active sessions" view (device/IP/last-active).
	if tableExists(db, "sessions") {
		if !columnExists(db, "sessions", "user_agent") {
			if err := exec("ALTER TABLE sessions ADD COLUMN user_agent TEXT"); err != nil {
				return err
			}
		}
		if !columnExists(db, "sessions", "ip_address") {
			if err := exec("ALTER TABLE sessions ADD COLUMN ip_address TEXT"); err != nil {
				return err
			}
		}
		if !columnExists(db, "sessions", "last_seen_at") {
			if err := exec("ALTER TABLE sessions ADD COLUMN last_seen_at " + sqlTimestampType(db)); err != nil {
				return err
			}
		}
		// Absolute session-lifetime ceiling (short-lived tokens): set at login,
		// carried through refresh, never extended. nil on legacy rows = uncapped.
		if !columnExists(db, "sessions", "absolute_expires_at") {
			if err := exec("ALTER TABLE sessions ADD COLUMN absolute_expires_at " + sqlTimestampType(db)); err != nil {
				return err
			}
		}
	}
	return nil
}

// alterSessionImpersonationColumns is one of migrateDatabase's ordered steps (factory.go).
func alterSessionImpersonationColumns(db *gorm.DB, exec func(string) error) error {
	// Impersonation sessions carry the initiating admin + start time.
	if tableExists(db, "sessions") {
		if !columnExists(db, "sessions", "impersonated_by") {
			if err := exec("ALTER TABLE sessions ADD COLUMN impersonated_by INTEGER"); err != nil {
				return err
			}
		}
		if !columnExists(db, "sessions", "impersonation_started_at") {
			if err := exec("ALTER TABLE sessions ADD COLUMN impersonation_started_at " + sqlTimestampType(db)); err != nil {
				return err
			}
		}
		// #3024: setup-only sessions (restricted, factor-less account under
		// security.require_mfa). false on legacy rows = an ordinary session.
		if !columnExists(db, "sessions", "setup_only") {
			if err := exec("ALTER TABLE sessions ADD COLUMN setup_only BOOLEAN NOT NULL DEFAULT false"); err != nil {
				return err
			}
		}
	}
	return nil
}
