package storage

import "gorm.io/gorm"

// sqlTimestampType is the column type every hand-written DDL statement in
// migrateDatabase declares for a column a model maps to time.Time or *time.Time
// (#3440). It returns what AutoMigrate itself creates on a fresh install:
// TIMESTAMP WITH TIME ZONE on PostgreSQL, DATETIME on SQLite. A literal
// "TIMESTAMP WITH TIME ZONE" is accepted by SQLite, but the driver then hands a
// stored value back as a string, and scanning it into the model's *time.Time
// fails ("unsupported Scan, storing driver.Value type string into type
// *time.Time"); OTP-EXPIRY-1 and secret_nodes.purge_at both hit this.
//
// Reachability (#3440, checked 2026-10-29): the older timestamp ALTERs
// (users.last_login_at, password_changed_at, last_failed_login_at,
// login_locked_until; sessions.last_seen_at, absolute_expires_at,
// impersonation_started_at; secret_nodes.last_rotated_at, deleted_at,
// cert_not_after) and the user_roles/group_roles primary-key rebuild with
// expires_at never run on a database from a supported upgrade source.
// docs/UPGRADING.md's oldest source is v0.93.x, and a SQLite database
// created by v0.93.0, v0.94.0 or v0.95.0 already has every one of these
// columns as DATETIME, created by AutoMigrate. They ran with the
// literal type only on databases from before v0.93.
// TestTimestampAlters_SupportedUpgradeSources_NoUnscannableColumn pins that
// fact on the real v093/v094/v095 fixtures. They take this type anyway, so a
// pre-v0.93 database that still reaches them gets a scannable column.
//
// TestNoHandWrittenTimestampColumnDDL fails on a string literal in
// internal/storage that spells out a timestamp column type, so a new ALTER has
// to come through here (or through Migrator().AddColumn).
func sqlTimestampType(db *gorm.DB) string {
	if db.Dialector.Name() == "postgres" {
		return "TIMESTAMP WITH TIME ZONE"
	}
	return "DATETIME"
}
