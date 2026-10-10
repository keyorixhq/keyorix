// adr112_grace.go — decides whether a boot is inside ADR-112's upgrade grace
// period for security.enable_file_permission_check, and ratchets a deployment
// out of it once it boots clean.
//
// ADR-112 flips enable_file_permission_check's default to true. "Absent from the
// config file" (EnableFilePermissionCheckImplicitDefault) is true for a fresh
// install and for an upgraded one alike, so it cannot by itself decide whether
// the grace period applies: a fresh install must be enforced from its first
// start, and only an existing deployment that relied on the old implicit-false
// default gets warnings instead of a refusal to boot. The fact that separates
// the two lives in the database:
//
//   - no database yet, or a database with no users: a fresh install -> enforced;
//   - the adr112FilePermEnforcedKey system_metadata row is present: this
//     deployment has already booted clean under the check (or was installed
//     under it) -> enforced. The row is written by recordADR112EnforcedIfClean,
//     so the grace period ends the first time the deployment complies and never
//     comes back (a ratchet, not a timer);
//   - users exist and the row is absent: an upgraded deployment still inside the
//     grace period -> warn instead of refusing to start.
//
// Any error while deciding fails closed (no grace).
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// adr112FilePermEnforcedKey is the system_metadata key recording that this
// deployment is past (or was never in) ADR-112's file-permission-check grace
// period. Its value is the RFC 3339 time it was first recorded.
const adr112FilePermEnforcedKey = "adr112.file_permission_check.enforced"

// adr112GraceSoftened is set when a grace-period branch (runStartupValidation or
// enforceKeyFilePermissions) turned a real failure into a warning during this
// boot. recordADR112EnforcedIfClean then leaves the deployment in the grace
// period instead of ratcheting it to enforced.
var adr112GraceSoftened atomic.Bool

// applyADR112UpgradeGrace sets cfg.Security.EnableFilePermissionCheckUpgradeGrace
// from adr112UpgradeGraceEligible and logs the decision when the key is at its
// implicit default.
func applyADR112UpgradeGrace(cfg *config.Config) {
	eligible, why := adr112UpgradeGraceEligible(cfg)
	cfg.Security.EnableFilePermissionCheckUpgradeGrace = eligible
	if !cfg.Security.EnableFilePermissionCheck || !cfg.Security.EnableFilePermissionCheckImplicitDefault {
		return
	}
	if eligible {
		log.Printf("WARNING: ADR-112 grace period: security.enable_file_permission_check now defaults to true and this config never set it; %s. A problem the startup checks find is logged as a warning instead of refusing to start until this deployment boots clean once (it is then enforced for good) or sets the key explicitly.", why)
		return
	}
	log.Printf("INFO: security.enable_file_permission_check is enforcing on its ADR-112 secure-by-default value (never set in this config); %s, so a problem the startup checks find refuses to start.", why)
}

// adr112UpgradeGraceEligible reports whether this boot is an upgraded deployment
// inside the grace period, with a human-readable reason either way. See the file
// comment for the decision table. It never creates the database: a local SQLite
// file that does not exist yet is a fresh install, and is left for the normal
// boot path to create with its own permissions.
func adr112UpgradeGraceEligible(cfg *config.Config) (bool, string) {
	sec := cfg.Security
	if !sec.EnableFilePermissionCheck || !sec.EnableFilePermissionCheckImplicitDefault {
		return false, "the key is set explicitly"
	}
	switch cfg.Storage.Type {
	case "postgres", "postgresql":
	default: // "local", "sqlite", ""
		if _, err := os.Stat(cfg.Storage.Database.Path); errors.Is(err, os.ErrNotExist) {
			return false, "this is a fresh install (no database yet)"
		} else if err != nil {
			return false, "could not inspect the database file (" + err.Error() + "), failing closed"
		}
	}
	db, err := appstorage.OpenGormDB(cfg)
	if err != nil {
		return false, "could not open the database to tell a fresh install from an upgrade (" + err.Error() + "), failing closed"
	}
	defer closeGormDB(db)
	return adr112GraceFromDB(db)
}

// adr112GraceFromDB is adr112UpgradeGraceEligible's database half.
func adr112GraceFromDB(db *gorm.DB) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db = db.WithContext(ctx)
	m := db.Migrator()
	if !m.HasTable(&models.User{}) {
		return false, "this is a fresh install (no schema yet)"
	}
	var users int64
	if err := db.Unscoped().Model(&models.User{}).Count(&users).Error; err != nil {
		return false, "could not count users (" + err.Error() + "), failing closed"
	}
	if users == 0 {
		return false, "this is a fresh install (no users yet)"
	}
	if m.HasTable(&models.SystemMetadata{}) {
		var row models.SystemMetadata
		err := db.Where("key = ?", adr112FilePermEnforcedKey).Take(&row).Error
		switch {
		case err == nil:
			return false, "this deployment already booted clean under the check on " + row.Value
		case !errors.Is(err, gorm.ErrRecordNotFound):
			return false, "could not read the ADR-112 enforcement marker (" + err.Error() + "), failing closed"
		}
	}
	return true, "this is an upgraded deployment that has not yet booted clean under the check"
}

// recordADR112EnforcedIfClean writes adr112FilePermEnforcedKey once the startup
// checks ran this boot and nothing was softened by the grace period, so a
// later boot of the same deployment (a fresh install's second start included)
// is enforced. Best-effort: a failure leaves the deployment in whatever state
// it was (a fresh install stays enforced through its user count anyway).
func recordADR112EnforcedIfClean(cfg *config.Config) {
	if !cfg.Security.EnableFilePermissionCheck || adr112GraceSoftened.Load() {
		return
	}
	db, err := appstorage.OpenGormDB(cfg)
	if err != nil {
		log.Printf("ADR-112: could not record the file-permission-check enforcement marker: %v (continuing)", err)
		return
	}
	defer closeGormDB(db)
	if err := recordADR112Enforced(db, time.Now()); err != nil {
		log.Printf("ADR-112: could not record the file-permission-check enforcement marker: %v (continuing)", err)
	}
}

// recordADR112Enforced inserts the marker if it is not already there; the first
// recorded time is kept.
func recordADR112Enforced(db *gorm.DB, now time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&models.SystemMetadata{
		Key:       adr112FilePermEnforcedKey,
		Value:     now.UTC().Format(time.RFC3339),
		UpdatedAt: now,
	}).Error
}

func closeGormDB(db *gorm.DB) {
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}
