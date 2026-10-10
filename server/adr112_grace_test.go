// adr112_grace_test.go -- adr112UpgradeGraceEligible / recordADR112EnforcedIfClean:
// the database-derived fact that separates a fresh install (enforced) from an
// upgraded deployment (grace-period warnings) under ADR-112's implicit
// enable_file_permission_check default.
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func adr112GraceConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: filepath.Join(t.TempDir(), "keyorix.db")},
		},
		Security: config.SecurityConfig{
			EnableFilePermissionCheck:                true,
			EnableFilePermissionCheckImplicitDefault: true,
		},
	}
}

// migrateADR112DB creates the database with the two tables the decision reads,
// and nUsers users in it.
func migrateADR112DB(t *testing.T, cfg *config.Config, nUsers int) {
	t.Helper()
	db, err := appstorage.OpenGormDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeGormDB(db)
	if err := db.AutoMigrate(&models.User{}, &models.SystemMetadata{}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < nUsers; i++ {
		u := models.User{Username: "admin" + string(rune('a'+i)), Email: string(rune('a'+i)) + "@example.test"}
		if err := db.Create(&u).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func TestADR112UpgradeGrace_Decision(t *testing.T) {
	t.Run("fresh install, no database file", func(t *testing.T) {
		cfg := adr112GraceConfig(t)
		if ok, why := adr112UpgradeGraceEligible(cfg); ok {
			t.Fatalf("fresh install must be enforced, got grace (%s)", why)
		}
		if _, err := os.Stat(cfg.Storage.Database.Path); !os.IsNotExist(err) {
			t.Fatalf("the decision must not create the database file: %v", err)
		}
	})
	t.Run("fresh install, schema but no users", func(t *testing.T) {
		cfg := adr112GraceConfig(t)
		migrateADR112DB(t, cfg, 0)
		if ok, why := adr112UpgradeGraceEligible(cfg); ok {
			t.Fatalf("a database with no users is a fresh install and must be enforced, got grace (%s)", why)
		}
	})
	t.Run("upgraded deployment, users and no marker", func(t *testing.T) {
		cfg := adr112GraceConfig(t)
		migrateADR112DB(t, cfg, 2)
		if ok, why := adr112UpgradeGraceEligible(cfg); !ok {
			t.Fatalf("an upgraded deployment must get the grace period, got enforced (%s)", why)
		}
	})
	t.Run("upgraded deployment that already booted clean", func(t *testing.T) {
		cfg := adr112GraceConfig(t)
		migrateADR112DB(t, cfg, 2)
		db, err := appstorage.OpenGormDB(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := recordADR112Enforced(db, time.Now()); err != nil {
			t.Fatal(err)
		}
		closeGormDB(db)
		if ok, why := adr112UpgradeGraceEligible(cfg); ok {
			t.Fatalf("a deployment past the grace period must stay enforced, got grace (%s)", why)
		}
	})
	t.Run("explicit key never gets grace", func(t *testing.T) {
		cfg := adr112GraceConfig(t)
		migrateADR112DB(t, cfg, 2)
		cfg.Security.EnableFilePermissionCheckImplicitDefault = false
		if ok, _ := adr112UpgradeGraceEligible(cfg); ok {
			t.Fatal("an explicitly set key must never get the grace period")
		}
	})
	t.Run("unreadable database fails closed", func(t *testing.T) {
		cfg := adr112GraceConfig(t)
		if err := os.WriteFile(cfg.Storage.Database.Path, []byte("not a sqlite database, but long enough to be read as one...."), 0o600); err != nil {
			t.Fatal(err)
		}
		if ok, why := adr112UpgradeGraceEligible(cfg); ok {
			t.Fatalf("an undecidable database must fail closed, got grace (%s)", why)
		}
	})
}

// The ratchet: an upgraded deployment that boots clean once is enforced from
// then on; one whose problem was softened this boot stays in the grace period.
func TestRecordADR112EnforcedIfClean_Ratchet(t *testing.T) {
	t.Cleanup(func() { adr112GraceSoftened.Store(false) })

	cfg := adr112GraceConfig(t)
	migrateADR112DB(t, cfg, 1)

	adr112GraceSoftened.Store(true)
	recordADR112EnforcedIfClean(cfg)
	if ok, why := adr112UpgradeGraceEligible(cfg); !ok {
		t.Fatalf("a softened boot must not end the grace period (%s)", why)
	}

	adr112GraceSoftened.Store(false)
	recordADR112EnforcedIfClean(cfg)
	if ok, why := adr112UpgradeGraceEligible(cfg); ok {
		t.Fatalf("a clean boot must end the grace period for good (%s)", why)
	}
}

// End to end through applyADR112UpgradeGrace and the two gates: the same
// world-readable key file warns on an upgrade and refuses on a fresh install.
func TestApplyADR112UpgradeGrace_FreshRefusesUpgradeWarns(t *testing.T) {
	keyCfg := func(t *testing.T) *config.Config {
		cfg := adr112GraceConfig(t)
		dek := filepath.Join(t.TempDir(), "dek.json")
		if err := os.WriteFile(dek, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg.Storage.Encryption = config.EncryptionConfig{Enabled: true, DEKPath: dek}
		return cfg
	}

	fresh := keyCfg(t)
	applyADR112UpgradeGrace(fresh)
	if err := enforceKeyFilePermissions(fresh); err == nil {
		t.Error("fresh install: expected a world-readable key file to refuse to start")
	}

	upgrade := keyCfg(t)
	migrateADR112DB(t, upgrade, 1)
	t.Cleanup(func() { adr112GraceSoftened.Store(false) })
	applyADR112UpgradeGrace(upgrade)
	if err := enforceKeyFilePermissions(upgrade); err != nil {
		t.Errorf("upgrade: expected the grace period to warn, got %v", err)
	}
	if !adr112GraceSoftened.Load() {
		t.Error("upgrade: a softened failure must be recorded so the boot does not ratchet to enforced")
	}
}
