package storage

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// TestMigrateDatabase_CreatesAllSevenPreviouslyUnmigratedTables pins a real bug
// found while building storage.AllModels() for design-b3-backup-v2.md §3.2 (whose
// whole premise is that AutoMigrate coverage and the backup table-walk share one
// real list): SecretTemplate, AlertEscalationPolicy, NotificationChannel,
// SecretVersionComment, MFAStepupToken, HygieneTrendSnapshot, and
// CompliancePostureSnapshot each have live, wired handler code
// (server/http/handlers/{secret_templates,alert_escalation,notification_channels,
// secret_version_comments,mfa_stepup,hygiene_trends,compliance_snapshots_handler}.go)
// but were never reachable from any db.AutoMigrate call in migrateDatabase —
// confirmed by grepping the entire repo for AutoMigrate(&models.<each type>) and
// finding matches only in _test.go files. Every fresh install, and every existing
// install upgrading onto a binary carrying that handler code, would hit "no such
// table" / "relation does not exist" the first time any of these seven features
// was used.
//
// Red without the fix: db.Migrator().HasTable returns false for all seven after a
// full migrateDatabase run against a brand-new database file, matching the exact
// boot path a real fresh install takes.
func TestMigrateDatabase_CreatesAllSevenPreviouslyUnmigratedTables(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "seven-unmigrated.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	cases := []struct {
		name  string
		model any
	}{
		{"secret_templates", &models.SecretTemplate{}},
		{"alert_escalation_policies", &models.AlertEscalationPolicy{}},
		{"notification_channels", &models.NotificationChannel{}},
		{"secret_version_comments", &models.SecretVersionComment{}},
		{"mfa_stepup_tokens", &models.MFAStepupToken{}},
		{"hygiene_trend_snapshots", &models.HygieneTrendSnapshot{}},
		{"compliance_posture_snapshots", &models.CompliancePostureSnapshot{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !db.Migrator().HasTable(tc.model) {
				t.Fatalf("table for %T was not created by migrateDatabase -- this feature's handler code would fail with "+
					"\"no such table\" the first time it ran against a freshly migrated database", tc.model)
			}
		})
	}
}

// TestMigrateDatabase_SevenPreviouslyUnmigratedTables_SurviveUpgradeRerun confirms
// the guarded (tableExists-gated) form of the fix doesn't just work on a fresh
// install: re-running migrateDatabase against an already-migrated database (the
// exact call every subsequent server boot makes) must not error and must leave
// the tables in place -- the same "upgrade" shape TestCompanionIndexes_
// CreatedOnUpgrade exercises for the existing tableExists-gated migrations.
func TestMigrateDatabase_SevenPreviouslyUnmigratedTables_SurviveUpgradeRerun(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "seven-unmigrated-upgrade.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	require.NoError(t, f.migrateDatabase(db), "second migrateDatabase run (simulating a subsequent boot) must not error")

	require.True(t, db.Migrator().HasTable(&models.SecretTemplate{}))
	require.True(t, db.Migrator().HasTable(&models.CompliancePostureSnapshot{}))
}
