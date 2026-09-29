// diagnose_recovery_key_test.go — coverage for diagnoseRecoveryKey (F6,
// recovery-key visibility): `admin diagnose` must report whether
// `recover-admin` is currently usable.
package admin

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newDiagnoseTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.RecoveryKeyRecord{}))
	return db
}

// TestDiagnoseRecoveryKey_NotConfigured verifies the [WARN] case: keyless
// mode is off and no recovery key has ever been generated.
func TestDiagnoseRecoveryKey_NotConfigured(t *testing.T) {
	db := newDiagnoseTestDB(t)
	cfg := &config.Config{}

	out, err := captureStdout(t, func() error { diagnoseRecoveryKey(db, cfg); return nil })
	require.NoError(t, err)

	assert.Contains(t, out, "[WARN]")
	assert.Contains(t, out, "recovery key not configured")
	assert.Contains(t, out, "recovery-key rotate")
}

// TestDiagnoseRecoveryKey_Configured verifies the [ OK ] case, naming the
// generation, once a key has been generated.
func TestDiagnoseRecoveryKey_Configured(t *testing.T) {
	db := newDiagnoseTestDB(t)
	require.NoError(t, db.Create(&models.RecoveryKeyRecord{ID: 1, KeyHash: "x", KeyVersion: 2}).Error)
	cfg := &config.Config{}

	out, err := captureStdout(t, func() error { diagnoseRecoveryKey(db, cfg); return nil })
	require.NoError(t, err)

	assert.Contains(t, out, "[ OK ]")
	assert.Contains(t, out, "generation 2")
}

// TestDiagnoseRecoveryKey_KeylessModeSkips verifies keyless-mode installs get
// [SKIP], not [WARN] -- recover-admin does not check a key in that mode, so
// its absence is expected, not a problem.
func TestDiagnoseRecoveryKey_KeylessModeSkips(t *testing.T) {
	db := newDiagnoseTestDB(t)
	cfg := &config.Config{}
	cfg.Security.RecoverAdmin.KeylessMode = true

	out, err := captureStdout(t, func() error { diagnoseRecoveryKey(db, cfg); return nil })
	require.NoError(t, err)

	assert.Contains(t, out, "[SKIP]")
	assert.NotContains(t, out, "[WARN]")
}
