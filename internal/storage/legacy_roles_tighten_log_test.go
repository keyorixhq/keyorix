package storage

// legacy_roles_tighten_log_test.go — LEGACY-ROLES-TAILS-1 item 2: the boot that
// tightens the legacy roles to global (#3605) writes no audit row, so it says so
// once in the startup log: how many role rows moved and from which scope to
// which. A boot that has nothing to tighten prints nothing.

import (
	"bytes"
	"log"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// captureLog returns what the standard logger writes until the test ends.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(prevFlags) })
	return &buf
}

// requireTightenLogOnce seeds the five legacy roles at any (as the epoch-7
// backfill left them) plus a custom any role, then boots twice: the first boot
// reports the five rows moving from any to global, the second logs nothing about
// it.
func requireTightenLogOnce(t *testing.T, db *gorm.DB) {
	t.Helper()
	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	legacy := models.LegacyRoleNames()
	require.Len(t, legacy, 5)
	for _, name := range append([]string{"deploy-bot"}, legacy...) {
		require.NoError(t, db.Exec(`INSERT INTO roles (name, name_folded, description, bypasses_permission_checks, assignable_scope) VALUES (?, ?, '', false, 'any')`,
			name, name).Error)
	}

	first := captureLog(t)
	require.NoError(t, f.migrateDatabase(db), "upgrade boot")
	assert.Contains(t, first.String(), "tightened assignable_scope of 5 legacy role row(s) from any to global",
		"the first boot reports how many rows moved and from which scope to which")
	assert.Contains(t, first.String(), "no grant was changed")
	assert.Equal(t, models.RoleAssignableAny, roleAssignableScopes(t, db)["deploy-bot"], "a custom role is neither moved nor counted")

	second := captureLog(t)
	require.NoError(t, f.migrateDatabase(db), "second boot")
	assert.NotContains(t, second.String(), "tightened", "a boot with nothing to tighten prints nothing about it")
	assert.NotContains(t, second.String(), "assignable_scope")
}

func TestLegacyRolesTighten_LogsOnceOnSQLite(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "legacy-tighten-log.db"))
	require.NoError(t, err)
	requireTightenLogOnce(t, db)
}

// A fresh install has nothing to tighten (roles are seeded at global), so it
// logs nothing either.
func TestLegacyRolesTighten_FreshInstallLogsNothing(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "legacy-tighten-fresh.db"))
	require.NoError(t, err)
	buf := captureLog(t)
	require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))
	assert.NotContains(t, buf.String(), "tightened")
}
