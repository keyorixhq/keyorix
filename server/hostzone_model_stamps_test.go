// hostzone_model_stamps_test.go -- HOSTZONE-TIME-NOV-1 item 1, server half.
//
// Three boot-time writers stamp system_metadata.updated_at with the host clock and insert it with a
// plain Create, which stores a non-zero timestamp as given (GORM's NowFunc is UTC but stamps only a
// zero field): on SQLite as text carrying the host offset, which SQLite compares by wall clock and so
// does not order against the UTC values every other writer stores; on PostgreSQL (timestamptz) an
// instant, harmless.
//
//	recordKeyDirLockMode      server/key_dir_lock.go     time.Now()
//	recordADR112MFAGraceWindow server/adr112_grace.go    adr112Now() = time.Now().Round(0)
//	recordADR112Enforced       server/adr112_grace.go    adr112Now() / time.Now()
//
// Each runs in a child of this test binary with TZ=Asia/Tokyo (time.Local is never assigned). The
// adr112Now hook is left as production has it; only the write sites normalise.

package main

import (
	"database/sql"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	_ "time/tzdata"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
)

const (
	hostZoneStampsChildEnv = "KEYORIX_TEST_SERVER_HOSTZONE_STAMPS_CHILD"
	hostZoneStampsTZ       = "Asia/Tokyo"
)

// storedTimeLayouts are the text forms an SQLite timestamp column comes back in.
var storedTimeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999 -0700 MST",
	"2006-01-02 15:04:05.999999999 -0700 -0700",
}

func parseStoredTime(t *testing.T, s string) time.Time {
	t.Helper()
	if before, _, found := strings.Cut(s, " m="); found {
		s = before
	}
	for _, layout := range storedTimeLayouts {
		if got, err := time.Parse(layout, s); err == nil {
			return got
		}
	}
	t.Fatalf("stored timestamp %q matches no known layout", s)
	return time.Time{}
}

// requireMetadataUpdatedAtNow asserts system_metadata.updated_at of key is a UTC time inside
// [before, after], and that a predicate against a UTC bound finds the row.
func requireMetadataUpdatedAtNow(t *testing.T, db *gorm.DB, pg bool, key string, before, after time.Time) {
	t.Helper()
	var stored time.Time
	if pg {
		var got sql.NullTime
		require.NoError(t, db.Raw(`SELECT updated_at FROM system_metadata WHERE "key" = ?`, key).Row().Scan(&got))
		require.True(t, got.Valid, "system_metadata.updated_at of %s is NULL", key)
		stored = got.Time
	} else {
		var s string
		require.NoError(t, db.Raw(`SELECT CAST(updated_at AS TEXT) FROM system_metadata WHERE "key" = ?`, key).Row().Scan(&s))
		stored = parseStoredTime(t, s)
		_, off := stored.Zone()
		require.Zero(t, off, "system_metadata.updated_at of %s stored with the host offset: %q (want UTC)", key, s)
	}
	require.False(t, stored.Before(before) || stored.After(after), "system_metadata.updated_at of %s = %s, want a time in [%s, %s]", key, stored.UTC(), before.UTC(), after.UTC())

	var n int64
	bound := after.Add(time.Hour).UTC()
	require.NoError(t, db.Raw(`SELECT COUNT(*) FROM system_metadata WHERE "key" = ? AND updated_at <= ?`, key, bound).Scan(&n).Error)
	require.EqualValues(t, 1, n, "system_metadata.updated_at <= %s did not find the row of %s", bound, key)
}

func hostZoneStampWindow() (before, after time.Time) {
	return time.Now().UTC().Add(-time.Second), time.Now().UTC().Add(time.Minute)
}

func TestHostZoneStamps_ServerSystemMetadataStoresUTC(t *testing.T) {
	if os.Getenv(hostZoneStampsChildEnv) == "" {
		runHostZoneStampsChild(t)
		return
	}
	_, off := time.Now().Zone()
	require.NotZero(t, off, "child must run with a non-UTC host zone (TZ=%s)", hostZoneStampsTZ)

	t.Run("sqlite", func(t *testing.T) {
		cfg := adr112GraceConfig(t)
		migrateADR112DB(t, cfg, 0)
		hostZoneSystemMetadataSites(t, cfg, false)
	})

	t.Run("postgres", func(t *testing.T) {
		dsn := keyDirLockDSN(t) // skips without KEYORIX_TEST_PG_DSN
		cfg := keyDirLockCfg(dsn, t.TempDir(), config.KeyDirLockDatabase)
		hostZoneSystemMetadataSites(t, cfg, true)
	})
}

func hostZoneSystemMetadataSites(t *testing.T, cfg *config.Config, pg bool) {
	t.Helper()

	t.Run("recordKeyDirLockMode", func(t *testing.T) {
		before, after := hostZoneStampWindow()
		require.NoError(t, recordKeyDirLockMode(cfg))
		db, err := appstorage.OpenGormDB(cfg)
		require.NoError(t, err)
		defer closeGormDB(db)
		requireMetadataUpdatedAtNow(t, db, pg, config.KeyDirLockModeMetadataKey, before, after)
	})

	t.Run("recordADR112MFAGraceWindow", func(t *testing.T) {
		db, err := appstorage.OpenGormDB(cfg)
		require.NoError(t, err)
		defer closeGormDB(db)
		before, after := hostZoneStampWindow()
		_, _, err = recordADR112MFAGraceWindow(db, adr112Now())
		require.NoError(t, err)
		requireMetadataUpdatedAtNow(t, db, pg, config.ADR112RequireMFAGraceStartedKey, before, after)
		requireMetadataUpdatedAtNow(t, db, pg, config.ADR112RequireMFAGraceClockKey, before, after)
	})

	t.Run("recordADR112Enforced with the boot clock", func(t *testing.T) {
		db, err := appstorage.OpenGormDB(cfg)
		require.NoError(t, err)
		defer closeGormDB(db)
		before, after := hostZoneStampWindow()
		require.NoError(t, recordADR112Enforced(db, adr112SCIMTokenEnforcedKey, time.Now()))
		requireMetadataUpdatedAtNow(t, db, pg, adr112SCIMTokenEnforcedKey, before, after)
	})
}

// runHostZoneStampsChild re-executes this test binary for the test above with TZ=Asia/Tokyo and
// requires that it ran and passed.
func runHostZoneStampsChild(t *testing.T) {
	t.Helper()
	if _, err := time.LoadLocation(hostZoneStampsTZ); err != nil {
		t.Skipf("zone database has no %s: %v", hostZoneStampsTZ, err)
	}
	exe, err := os.Executable()
	require.NoError(t, err)
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "TZ=") && !strings.HasPrefix(kv, hostZoneStampsChildEnv+"=") {
			env = append(env, kv)
		}
	}
	env = append(env, "TZ="+hostZoneStampsTZ, hostZoneStampsChildEnv+"=1")
	name := t.Name()
	cmd := exec.Command(exe, "-test.run=^"+name+"$", "-test.v", "-test.count=1")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "child TZ=%s failed:\n%s", hostZoneStampsTZ, out)
	require.Contains(t, string(out), "--- PASS: "+name+" ", "child TZ=%s did not run %s:\n%s", hostZoneStampsTZ, name, out)
}
