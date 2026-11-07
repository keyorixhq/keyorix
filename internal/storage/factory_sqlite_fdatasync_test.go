// factory_sqlite_fdatasync_test.go — database.fdatasync (opt-in, SQLite only).
//
// The switch is process-wide state inside modernc.org/sqlite, so every test
// here restores the previous setting. None of them use t.Parallel for the same
// reason.
//
// What this does NOT cover: that a commit really issues fdatasync(2) instead of
// fsync(2) (the library's own fdatasync_test.go and the power-cut script under
// scripts/powercut own that), or durability across power loss.
package storage

import (
	"bytes"
	"errors"
	"log"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	msqlite "modernc.org/sqlite"
)

// restoreFdatasync puts the process-wide setting back after the test.
func restoreFdatasync(t *testing.T) {
	t.Helper()
	prev := msqlite.FdatasyncEnabled()
	t.Cleanup(func() {
		if _, err := msqlite.Fdatasync(prev); err != nil && !errors.Is(err, msqlite.ErrFdatasyncUnavailable) {
			t.Errorf("restoring fdatasync=%v: %v", prev, err)
		}
	})
}

// fdatasyncSupported reports whether this platform's driver honours the switch.
func fdatasyncSupported() bool {
	switch runtime.GOOS {
	case "linux", "freebsd", "illumos", "netbsd":
		return true
	}
	return false
}

func bootLocalWithFdatasync(t *testing.T, enabled bool) {
	t.Helper()
	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "secrets.db")
	cfg.Storage.Database.Fdatasync = enabled
	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	require.NotNil(t, st)
}

func TestCreateLocalStorage_Fdatasync_OffByDefault(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	restoreFdatasync(t)
	_, _ = msqlite.Fdatasync(false)

	bootLocalWithFdatasync(t, false)

	assert.False(t, msqlite.FdatasyncEnabled(), "database.fdatasync unset must leave SQLite on fsync")
}

func TestCreateLocalStorage_Fdatasync_OnEnablesWhereSupported(t *testing.T) {
	if !fdatasyncSupported() {
		t.Skipf("driver does not honour fdatasync on %s; the unavailable path is covered by _UnavailablePlatformWarnsAndBoots", runtime.GOOS)
	}
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	restoreFdatasync(t)
	_, _ = msqlite.Fdatasync(false)

	bootLocalWithFdatasync(t, true)

	assert.True(t, msqlite.FdatasyncEnabled(), "database.fdatasync=true must switch SQLite to fdatasync")
}

// TestCreateLocalStorage_Fdatasync_UnavailablePlatformWarnsAndBoots simulates
// macOS/Windows through the seam: startup must succeed and log exactly one
// warning.
func TestCreateLocalStorage_Fdatasync_UnavailablePlatformWarnsAndBoots(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	calls := 0
	prevSeam := sqliteFdatasync
	sqliteFdatasync = func(bool) (bool, error) {
		calls++
		return false, msqlite.ErrFdatasyncUnavailable
	}
	t.Cleanup(func() { sqliteFdatasync = prevSeam })

	var buf bytes.Buffer
	prevOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prevOut)

	bootLocalWithFdatasync(t, true)

	assert.Equal(t, 1, calls, "the switch is requested exactly once per boot")
	assert.Equal(t, 1, bytes.Count(buf.Bytes(), []byte("database.fdatasync is set but this platform cannot sync with fdatasync")),
		"unavailable platform must log exactly one warning")
}

// TestCreateStorage_Fdatasync_PostgresUntouched asserts the option never
// reaches the PostgreSQL path: the seam must not be called even though
// database.fdatasync is set. The DSN points at a closed local port, so the
// boot is expected to fail; only the seam matters here.
func TestCreateStorage_Fdatasync_PostgresUntouched(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	// Reserve a port, then close it, so the connection is refused fast.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	called := false
	prevSeam := sqliteFdatasync
	sqliteFdatasync = func(bool) (bool, error) {
		called = true
		return false, nil
	}
	t.Cleanup(func() { sqliteFdatasync = prevSeam })

	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = "host=127.0.0.1 port=" + strconv.Itoa(port) + " user=x dbname=x sslmode=disable connect_timeout=2"
	cfg.Storage.Database.Fdatasync = true

	_, err = NewStorageFactory().CreateStorage(cfg)
	require.Error(t, err, "precondition: nothing listens on the port, so the Postgres boot must fail")

	assert.False(t, called, "database.fdatasync must not be applied on the PostgreSQL path")
}
