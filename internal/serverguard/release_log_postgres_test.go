package serverguard

// SEC-PG-COVERAGE-1: Postgres-gated tests for the release path of the presence and
// exclusive locks, which the mutants in serverguard.go (the 10*time.Second release
// context and the err != nil choosing whether to log a failed explicit unlock or
// ROLLBACK) and keyinit.go (the error detail of keyInitLockStillHeld) outlived.
//
// A failed explicit unlock is the one signal that the fast release path did not fire
// (see the comment in acquirePostgresPresence), so both directions are pinned: a healthy
// release says nothing, and one whose connection is gone says so.
//
// keyinit.go:80 (`10*time.Second` on the release context of WithKeyInitLock) stays an
// equivalent mutant: its unlock result is discarded and the deferred conn/sqlDB close
// releases the lock either way, so no outcome except the timing of the backend's exit
// differs, and that is not deterministic.

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// fallbackLogFragment is common to the three "explicit release failed" log lines.
const fallbackLogFragment = "falling back to connection-close release"

// releasable is what the presence and exclusive locks share.
type releasable struct {
	release func() error
	lost    <-chan struct{}
}

type releaseShape struct {
	name string
	cfg  func(t *testing.T) *config.Config
	// failLog is the line a failed explicit release must log in this shape.
	failLog string
}

func releaseShapes() []releaseShape {
	return []releaseShape{
		{"presence/session", pgCfg, "explicit pg_advisory_unlock_shared("},
		{"exclusive/session", pgCfg, "explicit pg_advisory_unlock("},
		{"presence/transaction", func(t *testing.T) *config.Config { c, _ := poolerGuardCfg(t); return c }, "ending the presence lock transaction failed"},
		{"exclusive/transaction", func(t *testing.T) *config.Config { c, _ := poolerGuardCfg(t); return c }, "ending the presence lock transaction failed"},
	}
}

func acquireReleasable(t *testing.T, name string, cfg *config.Config) releasable {
	t.Helper()
	if strings.HasPrefix(name, "presence") {
		p, err := AcquirePresence(cfg)
		require.NoError(t, err)
		return releasable{release: p.Release, lost: p.Lost()}
	}
	x, err := AcquireExclusive(cfg)
	require.NoError(t, err)
	return releasable{release: x.Release, lost: x.Lost()}
}

// A release whose connection is healthy logs nothing. Under the release-timeout
// mutants (10*time.Second -> a zero timeout) the explicit unlock fails at once and
// logs the fallback line; under the err != nil negations the healthy path logs it.
func TestPostgres_ServerGuard_HealthyReleaseLogsNothing(t *testing.T) {
	for _, shape := range releaseShapes() {
		t.Run(shape.name, func(t *testing.T) {
			cfg := shape.cfg(t)
			shortLockPing(t)
			buf := captureLog(t)

			r := acquireReleasable(t, shape.name, cfg)
			require.NoError(t, r.release())

			assert.NotContains(t, buf.String(), fallbackLogFragment,
				"a release on a live connection must not report a failed explicit unlock")
		})
	}
}

// A release whose backend is already gone cannot unlock explicitly: it must say so
// (the lock is then released by the connection close, with no other signal) and still
// finish.
func TestPostgres_ServerGuard_FailedExplicitReleaseIsLogged(t *testing.T) {
	for _, shape := range releaseShapes() {
		t.Run(shape.name, func(t *testing.T) {
			cfg := shape.cfg(t)
			shortLockPing(t)
			buf := captureLog(t)

			r := acquireReleasable(t, shape.name, cfg)
			terminateLockHolder(t, serverPresenceLockKey)
			select {
			case <-r.lost:
			case <-time.After(5 * time.Second):
				t.Fatal("the lock's backend was terminated but Lost never closed (test premise)")
			}

			_ = r.release() // the connection is gone: a close error is fine, the log line is the point
			assert.Contains(t, buf.String(), shape.failLog)
			assert.Contains(t, buf.String(), fallbackLogFragment)
		})
	}
}

// keyInitLockStillHeld names why the lock is gone: "no longer held" when the query
// worked and found nothing, the database error when the query itself failed. The
// error is errKeyInitLockLost either way.
func TestPostgres_KeyInitLockStillHeld_ErrorDetail(t *testing.T) {
	for _, xact := range []bool{false, true} {
		name := "session"
		if xact {
			name = "transaction"
		}
		t.Run(name+"/not held", func(t *testing.T) {
			sqlDB, conn, err := pgConn(pgCfg(t))
			require.NoError(t, err)
			defer func() { _ = sqlDB.Close() }()
			defer func() { _ = conn.Close() }()

			err = keyInitLockStillHeld(conn, xact)
			require.Error(t, err)
			assert.True(t, errors.Is(err, errKeyInitLockLost))
			assert.Contains(t, err.Error(), "(no longer held by this connection)")
		})
		t.Run(name+"/query fails", func(t *testing.T) {
			sqlDB, conn, err := pgConn(pgCfg(t))
			require.NoError(t, err)
			defer func() { _ = sqlDB.Close() }()
			require.NoError(t, conn.Close())

			err = keyInitLockStillHeld(conn, xact)
			require.Error(t, err)
			assert.True(t, errors.Is(err, errKeyInitLockLost))
			assert.Contains(t, err.Error(), "("+sql.ErrConnDone.Error()+")")
			assert.NotContains(t, err.Error(), "no longer held by this connection")
		})
	}
}
