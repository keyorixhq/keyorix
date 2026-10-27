package serverguard

import (
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// pgTestDSN returns the KEYORIX_TEST_PG_DSN base DSN, skipping the test (not
// failing it) when unset -- matching internal/storage's own convention
// (postgres_pk_rebuild_helpers_test.go's pgTestDSN).
func pgTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping Postgres server-presence guard test")
	}
	return dsn
}

func pgCfg(t *testing.T) *config.Config {
	return &config.Config{
		Storage: config.StorageConfig{
			Type:     "postgres",
			Database: config.DatabaseConfig{DSN: pgTestDSN(t)},
		},
	}
}

func TestPostgres_ProbeRunning_FalseWhenNoServer(t *testing.T) {
	cfg := pgCfg(t)
	running, detail, err := ProbeRunning(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if running {
		t.Fatalf("expected running=false with no server, got true (detail=%q)", detail)
	}
}

func TestPostgres_ProbeRunning_TrueWhileServerHoldsPresence(t *testing.T) {
	cfg := pgCfg(t)
	presence, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	defer presence.Release() //nolint:errcheck

	running, detail, err := ProbeRunning(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !running {
		t.Fatal("expected running=true while a server holds the presence advisory lock")
	}
	if detail == "" {
		t.Fatal("expected a non-empty detail message")
	}
}

func TestPostgres_ProbeRunning_FalseAfterServerReleases(t *testing.T) {
	cfg := pgCfg(t)
	presence, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	if err := presence.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	running, _, err := ProbeRunning(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if running {
		t.Fatal("expected running=false after the server released its presence lock")
	}
}

// parseLibpqDSN parses a PostgreSQL DSN into libpq keyword/value fields (host, port,
// user, password, dbname, sslmode), just enough to let
// TestPostgres_AcquireExclusive_AuthFailureIsNotLockHeld mutate the password without its
// own separate connection config. Both forms are read: the keyword/value form CI's
// e2e-nightly sets ("host=... user=... password=..."; scripts/e2e/api_smoke_test.go's
// convention) and the URL form kpg and most local setups give
// ("postgres://user:pw@host:port/db?sslmode=..."), so the test runs on either instead of
// skipping on the URL form (REVIEW-SERVERGUARD-RECOVERYKEY-1 leftover).
func parseLibpqDSN(dsn string) map[string]string {
	out := map[string]string{}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return out
		}
		out["host"], out["port"] = u.Hostname(), u.Port()
		if u.User != nil {
			out["user"] = u.User.Username()
			out["password"], _ = u.User.Password()
		}
		out["dbname"] = strings.TrimPrefix(u.Path, "/")
		for k, v := range u.Query() {
			if len(v) > 0 {
				out[k] = v[0]
			}
		}
		return out
	}
	for tok := range strings.FieldsSeq(dsn) {
		kv := strings.SplitN(tok, "=", 2)
		if len(kv) == 2 {
			out[kv[0]] = strings.Trim(kv[1], `'"`)
		}
	}
	return out
}

// authFailureMisclassified returns why err, from AcquireExclusive with a wrong password
// against a reachable server, is NOT reported the way #2362 requires (nil when it is):
// it must be the auth error itself (presence was never determined), never a lock-held
// refusal.
func authFailureMisclassified(err error) string {
	switch {
	case err == nil:
		return "AcquireExclusive succeeded with a wrong password"
	case IsLockHeld(err):
		return "an auth failure was reported as lock-held (IsLockHeld == true): " + err.Error()
	}
	if _, ok := errors.AsType[*config.PostgresAuthError](err); !ok {
		return "want a PostgresAuthError (SQLSTATE 28P01), got: " + err.Error()
	}
	return ""
}

// wrongPasswordCfg targets KEYORIX_TEST_PG_DSN's real server with a mutated password.
func wrongPasswordCfg(t *testing.T) *config.Config {
	t.Helper()
	fields := parseLibpqDSN(pgTestDSN(t))
	if fields["host"] == "" || fields["user"] == "" {
		t.Skip("KEYORIX_TEST_PG_DSN names no host or user -- cannot target its real host with a mutated password")
	}
	sslMode := fields["sslmode"]
	if sslMode == "" {
		sslMode = "disable"
	}
	return &config.Config{
		Storage: config.StorageConfig{
			Type: "postgres",
			Database: config.DatabaseConfig{
				Host: fields["host"], Port: fields["port"], Name: fields["dbname"],
				User: fields["user"], Password: "wrong-" + fields["password"] + "-definitely-not-it", SSLMode: sslMode,
			},
		},
	}
}

// TestPostgres_AcquireExclusive_AuthFailureIsNotLockHeld reproduces #2362 exactly: a real
// Postgres server, reachable, but with a wrong password (SQLSTATE 28P01) -- as opposed to
// TestPostgres_AcquireExclusive_ConnectFailureIsNotLockHeld's unreachable-host case. Either
// way, IsLockHeld must be false: presence was never actually determined.
func TestPostgres_AcquireExclusive_AuthFailureIsNotLockHeld(t *testing.T) {
	_, err := AcquireExclusive(wrongPasswordCfg(t))
	if why := authFailureMisclassified(err); why != "" {
		t.Fatal(why)
	}
}

// TestPostgres_AuthFailureOracle_CatchesAPlantedMisclassification shows the test above
// goes red on the bug it guards: the same real auth error, planted as a lock-held refusal
// (what #2362 reported), and an error that is not an auth failure at all, are both
// rejected; the real error is accepted.
func TestPostgres_AuthFailureOracle_CatchesAPlantedMisclassification(t *testing.T) {
	_, err := AcquireExclusive(wrongPasswordCfg(t))
	if why := authFailureMisclassified(err); why != "" {
		t.Fatalf("precondition: the real auth failure must pass the oracle: %s", why)
	}
	if authFailureMisclassified(&lockHeldErr{err}) == "" {
		t.Error("the oracle accepted an auth failure planted as lock-held")
	}
	if authFailureMisclassified(errors.New("dial tcp: connection refused")) == "" {
		t.Error("the oracle accepted an error that is not an auth failure")
	}
	if authFailureMisclassified(nil) == "" {
		t.Error("the oracle accepted a success")
	}
}

// TestPostgres_AcquireExclusive_ConflictsWithAnotherExclusive_IsLockHeld is the Postgres
// counterpart to TestSQLite_AcquireExclusive_ConflictsWithAnotherExclusive: a genuine
// lock-held failure, as opposed to the auth/connect-failure tests above, must satisfy
// IsLockHeld.
func TestPostgres_AcquireExclusive_ConflictsWithAnotherExclusive_IsLockHeld(t *testing.T) {
	cfg := pgCfg(t)
	first, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("first AcquireExclusive: %v", err)
	}
	defer first.Release() //nolint:errcheck

	_, err = AcquireExclusive(cfg)
	if err == nil {
		t.Fatal("expected a second concurrent AcquireExclusive to fail")
	}
	if !IsLockHeld(err) {
		t.Fatalf("expected IsLockHeld(err) == true for a genuine lock conflict, got: %v", err)
	}
}

func TestPostgres_MultipleServerReplicas_ShareCoexist(t *testing.T) {
	// Multiple server replicas sharing one Postgres database (ADR-039 HA)
	// must not conflict on the SHARED presence lock — only the admin
	// commands' EXCLUSIVE probe treats that as contention.
	cfg := pgCfg(t)
	p1, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("first AcquirePresence: %v", err)
	}
	defer p1.Release() //nolint:errcheck

	p2, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("second AcquirePresence (concurrent shared holder / HA replica) unexpectedly failed: %v", err)
	}
	defer p2.Release() //nolint:errcheck
}
