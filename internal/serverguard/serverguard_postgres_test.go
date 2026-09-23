package serverguard

import (
	"os"
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
