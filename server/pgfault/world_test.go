// world_test.go wires the pgfault proxy (proxy_test.go) in front of a REAL
// PostgreSQL server and drives keyorix's production audit-commit path
// (store.LocalStorage.LogAuditEvent — the same hash-chained, group-committed
// path scripts/powercut exercises on SQLite) through it, so a TCP fault at a
// chosen point of the v3 wire protocol hits a real transaction mid-flight.
//
// Safety (FS-PG RULES): the shared test PostgreSQL server is only ever used to CREATE /
// DROP databases whose names start with "fspg_" (pgdsn.IsolatedDatabase with
// prefix "fspg"); the server process is never signalled, stopped, or restarted.
// Every write lands in a throwaway fspg_<pid>_<n> database dropped on cleanup.
package pgfault

import (
	"context"
	"os"
	"testing"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// pgDSNEnv matches CI's and every other PG-gated test's convention: unset means
// "no Postgres available", so the whole pgfault package skips (it has no SQLite
// fallback — its entire reason to exist is real-Postgres wire faults).
const pgDSNEnv = "KEYORIX_TEST_PG_DSN"

// requirePG returns the base DSN (pointed at a fresh fspg_ database that is
// dropped on cleanup) or skips. It never prints the DSN (it carries a password).
func requirePG(tb testing.TB) string {
	tb.Helper()
	base := os.Getenv(pgDSNEnv)
	if base == "" {
		tb.Skipf("%s not set — pgfault needs a real PostgreSQL server", pgDSNEnv)
	}
	if err := i18n.InitializeForTesting(); err != nil {
		tb.Fatalf("i18n: %v", err)
	}
	return pgdsn.IsolatedDatabase(tb, base, "fspg")
}

// openDirect opens a gorm.DB straight to isoDSN (no proxy) — used to migrate the
// schema, truncate between inputs, and VERIFY after a fault (the verification
// path must survive the cut, so it must not go through the proxy).
func openDirect(tb testing.TB, isoDSN string) *gorm.DB {
	tb.Helper()
	db, err := gorm.Open(postgres.Open(isoDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		tb.Fatalf("open direct: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		tb.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(2)
	tb.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

// openThroughProxy opens a gorm.DB whose connections are routed through p, so
// an armed fault interrupts this DB's commits. maxConns is kept at 1 so message
// counting on the proxy maps cleanly onto one in-flight transaction at a time.
func openThroughProxy(tb testing.TB, isoDSN string, p *proxy) *gorm.DB {
	tb.Helper()
	clientDSN, _, err := proxyClientDSN(isoDSN, p.Addr())
	if err != nil {
		tb.Fatalf("proxyClientDSN: %v", err)
	}
	db, err := gorm.Open(postgres.Open(clientDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		tb.Fatalf("open through proxy: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		tb.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetConnMaxLifetime(0)
	tb.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

// pgWorld is one proxied Postgres backend: a throwaway database, a proxy in
// front of it, a direct verification handle, and the upstream host:port.
type pgWorld struct {
	isoDSN   string
	upstream string
	proxy    *proxy
	verify   *gorm.DB // direct — migration, truncation, post-fault verification
}

// newPGWorld builds the world: isolated DB, migrated audit schema, proxy.
func newPGWorld(tb testing.TB) *pgWorld {
	tb.Helper()
	isoDSN := requirePG(tb)
	_, upstream, err := proxyClientDSN(isoDSN, "0.0.0.0:0")
	if err != nil {
		tb.Fatalf("parse upstream: %v", err)
	}
	p, err := newProxy(upstream)
	if err != nil {
		tb.Fatalf("newProxy: %v", err)
	}
	tb.Cleanup(func() { _ = p.Close() })

	verify := openDirect(tb, isoDSN)
	if err := verify.AutoMigrate(&models.AuditEvent{}); err != nil {
		tb.Fatalf("migrate audit_events: %v", err)
	}
	return &pgWorld{isoDSN: isoDSN, upstream: upstream, proxy: p, verify: verify}
}

// truncate empties audit_events so the next input starts from genesis. Done on
// the DIRECT handle: it must not be subject to any armed fault.
func (w *pgWorld) truncate(tb testing.TB) {
	tb.Helper()
	if err := w.verify.Exec("TRUNCATE audit_events RESTART IDENTITY").Error; err != nil {
		tb.Fatalf("truncate: %v", err)
	}
}

// openProxiedStorage opens a fresh LocalStorage whose commits flow through the
// proxy. A fresh pool + fresh LocalStorage per call means an empty in-memory
// audit-head cache, so after truncate() the chain restarts from genesis. The
// returned storage owns its pool; Close() it (which closes the pool).
func openProxiedStorage(tb testing.TB, w *pgWorld) *store.LocalStorage {
	tb.Helper()
	return store.NewLocalStorage(openThroughProxy(tb, w.isoDSN, w.proxy))
}

// verifyStorage is a LocalStorage over the DIRECT handle, for VerifyAuditChain
// and read-back after a fault. A fresh one each call re-reads the chain head
// from the DB (no stale in-memory head cache).
func (w *pgWorld) verifyStorage() *store.LocalStorage {
	return store.NewLocalStorage(w.verify)
}

// countPresent returns the set of powercut indices (Description "pc-<i>")
// currently in audit_events, read directly.
func (w *pgWorld) presentIndices(tb testing.TB) map[int]bool {
	tb.Helper()
	var descs []string
	if err := w.verify.Raw(
		"SELECT description FROM audit_events WHERE event_type = 'pgfault.commit'").
		Scan(&descs).Error; err != nil {
		tb.Fatalf("select present: %v", err)
	}
	out := make(map[int]bool, len(descs))
	for _, d := range descs {
		if i, ok := parsePC(d); ok {
			out[i] = true
		}
	}
	return out
}

func pcEvent(i int) *models.AuditEvent {
	return &models.AuditEvent{
		EventType:   "pgfault.commit",
		IPAddress:   "127.0.0.1",
		Description: "pc-" + itoa(i),
		EventTime:   time.Now().UTC(),
	}
}

// commitRange runs LogAuditEvent commits for indices [start, start+n) serially
// through ls, returning the indices whose commit was ACKNOWLEDGED (returned
// nil). The context carries a per-commit deadline so a stall fault cannot hang
// the burst unboundedly.
func commitRange(ctx context.Context, ls corestorage.Storage, start, n int, perCommit time.Duration) []int {
	acked := make([]int, 0, n)
	for k := range n {
		i := start + k
		cctx, cancel := context.WithTimeout(ctx, perCommit)
		err := ls.LogAuditEvent(cctx, pcEvent(i))
		cancel()
		if err == nil {
			acked = append(acked, i)
		}
	}
	return acked
}

// commitBurst is commitRange starting at 0.
func commitBurst(ctx context.Context, ls corestorage.Storage, n int, perCommit time.Duration) []int {
	return commitRange(ctx, ls, 0, n, perCommit)
}
