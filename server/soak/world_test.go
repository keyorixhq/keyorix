package soak

// world_test.go builds the server the soak drives: the REAL server/http router
// over a real core and the production schema (fuzzworld.Bootstrap runs the
// production migration), behind an httptest.Server on a loopback socket. SQLite
// is a WAL file with the production pool ceiling; PostgreSQL (when
// KEYORIX_TEST_PG_DSN is set) is a throwaway schema on the shared server.
//
// Every goroutine, descriptor, connection and temp file the world itself owns
// is released by Close, so the same Close path is what the final oracle
// compares against: a soak that needed an extra teardown step to look clean
// would hide the leak it is looking for.

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"github.com/keyorixhq/keyorix/server/grpc/services"
	"github.com/keyorixhq/keyorix/server/http/handlers"

	httpserver "github.com/keyorixhq/keyorix/server/http"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

const (
	soakAdminUser     = "soakadmin"
	soakAdminPassword = "Qx7#Lm2$Vn9@Rp4!"
	soakBootstrapTok  = "soak-bootstrap-token"
)

// handlerWrappers is the seam the red-proof plants use (testdata/redproof): a
// plant file registers a wrapper from init() and every request then passes
// through it inside the real server. Empty in every committed build, so the
// control run is the unmodified router.
var handlerWrappers []func(next http.Handler, env *soakEnv) http.Handler

// plantCleanups release what a plant leaked, run by Close after the oracles
// have judged the run, so a planted leak never outlives its test.
var plantCleanups []func()

type soakEnv struct {
	backend string
	db      *gorm.DB
	sqlDB   *sql.DB
	core    *core.KeyorixCore
	srv     *httptest.Server
	client  *http.Client
	tr      *http.Transport
	// tmpDir is the process temp dir for the duration of the run (TMPDIR), so a
	// temp file the server leaves behind is countable and nothing else lands there.
	tmpDir     string
	adminToken string
	closed     bool
}

// newSoakEnv builds the world on t. It sets TMPDIR (restored by t.Setenv's own
// cleanup) so the temp-file series sees only what the server creates.
func newSoakEnv(t *testing.T) *soakEnv {
	t.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("i18n: %v", err)
	}
	t.Cleanup(i18n.ResetForTesting)

	var db *gorm.DB
	backend := fuzzworld.BackendSQLite
	if os.Getenv(fuzzworld.PGDSNEnv) != "" {
		backend = fuzzworld.BackendPostgres
		db = fuzzworld.OpenPostgres(t, "soak")
	} else {
		dbPath := filepath.Join(t.TempDir(), "soak.db")
		dsn := fmt.Sprintf("%s?_foreign_keys=1&_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate", dbPath)
		db = fuzzworld.OpenSQLite(t, dsn, appstorage.DefaultSQLiteMaxOpenConns)
	}
	fuzzworld.Bootstrap(t, db)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// The sampler reads this pool's stats; Close must happen after the server is down.
	t.Cleanup(func() { _ = sqlDB.Close() })

	// TMPDIR is set only after the DB directory exists, so the database files are
	// not counted as server temp files.
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	c.SetBootstrapToken(soakBootstrapTok)
	ctx := context.Background()
	if _, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: soakAdminUser, Email: "soakadmin@example.com",
		Password: soakAdminPassword, Token: soakBootstrapTok,
	}); err != nil {
		t.Fatalf("BootstrapSystem: %v", err)
	}
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: soakAdminUser, Password: soakAdminPassword})
	if err != nil {
		t.Fatalf("admin login: %v", err)
	}

	cfg := &config.Config{}
	cfg.Server.HTTP = config.ServerInstanceConfig{Enabled: true, Port: "8080"}
	router, err := httpserver.NewRouter(cfg, c)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	env := &soakEnv{
		backend: backend, db: db, sqlDB: sqlDB, core: c,
		tmpDir: tmpDir, adminToken: sess.SessionToken,
	}
	h := router
	for _, wrap := range handlerWrappers {
		h = wrap(h, env)
	}
	env.srv = httptest.NewServer(h)
	// A dedicated transport (not http.DefaultTransport) so the soak owns, and can
	// close, every client-side connection goroutine it creates.
	env.tr = &http.Transport{MaxIdleConnsPerHost: 8, IdleConnTimeout: 90 * time.Second}
	env.client = &http.Client{Transport: env.tr, Timeout: 30 * time.Second}

	// Registered last, so it runs first: stop the server and the core's
	// bookkeeping before the DB handle (and, on PostgreSQL, the schema) goes.
	t.Cleanup(env.Close)
	return env
}

// Close stops the server and quiesces the core. Safe to call twice.
func (e *soakEnv) Close() {
	if e.closed {
		return
	}
	e.closed = true
	e.tr.CloseIdleConnections()
	e.srv.Close()
	e.core.FlushLastUsed(context.Background())
	e.core.FlushSecretReadDenials()
	handlers.DrainBackgroundGoroutines()
	services.DrainBackgroundGoroutines()
	core.DrainBackgroundGoroutines()
	for _, fn := range plantCleanups {
		fn()
	}
}
