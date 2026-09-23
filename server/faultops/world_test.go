// world_test.go builds a fresh world per operation: a real SQLite-backed
// storage.Storage wrapped in faultstorage.FaultyStorage, installed as
// KeyorixCore's storage, and driven through REAL transports — an httptest.Server
// over the actual server/http router for REST/system, and a real grpc.Server
// (server/grpc.NewServer, the exact production wiring including
// RecoveryInterceptor/AuthInterceptor) over bufconn for gRPC. Using the real
// interceptor chain (not calling *GRPCService methods in-process, which several
// existing unit tests do) matters specifically for oracle (b): a panic must
// reach the caller through the SAME recovery path a production panic would.
//
// Reproducibility (RULES): every world is built ONLY from the fuzz input (which
// op, which transport, which fault) — nothing carries over between fuzz
// iterations, so a saved input reproduces its failure standalone.
package faultops

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	grpcserver "github.com/keyorixhq/keyorix/server/grpc"
	httpserver "github.com/keyorixhq/keyorix/server/http"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var memDBSeq atomic.Int64

func uniqueMemDSN() string {
	return fmt.Sprintf("file:faultops_%d?mode=memory&cache=shared&_timeout=30000&_journal_mode=WAL", memDBSeq.Add(1))
}

func mustExec(t *testing.T, db *gorm.DB, sql string) {
	t.Helper()
	if err := db.Exec(sql).Error; err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// faultWorld is everything one fuzz iteration needs: the raw DB (for
// snapshotDB), the faulty storage wrapper (for arming/inspecting faults), and
// live REST + gRPC clients authenticated as the one bootstrapped admin.
type faultWorld struct {
	db         *gorm.DB
	core       *core.KeyorixCore
	faulty     *faultstorage.FaultyStorage
	httpServer *httptest.Server
	httpClient *http.Client
	adminToken string
	grpcConn   *grpc.ClientConn
	grpcCtx    context.Context
}

// newFaultWorld builds a fresh world with spec armed (nil arms nothing — a pure
// pass-through, used to run an unfaulted prefix/suffix or a fault-free reference
// world for the oracle's state comparison).
func newFaultWorld(t *testing.T, spec *faultstorage.FaultSpec) *faultWorld {
	t.Helper()

	// sync.Once-guarded internally — cheap to call once per world, and every
	// core code path that renders a user-facing message (BootstrapSystem
	// included) panics without it.
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("i18n.InitializeForTesting: %v", err)
	}

	worldPhase := time.Now()
	db, err := gorm.Open(sqlite.Open(uniqueMemDSN()), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		t.Fatal(err)
	}
	// Mirrors server/http/integration_test.go's partial-unique-index setup
	// (production migrations these AutoMigrate skips) — duplicated here rather
	// than shared (see STEP 0 report).
	mustExec(t, db, "CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active "+
		"ON project_memberships (project_id, user_id) WHERE state <> 'revoked'")
	mustExec(t, db, "CREATE UNIQUE INDEX IF NOT EXISTS uniq_legal_holds_active "+
		"ON legal_holds (released) WHERE released = false")
	mustExec(t, db, "CREATE UNIQUE INDEX IF NOT EXISTS uniq_break_glass_active_project_user "+
		"ON break_glass_activations (project_id, user_id) WHERE state = 'active'")
	mustExec(t, db, "CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active "+
		"ON users (LOWER(email)) WHERE deleted_at IS NULL AND email <> ''")
	logWorldPhase(t, "sqlite open+migrate+indexes", worldPhase)

	worldPhase = time.Now()
	real := store.NewLocalStorage(db)
	faulty := faultstorage.NewFaultyStorage(real, spec)
	testCore := core.NewKeyorixCore(faulty)

	testCore.SetBootstrapToken("fault-fuzz-bootstrap")
	ctx := context.Background()
	if _, err := testCore.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "faultadmin", Email: "faultadmin@example.com",
		Password: "FaultFuzzAdmin123!", Token: "fault-fuzz-bootstrap",
	}); err != nil {
		t.Fatalf("BootstrapSystem: %v", err)
	}
	session, _, err := testCore.Login(ctx, &core.LoginRequest{
		Username: "faultadmin", Password: "FaultFuzzAdmin123!",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	logWorldPhase(t, "bootstrap+login", worldPhase)

	worldPhase = time.Now()
	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}
	handler, err := httpserver.NewRouter(cfg, testCore)
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewServer(handler)
	t.Cleanup(httpSrv.Close)
	logWorldPhase(t, "REST router + httptest.Server", worldPhase)

	worldPhase = time.Now()
	grpcSrv, err := grpcserver.NewServer(&config.Config{}, testCore)
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	logWorldPhase(t, "grpc.Server + bufconn + client", worldPhase)

	grpcCtx := metadata.NewOutgoingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+session.SessionToken))

	return &faultWorld{
		db: db, core: testCore, faulty: faulty,
		httpServer: httpSrv, httpClient: &http.Client{Timeout: 10 * time.Second},
		adminToken: session.SessionToken,
		grpcConn:   conn, grpcCtx: grpcCtx,
	}
}

// logWorldPhase records one newFaultWorld phase's duration — always-on since
// it's cheap and directly informs whether a slow iteration is DB/bootstrap-,
// REST-, or gRPC-server-bound (see PROFILE-tagged tests in
// profile_iteration_test.go and the STEP 1 execs/sec follow-up).
func logWorldPhase(t *testing.T, label string, start time.Time) {
	t.Helper()
	t.Logf("PROFILE world.%-28s %v", label, time.Since(start))
}
