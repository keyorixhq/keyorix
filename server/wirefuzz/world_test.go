// Package wirefuzz holds the wire-protocol fuzz harnesses for the Keyorix
// server (backlog B1). Unlike the existing HTTP fuzzers (FuzzKeyorixHTTPAPISequence
// et al.), which drive router.ServeHTTP through httptest.NewRequest and therefore
// BYPASS the wire, these harnesses stand the real stack up on a loopback
// net.Listener and feed RAW BYTES to the production HTTP/1.1 parser, the x/net/http2
// framer, and the gRPC framing layer — the request-smuggling / framing-confusion
// surface that lives between the socket and the handlers.
//
// This file (world_test.go) builds the shared, seeded, fully-wired stack once and
// serves it on 127.0.0.1:0. It deliberately reuses the SAME seeding path the
// existing HTTP fuzzer uses (fuzzworld.OpenSQLite + Bootstrap + core.NewKeyorixCore
// + NewRouter), so the harness exercises the exact production router + auth
// middleware + handlers + core + crypto + storage, not a reduced copy.
package wirefuzz

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	httpServer "github.com/keyorixhq/keyorix/server/http"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// Connection-level limits mirror the production REST listener (server/http_server.go).
// The wire harness pins them so an input that would be rejected by a slowloris/body
// cap in production is rejected identically here.
const (
	wireReadHeaderTimeout = 10 * time.Second
	wireReadTimeout       = 15 * time.Second
	wireIdleTimeout       = 60 * time.Second
	wireMaxHeaderBytes    = 64 << 10
)

// handlerHit records one top-of-stack handler invocation, i.e. one request that
// net/http's own HTTP/1.1 (or HTTP/2) parser decided was a complete request and
// delivered to the router. The smuggling oracle counts these: K well-formed
// requests on the wire must produce at most K hits.
type handlerHit struct {
	method    string
	path      string
	authHdr   string // Authorization header as presented on the wire
	principal string // principal resolved from authHdr against the seeded store ("" = none/invalid)
	status    int
}

// recorder is the OUTERMOST middleware. It counts handler invocations and logs
// what each request presented. It sits outside NewRouter's chain, so it sees the
// request exactly as net/http framed it (the smuggling-relevant boundary) and the
// final status the chain produced.
//
// What it does NOT see: the server-internal post-auth *middleware.UserContext (that
// is set by the Authentication middleware INSIDE NewRouter, downstream of here, and
// its context does not propagate back out). The `principal` field is therefore the
// principal the request PRESENTS on the wire, resolved independently against the
// same store — not the server's own decision. Principal confusion is caught by the
// authorization-invariance oracle (response divergence), not by reading this field.
type recorder struct {
	mu   sync.Mutex
	hits []handlerHit
	n    atomic.Int64
	// resolve maps a bearer token to a principal label using the seeded store.
	resolve func(authHdr string) string
}

func (rec *recorder) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.n.Add(1)
		sw := &statusWriter{ResponseWriter: w, status: 200}
		auth := r.Header.Get("Authorization")
		next.ServeHTTP(sw, r)
		rec.mu.Lock()
		rec.hits = append(rec.hits, handlerHit{
			method: r.Method, path: r.URL.Path, authHdr: auth,
			principal: rec.resolve(auth), status: sw.status,
		})
		rec.mu.Unlock()
	})
}

func (rec *recorder) reset() {
	rec.mu.Lock()
	rec.hits = rec.hits[:0]
	rec.mu.Unlock()
	rec.n.Store(0)
}

func (rec *recorder) count() int { return int(rec.n.Load()) }

func (rec *recorder) snapshot() []handlerHit {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	out := make([]handlerHit, len(rec.hits))
	copy(out, rec.hits)
	return out
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

// wireWorld is the running stack under test.
type wireWorld struct {
	addr     string // 127.0.0.1:<port> of the live HTTP listener
	rec      *recorder
	c        *core.KeyorixCore
	db       *gorm.DB
	adminTok string // a global-admin bearer token (authorized everywhere)
	readTok  string // a scoped reader token (projA only)
	refA     string // "proja/prod/sa"
	valA     string // plaintext of secret A
	refB     string // "projb/prod/sb" — readTok is NOT granted here
	valB     string
	srv      *http.Server
}

// grantedReaderUser/… are fixed labels used by the token resolver.
const (
	adminUser  = "testadmin"
	readerUser = "wirereader"
	readerPass = "Xk7#Qp2$Rn5@Wv9!"
	adminPass  = "TestPassword123!"
)

// seededStack is the shared seeded core + credentials both the HTTP and gRPC wire
// worlds stand their transports on.
type seededStack struct {
	c        *core.KeyorixCore
	db       *gorm.DB
	adminTok string
	readTok  string
	refA     string
	valA     string
	refB     string
	valB     string
}

// resolveToken labels a bearer token against the two seeded sessions.
func (s *seededStack) resolveToken(authHdr string) string {
	const p = "Bearer "
	if len(authHdr) <= len(p) || authHdr[:len(p)] != p {
		return ""
	}
	switch authHdr[len(p):] {
	case s.adminTok:
		return adminUser
	case s.readTok:
		return readerUser
	default:
		return ""
	}
}

// seedCore builds the fully-wired core with an admin + a projA-scoped reader and
// two secrets (A in projA, B in projB). Identical to the existing HTTP fuzzer's
// seeding path so the wire harness exercises production code, not a reduced copy.
func seedCore(tb testing.TB) *seededStack {
	tb.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		tb.Fatalf("i18n: %v", err)
	}
	tb.Cleanup(i18n.ResetForTesting)

	db := fuzzworld.OpenSQLite(tb, sqlitetest.DSN("wirefuzz_"), 1)
	fuzzworld.Bootstrap(tb, db)
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		tb.Fatalf("migrate test models: %v", err)
	}

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	c.SetBootstrapToken("wire-bootstrap-token")
	if _, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: adminUser, Email: "testadmin@example.com",
		Password: adminPass, Token: "wire-bootstrap-token",
	}); err != nil {
		tb.Logf("bootstrap: %v (may already be initialised)", err)
	}
	adminSess, _, err := c.Login(ctx, &core.LoginRequest{Username: adminUser, Password: adminPass})
	if err != nil {
		tb.Fatalf("admin login: %v", err)
	}
	admin, err := ls.GetUserByUsername(ctx, adminUser)
	if err != nil || admin == nil {
		tb.Fatalf("admin lookup: %v", err)
	}

	pA, err := ls.CreateProject(ctx, &models.Project{Name: "proja"})
	if err != nil {
		tb.Fatalf("projA: %v", err)
	}
	eA, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: pA.ID})
	if err != nil {
		tb.Fatalf("envA: %v", err)
	}
	pB, err := ls.CreateProject(ctx, &models.Project{Name: "projb"})
	if err != nil {
		tb.Fatalf("projB: %v", err)
	}
	eB, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: pB.ID})
	if err != nil {
		tb.Fatalf("envB: %v", err)
	}

	// Reader role carrying secrets.read.
	var perm models.Permission
	if e := db.Where("name = ?", "secrets.read").First(&perm).Error; e != nil {
		perm = models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		if e2 := db.Create(&perm).Error; e2 != nil {
			tb.Fatalf("seed permission: %v", e2)
		}
	}
	role := models.Role{Name: "wire-reader", NameFolded: "wire-reader"}
	if e := db.Create(&role).Error; e != nil {
		tb.Fatalf("seed role: %v", e)
	}
	if e := db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error; e != nil {
		tb.Fatalf("seed role-permission: %v", e)
	}

	sA, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "sa", Value: []byte("VALUE-A-9f3c1"), ProjectID: pA.ID, EnvironmentID: eA.ID,
		Type: "password", CreatedBy: adminUser, OwnerID: admin.ID,
	})
	if err != nil || sA == nil {
		tb.Fatalf("secretA: %v", err)
	}
	sB, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "sb", Value: []byte("VALUE-B-6b28e"), ProjectID: pB.ID, EnvironmentID: eB.ID,
		Type: "password", CreatedBy: adminUser, OwnerID: admin.ID,
	})
	if err != nil || sB == nil {
		tb.Fatalf("secretB: %v", err)
	}

	// Scoped reader: granted secrets.read on projA ONLY.
	reader, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: readerUser, Email: "wirereader@x.io", Password: readerPass})
	if err != nil || reader == nil {
		tb.Fatalf("create reader: %v", err)
	}
	if err := c.AssignUserRole(ctx, 0, reader.ID, role.ID, core.Scope{ProjectID: pA.ID}, false); err != nil {
		tb.Fatalf("grant reader: %v", err)
	}
	readerSess, _, err := c.Login(ctx, &core.LoginRequest{Username: readerUser, Password: readerPass})
	if err != nil {
		tb.Fatalf("reader login: %v", err)
	}

	return &seededStack{
		c: c, db: db,
		adminTok: adminSess.SessionToken, readTok: readerSess.SessionToken,
		refA: "proja/prod/sa", valA: "VALUE-A-9f3c1",
		refB: "projb/prod/sb", valB: "VALUE-B-6b28e",
	}
}

// buildWireWorld seeds a stack and serves the real HTTP router on a loopback
// listener behind a recording outer middleware.
func buildWireWorld(tb testing.TB) *wireWorld {
	tb.Helper()
	s := seedCore(tb)
	router, err := httpServer.NewRouter(&config.Config{}, s.c)
	if err != nil {
		tb.Fatalf("router: %v", err)
	}
	rec := &recorder{resolve: s.resolveToken}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler:           rec.wrap(router),
		ReadHeaderTimeout: wireReadHeaderTimeout,
		ReadTimeout:       wireReadTimeout,
		IdleTimeout:       wireIdleTimeout,
		MaxHeaderBytes:    wireMaxHeaderBytes,
	}
	go func() { _ = srv.Serve(ln) }()
	tb.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	})

	return &wireWorld{
		addr: ln.Addr().String(), rec: rec, c: s.c, db: s.db,
		adminTok: s.adminTok, readTok: s.readTok,
		refA: s.refA, valA: s.valA, refB: s.refB, valB: s.valB,
		srv: srv,
	}
}
