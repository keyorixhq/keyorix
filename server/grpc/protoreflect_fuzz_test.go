package grpc_test

// FuzzGRPCProtoreflectInvariants -- fuzzer inventory item #6: a schema-aware
// gRPC fuzzer. Existing byte-level gRPC fuzzing dies almost entirely in proto
// decoding (malformed wire bytes never reach a handler); this one instead
// builds a WELL-TYPED request for a fuzzer-chosen registered keyorix.v1
// service+method by walking that method's protoreflect descriptor
// (protoreflect_builder_fuzz_test.go), then drives it through the REAL,
// fully-wired in-process gRPC server (bufconn) -- the actual interceptor
// chain, services, core, and a real SQLite world -- as three identities with
// different grants (zero-grant, read-only, admin), and checks four
// invariants that hold for EVERY RPC regardless of which one was picked:
//
//  1. NO LEAK: no panic reaches the client, and no codes.Unknown/Internal
//     status leaks a raw Go error string or stack trace (classifyStatusLeak,
//     red/green-proofed in protoreflect_oracle_mechanism_test.go).
//  2. AUTHZ: the zero-grant identity (a freshly created user with only the
//     universal baseline role, no read/write grant of any kind) must never
//     get an OK response that either changed the database (derived, not
//     hand-classified "mutating" -- see dbSnapshot) or carried the planted
//     canary secret's plaintext (derived "secret-reading", via
//     containsCanary). The read-only identity (system_auditor, global scope --
//     read access to secrets/users/roles/audit/system, no write grant of any
//     kind) gets the same write-side check. This generalizes
//     FuzzGRPCRESTSecretReadAuthzParity's model (REST vs gRPC decision parity
//     for secret reads) to EVERY RPC by deriving "mutating"/"secret-reading"
//     from the call's actual, observed effect instead of a hand-maintained
//     per-method list -- the latter is exactly the enumeration-completeness
//     trap CLAUDE.md warns about (new methods are added to this proto
//     routinely; a hand list would silently stop covering them).
//  3. ERROR-IMPLIES-NO-COMMIT: a non-OK status must leave the database
//     unchanged, except for a documented best-effort async write (see
//     bestEffortSideEffectTables).
//  4. BOUNDED WORK: handling time must not be disproportionate to the
//     request's marshaled size (checkBoundedWork).
//
// Oracles 2 and 3 share one mechanism (dbSnapshot/unexplainedWrite) --
// "did this one call write anything the documented best-effort channel
// doesn't already explain" is the same question whether asked of a call that
// returned OK (2) or one that didn't (3). This mechanism caught two REAL gaps
// in its own exemption list live (not product bugs): the GetCompliancePosture
// snapshot upsert and the LogSecretRead*-family secret_access_logs write --
// both are documented, intentional best-effort side effects, now named in
// bestEffortSideEffectTables.
//
// REPRODUCIBILITY GATE (mirrors server/http's FuzzCanarySecretLeakage, same
// reasoning): this world is long-lived and shared across every fuzz
// iteration within one worker process. A -fuzz burst's minimization step can
// report a failure whose window includes residual state from an earlier,
// not-yet-minimized candidate in the SAME continuing process -- confirmed
// live (2026-10-02): four burst-discovered ERROR-IMPLIES-NO-COMMIT /
// AUTHZ-BYPASS(write) failures on calls that structurally cannot write
// anything (a validation or authz rejection that returns before touching the
// DB, traced in each case) ALL passed cleanly when replayed in total
// isolation (go test -run=FuzzGRPCProtoreflectInvariants/<hash>), including
// with -parallel=1 (ruling out any cross-worker-process explanation). Before
// reporting ANY burst-discovered failure as a finding: replay its saved
// testdata/fuzz/FuzzGRPCProtoreflectInvariants/<hash> file alone. If it
// fails again, it's a genuine, state-independent finding. If it passes, it's
// state-dependent noise from this class of long-lived-world fuzzing -- do
// NOT commit it as a regression corpus entry (a replay-dependent file is
// flaky by file-discovery order, not a real regression check), and do not
// assert the underlying code is broken without separately confirming it
// (read the handler; a validation/authz-rejection path that returns before
// any storage call cannot have written anything).
//
// Session E5 already covers the request-smuggling / double-parse variant for
// gRPC; this target does not re-attempt that. Streaming RPCs are out of scope
// (see discoverUnaryMethods) and reported as a known gap in the coverage
// summary this fuzzer logs on Cleanup.

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	grpcservices "github.com/keyorixhq/keyorix/server/grpc/services"
)

// --- world ------------------------------------------------------------

var prMemDBSeq atomic.Int64

// prUniqueMemDSN mirrors server/http's uniqueMemDSN (package-private there,
// recreated here): a fresh shared-cache in-memory SQLite DB name per call so
// concurrent/sequential fuzz worlds never collide.
func prUniqueMemDSN() string {
	return fmt.Sprintf("file:kxprfuzz_%d?mode=memory&cache=shared&_timeout=30000&_journal_mode=WAL", prMemDBSeq.Add(1))
}

// prPrincipalPassword is the shared login password for every non-admin
// principal this world mints.
const prPrincipalPassword = "Xk7#Qp2$Rn5@Wv9!"

// prCanaryValue is the plaintext of the one secret this world seeds. Fixed
// (not per-run random) so a failing corpus entry replays identically --
// Go fuzz targets must not depend on a nondeterministic source.
const prCanaryValue = "KXPROTOREFLECT-CANARY-9f21ab77c6"

type prWorld struct {
	srv  *grpc.Server
	conn *grpc.ClientConn
	db   *sql.DB // raw *sql.DB for total_changes()/COUNT(*) snapshotting -- see dbSnapshot
	c    *core.KeyorixCore

	methods []grpcMethod

	zeroGrantTok string
	readOnlyTok  string
	adminTok     string

	// reachedMu/reached track, across the whole fuzz run, which methods were
	// actually invoked at least once -- drained in f.Cleanup to log the
	// coverage summary the session's "Done when" asks for.
	reachedMu sync.Mutex
	reached   map[string]bool
}

func (w *prWorld) markReached(key string) {
	w.reachedMu.Lock()
	defer w.reachedMu.Unlock()
	if w.reached == nil {
		w.reached = map[string]bool{}
	}
	w.reached[key] = true
}

func buildPRWorld(f *testing.F) *prWorld {
	f.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		f.Fatalf("i18n: %v", err)
	}

	gormDB := fuzzworld.OpenSQLite(f, prUniqueMemDSN(), 1)
	fuzzworld.Bootstrap(f, gormDB)
	if err := gormDB.AutoMigrate(models.AllTestModels()...); err != nil {
		f.Fatalf("migrate test models: %v", err)
	}
	sqlDB, err := gormDB.DB()
	if err != nil {
		f.Fatalf("underlying *sql.DB: %v", err)
	}
	installWriteCountTriggers(f, sqlDB, bestEffortSideEffectTables)

	c := core.NewKeyorixCore(store.NewLocalStorage(gormDB))
	ls := store.NewLocalStorage(gormDB)
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	if _, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "testadmin", Email: "testadmin@example.com",
		Password: "TestPassword123!", Token: "test-bootstrap-token",
	}); err != nil {
		f.Logf("bootstrap: %v (may already be initialised)", err)
	}
	adminSess, _, err := c.Login(ctx, &core.LoginRequest{Username: "testadmin", Password: "TestPassword123!"})
	if err != nil {
		f.Fatalf("admin login: %v", err)
	}
	admin, err := ls.GetUserByUsername(ctx, "testadmin")
	if err != nil || admin == nil {
		f.Fatalf("admin lookup: %v", err)
	}

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "prfuzz-proj"})
	if err != nil {
		f.Fatalf("project: %v", err)
	}
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	if err != nil {
		f.Fatalf("environment: %v", err)
	}
	if _, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "prfuzz-canary", Value: []byte(prCanaryValue), ProjectID: proj.ID, EnvironmentID: env.ID,
		Type: "password", CreatedBy: "testadmin", OwnerID: admin.ID,
	}); err != nil {
		f.Fatalf("seed canary secret: %v", err)
	}

	mint := func(uname string) string {
		u, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: uname, Email: uname + "@x.io", Password: prPrincipalPassword})
		if err != nil || u == nil {
			f.Fatalf("create user %s: %v", uname, err)
		}
		sess, _, err := c.Login(ctx, &core.LoginRequest{Username: uname, Password: prPrincipalPassword})
		if err != nil || sess == nil {
			f.Fatalf("login %s: %v", uname, err)
		}
		return sess.SessionToken
	}
	zeroGrantTok := mint("prfuzz-zero-grant")
	readOnlyTok := mint("prfuzz-read-only")

	// system_auditor (ADR-021 built-in role): install-wide read access to
	// secrets/users/roles/audit/system, no write permission of any kind --
	// reused as-is (not a bespoke role) so this fuzzer's "read-only" identity
	// tracks whatever the product actually ships as its read-only persona.
	auditorRole, err := ls.GetRoleByName(ctx, "system_auditor")
	if err != nil || auditorRole == nil {
		f.Fatalf("system_auditor role lookup: %v", err)
	}
	roUser, err := ls.GetUserByUsername(ctx, "prfuzz-read-only")
	if err != nil || roUser == nil {
		f.Fatalf("read-only user lookup: %v", err)
	}
	if err := c.AssignUserRole(ctx, 0, roUser.ID, auditorRole.ID, core.Scope{}, false); err != nil {
		f.Fatalf("grant system_auditor: %v", err)
	}

	srv, err := keyorixgrpc.NewServer(&config.Config{}, c)
	if err != nil {
		f.Fatalf("grpc server: %v", err)
	}
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		f.Fatalf("grpc dial: %v", err)
	}

	methods := discoverUnaryMethods(srv)
	if len(methods) == 0 {
		f.Fatalf("discoverUnaryMethods found zero unary methods -- harness is dry")
	}

	return &prWorld{
		srv: srv, conn: conn, db: sqlDB, c: c, methods: methods,
		zeroGrantTok: zeroGrantTok, readOnlyTok: readOnlyTok, adminTok: adminSess.SessionToken,
	}
}

func (w *prWorld) close() {
	w.srv.Stop()
	_ = w.conn.Close()
}

// --- oracle 2/3 shared mechanism: derived DB-write detection -----------

// bestEffortSideEffectTables are the documented, named exceptions to
// error-implies-no-commit / zero-grant-or-read-only-never-mutates: writes that
// fire as a DOCUMENTED side effect of an otherwise read-only or
// not-independently-authorized call, not as a consequence of the caller's own
// grants. A short, explicit list on purpose -- NOT a broad pattern match -- so
// a future, undocumented best-effort write this fuzzer finds stays a real
// finding instead of being silently swallowed by an over-broad exemption.
//
//   - audit_events: the gRPC services' goSafe-dispatched audit log write (see
//     server/grpc/services/secret_service.go's goSafe calls), fired
//     asynchronously and independently of whether the triggering RPC itself
//     was authorized or succeeded.
//   - compliance_posture_snapshots: GetCompliancePosture's own doc comment
//     (internal/core/compliance_posture.go) -- "Persist today's snapshot for
//     trend tracking (best-effort -- a write failure must not abort the
//     posture response an auditor is waiting on)". Found live by this
//     fuzzer's first run: a read-only (system_auditor) call to
//     GetCompliancePosture (and, transitively, GetComplianceControls, which
//     calls it internally) tripped the write-detection oracle before this
//     table was named here -- a real, intentional, documented side effect,
//     not a security bug, which is exactly what this list exists to name
//     explicitly rather than mask with a broader heuristic.
//   - secret_access_logs: every LogSecretRead*/LogSecretCreated*/
//     LogSecretUpdated*-family call (internal/core/audit.go's writeAccessLog)
//     writes BOTH audit_events AND this table for the same event -- found
//     live the same way as compliance_posture_snapshots: a read-only
//     (system_auditor) GetSecretVersions call (a metadata-only RPC, and
//     GRPC's own comment on it: "Audit as a secret read... Best-effort
//     metadata fetch") tripped the oracle because only audit_events was
//     named here at the time.
var bestEffortSideEffectTables = []string{"audit_events", "compliance_posture_snapshots", "secret_access_logs"}

// prFuzzWriteCountsTable plus one AFTER INSERT/UPDATE/DELETE trigger per
// bestEffortSideEffectTables entry (installed once in buildPRWorld via
// installWriteCountTriggers) is how this oracle tells "this exempt table
// absorbed a write" from "some OTHER table did", precisely. A row-content hash
// diff was tried first and rejected: GORM's FirstOrCreate+Assign (the
// snapshot upsert) issues a real UPDATE on every call regardless of whether
// the new values differ from the old ones, so SQLite's total_changes() counts
// it even when a content hash would see no difference -- a same-day second
// call with unchanged tallies produced exactly that false mismatch live
// (GetComplianceControls's seed, confirmed by tracing SQLite's own semantics:
// an UPDATE statement counts every row it SETs, not every row whose value
// actually changed). A trigger-based counter tracks "was a write statement
// executed against this table" directly, matching total_changes()'s own unit
// of account instead of approximating it via content.
const prFuzzWriteCountsTable = "pr_fuzz_write_counts"

func installWriteCountTriggers(t testing.TB, db *sql.DB, tables []string) {
	t.Helper()
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS " + prFuzzWriteCountsTable + " (table_name TEXT PRIMARY KEY, n INTEGER NOT NULL)"); err != nil {
		t.Fatalf("create %s: %v", prFuzzWriteCountsTable, err)
	}
	for _, tbl := range tables {
		// tbl always ranges over the fixed, hardcoded bestEffortSideEffectTables
		// literal slice, never fuzz input.
		if _, err := db.Exec("INSERT OR IGNORE INTO " + prFuzzWriteCountsTable + " (table_name, n) VALUES ('" + tbl + "', 0)"); err != nil { // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- tbl is always one of the hardcoded bestEffortSideEffectTables literals, never external input
			t.Fatalf("seed counter row for %s: %v", tbl, err)
		}
		for _, event := range []string{"INSERT", "UPDATE", "DELETE"} {
			stmt := fmt.Sprintf(
				"CREATE TRIGGER IF NOT EXISTS pr_fuzz_count_%s_%s AFTER %s ON %s BEGIN UPDATE %s SET n = n + 1 WHERE table_name = '%s'; END",
				tbl, event, event, tbl, prFuzzWriteCountsTable, tbl,
			) // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- tbl/event are always drawn from the fixed hardcoded literals above, never external input
			if _, err := db.Exec(stmt); err != nil {
				t.Fatalf("install %s trigger on %s: %v", event, tbl, err)
			}
		}
	}
}

type dbSnapshot struct {
	totalChanges int64
	sideEffectN  map[string]int64 // table -> write-trigger counter at snapshot time
}

func snapshotDB(t testing.TB, db *sql.DB) dbSnapshot {
	t.Helper()
	var snap dbSnapshot
	if err := db.QueryRow("SELECT total_changes()").Scan(&snap.totalChanges); err != nil {
		t.Fatalf("total_changes(): %v", err)
	}
	snap.sideEffectN = make(map[string]int64, len(bestEffortSideEffectTables))
	for _, tbl := range bestEffortSideEffectTables {
		var n int64
		if err := db.QueryRow("SELECT n FROM "+prFuzzWriteCountsTable+" WHERE table_name = ?", tbl).Scan(&n); err != nil {
			t.Fatalf("read write-count(%s): %v", tbl, err)
		}
		snap.sideEffectN[tbl] = n
	}
	return snap
}

// unexplainedWrite reports whether `after` reflects a DB write beyond what the
// documented best-effort side-effect tables account for. total_changes() is a
// SQLite connection-level counter of every row an INSERT/UPDATE/DELETE
// touched since the connection opened (serialized onto one connection by this
// world's SetMaxOpenConns(1), so it is meaningful here); comparing its delta
// against the exempt tables' own write-trigger-counter delta is what makes
// this check generic: it needs no per-call knowledge of which table a given
// RPC is expected to touch, unlike a hand-maintained "this method writes to
// that table" list -- it only needs the short, documented EXEMPTION list
// above.
//
// Known limitation (documented, not silently assumed away): if a single call
// legitimately touches an exempt table AND, in the same call, an unrelated
// table changes by exactly the same row count, the two deltas are
// indistinguishable from here and the latter would not be flagged. In
// practice this can only coincide for calls that already, legitimately, write
// the exempt table (i.e. GetCompliancePosture and GetComplianceControls) --
// every other RPC's calls see zero exempt-table writes, so any non-exempt
// write there is still caught in full.
func (before dbSnapshot) unexplainedWrite(after dbSnapshot) bool {
	delta := after.totalChanges - before.totalChanges
	var explained int64
	for _, tbl := range bestEffortSideEffectTables {
		// Each real write to tbl fires exactly one AFTER trigger, which issues its
		// own UPDATE on prFuzzWriteCountsTable -- that counter update is ITSELF one
		// more row total_changes() counts, on top of the real write it's counting.
		// So one explained write costs 2 total_changes() units, not 1: credit the
		// counter delta at that same rate so the two sides compare like for like.
		explained += 2 * (after.sideEffectN[tbl] - before.sideEffectN[tbl])
	}
	return delta > explained
}

// --- oracle 4: bounded work ---------------------------------------------

// perCallTimeout bounds a single RPC call; anything hitting it is either a
// hung handler or genuinely slow work on a huge input -- disproportionateSizeThreshold
// tells those two apart.
const perCallTimeout = 4 * time.Second

// disproportionateSizeThreshold: this builder caps individual
// string/bytes/repeated/map sizes well below 1 MiB (see fuzzCursor.sizeProbe),
// so a marshaled request below this threshold that still times out cannot be
// explained by "it was just a lot of data" -- it is disproportionate.
const disproportionateSizeThreshold = 1 << 20

// tLogger is the minimal subset of *testing.T checkBoundedWork needs --
// factored out so protoreflect_oracle_mechanism_test.go can red/green-proof
// this function directly with a recorder that observes a Fatalf call instead
// of actually failing the enclosing test (a real *testing.T's Fatalf aborts
// the goroutine and marks every ancestor subtest failed, which would make the
// RED half of that proof itself report as a failing test run).
type tLogger interface {
	Helper()
	Fatalf(format string, args ...any)
	Logf(format string, args ...any)
}

func checkBoundedWork(t tLogger, label string, m grpcMethod, reqSize int, elapsed time.Duration, timedOut bool) {
	t.Helper()
	if !timedOut {
		return
	}
	if reqSize < disproportionateSizeThreshold {
		t.Fatalf("BOUNDED-WORK VIOLATION op=%s principal=%s: a %d-byte request took longer than %s to handle (context deadline exceeded) -- work disproportionate to message size",
			m.key(), label, reqSize, perCallTimeout)
	}
	t.Logf("op=%s principal=%s: %d-byte request hit the %s deadline -- at/above the size-proportional threshold, not flagged", m.key(), label, reqSize, perCallTimeout)
}

// --- oracle 1: no panic / no leaking Unknown/Internal -------------------

// leakIndicatorPatterns are substrings that only ever appear in a RAW,
// unmapped Go/SQL/runtime error -- never in one of this codebase's own
// hand-written client-safe messages (see server/grpc/services/conversions.go's
// clientSafe and every mapXError's documented fallback string). Checking for
// these leak SHAPES, rather than hand-listing every one of the ~25 legitimate
// clientSafe/Internal messages the services package currently uses, is what
// keeps this sound as new Internal call sites are added -- a hand list would
// need updating every time; a leak-shape denylist does not.
var leakIndicatorPatterns = []string{
	"goroutine ", "runtime error", "panic:", "nil pointer dereference",
	".go:", "/users/", "/home/", "/private/",
	"sql:", "gorm:", "pq:", "sqlite:",
	"constraint failed", "constraint violation", "no rows in result set",
	"dial tcp", "connection refused",
}

func leakLooking(msg string) bool {
	lower := strings.ToLower(msg)
	for _, pat := range leakIndicatorPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

// classifyStatusLeak reports whether err's gRPC status is one oracle 1 must
// reject: codes.Unknown (which this codebase's handlers never intentionally
// return -- see the file-header's grep confirming every real call site maps to
// a specific code -- so its mere presence means some error reached the client
// unmapped, raw Go Error() text and all), or codes.Internal carrying a
// leak-shaped message. Red/green-proofed directly (no live server needed) in
// protoreflect_oracle_mechanism_test.go.
func classifyStatusLeak(err error) (bad bool, reason string) {
	if err == nil {
		return false, ""
	}
	st, ok := status.FromError(err)
	if !ok {
		return true, fmt.Sprintf("a non-gRPC-status error reached the client: %v", err)
	}
	switch st.Code() {
	case codes.Unknown:
		return true, fmt.Sprintf("codes.Unknown (an unmapped error reached the client, not a documented status): %q", st.Message())
	case codes.Internal:
		if leakLooking(st.Message()) {
			return true, fmt.Sprintf("codes.Internal message looks like a raw internal error, not a clean client-safe message: %q", st.Message())
		}
	}
	return false, ""
}

func containsCanary(resp *dynamicpb.Message) bool {
	if resp == nil {
		return false
	}
	b, err := proto.Marshal(resp)
	if err != nil {
		return false
	}
	return bytes.Contains(b, []byte(prCanaryValue))
}

func invokeGeneric(ctx context.Context, conn *grpc.ClientConn, m grpcMethod, req *dynamicpb.Message) (*dynamicpb.Message, error) {
	resp := dynamicpb.NewMessage(m.output)
	err := conn.Invoke(ctx, m.fullMethod(), req, resp)
	return resp, err
}

// --- the fuzz target -----------------------------------------------------

func FuzzGRPCProtoreflectInvariants(f *testing.F) {
	w := buildPRWorld(f)
	f.Cleanup(func() {
		w.close()
		i18n.ResetForTesting()
		w.reachedMu.Lock()
		defer w.reachedMu.Unlock()
		var unreached []string
		for _, m := range w.methods {
			if !w.reached[m.key()] {
				unreached = append(unreached, m.key())
			}
		}
		f.Logf("protoreflect fuzzer coverage: %d/%d unary methods reached", len(w.reached), len(w.methods))
		if len(unreached) > 0 {
			f.Logf("unreached methods (%d): %v", len(unreached), unreached)
		}
	})

	// One deterministic seed per discovered method -- every method gets
	// exercised at least once even before any coverage-guided mutation runs,
	// and `go test` (seed-corpus-only, no -fuzz flag) alone proves every RPC
	// is reachable through this harness.
	for i := range w.methods {
		f.Add([]byte{byte(i)})
	}
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, program []byte) {
		cur := newFuzzCursor(program)
		m := w.methods[int(cur.byte())%len(w.methods)]
		w.markReached(m.key())
		bodyOffset := cur.pos

		// buildReq rebuilds the SAME message from the SAME remaining bytes each
		// time it's called -- a fresh cursor copy starting at bodyOffset -- so all
		// three identities below are compared on an identical request, the same
		// control FuzzGRPCRESTSecretReadAuthzParity's own parity checks rely on.
		buildReq := func() *dynamicpb.Message {
			fresh := &fuzzCursor{data: program, pos: bodyOffset}
			return buildMessage(m.input, fresh, 0)
		}

		drain := func() {
			core.DrainBackgroundGoroutines()
			grpcservices.DrainBackgroundGoroutines()
		}

		runAs := func(label, token string) (resp *dynamicpb.Message, before, after dbSnapshot, err error) {
			req := buildReq()
			reqSize := proto.Size(req)
			ctx := context.Background()
			if token != "" {
				ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
			}
			cctx, cancel := context.WithTimeout(ctx, perCallTimeout)
			defer cancel()

			drain()
			before = snapshotDB(t, w.db)
			start := time.Now()
			resp, err = invokeGeneric(cctx, w.conn, m, req)
			elapsed := time.Since(start)
			drain()
			after = snapshotDB(t, w.db)

			timedOut := status.Code(err) == codes.DeadlineExceeded
			checkBoundedWork(t, label, m, reqSize, elapsed, timedOut)
			if bad, reason := classifyStatusLeak(err); bad {
				t.Fatalf("op=%s principal=%s: %s", m.key(), label, reason)
			}
			return resp, before, after, err
		}

		errorImpliesNoCommit := func(label string, callErr error, before, after dbSnapshot) {
			if callErr != nil && before.unexplainedWrite(after) {
				t.Fatalf("ERROR-IMPLIES-NO-COMMIT violation op=%s principal=%s: non-OK status (%v) but the DB changed outside the documented best-effort audit write", m.key(), label, callErr)
			}
		}

		zResp, zBefore, zAfter, zErr := runAs("zero-grant", w.zeroGrantTok)
		if zErr == nil {
			if zBefore.unexplainedWrite(zAfter) {
				t.Fatalf("AUTHZ BYPASS (write) op=%s: zero-grant principal got OK and the DB changed outside the documented best-effort audit write", m.key())
			}
			if containsCanary(zResp) {
				t.Fatalf("AUTHZ BYPASS (secret read) op=%s: zero-grant principal got OK and the response carried the canary secret's plaintext", m.key())
			}
		}
		errorImpliesNoCommit("zero-grant", zErr, zBefore, zAfter)

		_, roBefore, roAfter, roErr := runAs("read-only", w.readOnlyTok)
		if roErr == nil && roBefore.unexplainedWrite(roAfter) {
			t.Fatalf("AUTHZ BYPASS (write) op=%s: read-only principal (system_auditor, no write grant) got OK and the DB changed outside the documented best-effort audit write", m.key())
		}
		errorImpliesNoCommit("read-only", roErr, roBefore, roAfter)

		// admin: no authz assertion (expected to succeed broadly across a
		// fuzzer-chosen method+request it didn't design for) -- still covered by
		// the leak/bounded-work checks inside runAs, and by error-implies-no-commit
		// on whatever subset of fuzzed requests admin itself can't satisfy
		// (malformed IDs, missing resources, etc).
		_, adBefore, adAfter, adErr := runAs("admin", w.adminTok)
		errorImpliesNoCommit("admin", adErr, adBefore, adAfter)
	})
}
