package http

// canary_secret_leakage_fuzz_test.go — FuzzCanarySecretLeakage.
//
// Keyorix's core promise: a secret value never appears anywhere it shouldn't. This
// fuzzer plants unique canary secret values, drives a fuzzed sequence of hostile
// operations (cross-project reads, malformed/oversized/wrong-content-type requests,
// rotation, version reads, deletes, audit queries, list/export endpoints) through the
// REAL, fully-wired stack — the actual chi router + auth middleware + handlers + core
// + crypto + storage, PLUS the real gRPC server over bufconn — and scans EVERY
// reachable output channel for the canary after every op and at sequence end.
//
// Oracle (exact-match, no heuristics): a canary may appear ONLY in the JSON response
// body of one of three designated, permission-checked value-disclosure calls — HTTP
// GET /secrets/value?ref=, HTTP GET /secrets/{id}?include_value=true, gRPC
// SecretService.GetSecretValue — made by a principal the live shadow-grant model says
// currently holds read access to THAT EXACT secret (or is admin), and even then only
// in the `value` field, never alongside the OTHER secret's canary. Every other
// channel — logs (stdlib `log`, the sole logger in this codebase), every other HTTP
// response body/header (list, versions, diff, access-log export, audit search/export,
// inventory CSV, metrics, health, every mutation response), every gRPC response/error/
// metadata/trailer, the full SQLite schema (every table, every column, introspected —
// not hand-enumerated, so a table this file's author didn't think of is still
// covered), and the raw on-disk SQLite file bytes — gets ZERO TOLERANCE: any
// occurrence of any canary, in any of the encodings below, anywhere in any of those
// channels, is an immediate failure naming the channel, op index, principal, and a
// short (never more than ~24 bytes either side of the match) context snippet.
//
// Encodings checked per canary: raw, base64 (std/URL, padded/unpadded), hex
// (lower/upper). JSON-escaping and URL-encoding are no-ops for this charset
// ("kxcanary-" + lowercase hex) and are not separately generated — noted, not
// silently skipped. The DB-plaintext-at-rest property (storage.encryption.enabled)
// is asserted by wiring a REAL encryption.Service (not a no-op) and then applying the
// identical zero-tolerance scan to the ciphertext columns — a live encryption bug
// surfaces exactly like any other leak, through the same oracle.
//
// Audit rows are written asynchronously (goSafe, detached context) — a per-op DB scan
// would either race that write or need a bounded poll on every one of up to ~40*3
// steps, which is too slow for fuzzing throughput. The full generic DB/raw-file scan
// therefore runs once per sequence (after a short best-effort settle), not per-op; log
// buffer + HTTP/gRPC response scans DO run after every single op. This is a
// deliberate, documented scope decision, not a silent gap — see the investigation
// report for the full channel-coverage accounting.
//
// See docs/findings/ for any confirmed leak this harness's red-proofs or live runs
// surface, and scripts/fuzzing/targets.conf for this target's soak tier.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// lockedBuffer is a mutex-guarded io.Writer standing in for stdlib log's default
// output. A goSafe-launched background goroutine can log concurrently with the
// foreground fuzz iteration draining/resetting the buffer between ops, so this needs
// real synchronization, not the single-goroutine assumption the rest of this harness
// can otherwise make (buildCanaryWorld runs once per fuzz worker PROCESS — see below).
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuffer) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.buf.Bytes()...)
}

func (l *lockedBuffer) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf.Reset()
}

type canaryPrincipal struct {
	id    uint
	token string
}

type canaryWorld struct {
	router http.Handler
	grpc   pb.SecretServiceClient
	db     *gorm.DB
	dbPath string // on-disk SQLite file -- required for the raw-bytes plaintext-at-rest scan
	c      *core.KeyorixCore

	readerRole uint
	adminTok   string
	adminID    uint

	projAID, projBID uint
	envAID, envBID   uint
	secAID, secBID   uint
	refA, refB       string

	principals []canaryPrincipal // 3: index 2 is the deliberate "never granted by fixture setup" outsider anchor
	logBuf     *lockedBuffer
}

func (w *canaryWorld) drainLog() []byte {
	b := w.logBuf.Bytes()
	w.logBuf.Reset()
	return b
}

func (w *canaryWorld) adminReq(method, target, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Header.Set("Authorization", "Bearer "+w.adminTok)
	rec := httptest.NewRecorder()
	w.router.ServeHTTP(rec, req)
	return rec
}

// scanOp applies the zero-tolerance oracle to an ordinary (non-value-disclosure)
// HTTP call's body, headers, AND the log lines emitted while handling it. Every op in
// this fuzzer other than the three designated read endpoints goes through this.
func (w *canaryWorld) scanOp(t *testing.T, opIdx int, channel, principal string, rec *httptest.ResponseRecorder, canaries ...string) {
	t.Helper()
	scanZeroTolerance(t, channel+":body", opIdx, principal, rec.Body.Bytes(), canaries...)
	scanZeroTolerance(t, channel+":headers", opIdx, principal, []byte(fmt.Sprintf("%v", rec.Header())), canaries...)
	scanZeroTolerance(t, "log", opIdx, principal, w.drainLog(), canaries...)
}

// deriveCanary produces a per-iteration, per-label canary deterministically from the
// fuzz input bytes -- reproducible corpus replay (same input -> same canary -> same
// failure), not crypto/rand, and safe under Go's ban on nondeterministic sources
// (Date.Now/math-rand-style) inside fuzz targets meant to be resumable/replayable.
func deriveCanary(label string, program []byte) string {
	h := sha256.Sum256(append([]byte("kx-canary-"+label+"-"), program...))
	return "kxcanary-" + hex.EncodeToString(h[:16])
}

// canaryVariants expands one canary string into every encoding this fuzzer checks
// for. JSON-escaping and URL-encoding are deliberately absent: this charset
// ("kxcanary-" + lowercase hex) contains no character either encoding would alter, so
// the raw variant already covers both -- not an oversight, see the file header.
func canaryVariants(v string) [][]byte {
	b := []byte(v)
	h := hex.EncodeToString(b)
	return [][]byte{
		b,
		[]byte(base64.StdEncoding.EncodeToString(b)),
		[]byte(base64.RawStdEncoding.EncodeToString(b)),
		[]byte(base64.URLEncoding.EncodeToString(b)),
		[]byte(base64.RawURLEncoding.EncodeToString(b)),
		[]byte(h),
		[]byte(strings.ToUpper(h)),
	}
}

func snippetAround(haystack []byte, idx, matchLen int) string {
	start := idx - 12
	if start < 0 {
		start = 0
	}
	end := idx + matchLen + 12
	if end > len(haystack) {
		end = len(haystack)
	}
	return fmt.Sprintf("context=%q", string(haystack[start:end]))
}

// scanZeroTolerance fails immediately if ANY variant of ANY given canary appears
// anywhere in haystack. Every caller of this function represents a channel on which
// NO canary is ever legitimately disclosed -- see checkValueEndpoint for the three
// endpoints that get the nuanced (authorized-vs-not) oracle instead.
func scanZeroTolerance(t *testing.T, channel string, opIdx int, principal string, haystack []byte, canaries ...string) {
	t.Helper()
	for _, c := range canaries {
		if c == "" {
			continue
		}
		for _, variant := range canaryVariants(c) {
			if idx := bytes.Index(haystack, variant); idx >= 0 {
				t.Fatalf("CANARY LEAK [%s] op #%d principal=%s: matched %q -- %s",
					channel, opIdx, principal, string(variant), snippetAround(haystack, idx, len(variant)))
			}
		}
	}
}

type valueEnvelope struct {
	Data struct {
		Value string `json:"value"`
	} `json:"data"`
}

// checkValueEndpoint is the nuanced oracle for the three designated value-disclosure
// calls. allowed comes from the live shadow-grant model (or admin), NOT from the
// HTTP/gRPC status code -- so an authz bug that returns 200 to an unauthorized
// principal is still caught (AUTHZ BYPASS below), same as the wantVal/gotValue
// mismatch catches a cross-secret substitution bug (INTEGRITY below).
func checkValueEndpoint(t *testing.T, opIdx int, channel, principal string, allowed, statusOK bool, gotValue string, code int, body, headerBytes []byte, wantVal, otherVal string) {
	t.Helper()
	if len(headerBytes) > 0 {
		scanZeroTolerance(t, channel+":headers", opIdx, principal, headerBytes, wantVal, otherVal)
	}
	if !allowed {
		if statusOK {
			t.Fatalf("op #%d [%s]: AUTHZ BYPASS -- unauthorized principal=%s got a successful response (code=%d)", opIdx, channel, principal, code)
		}
		scanZeroTolerance(t, channel+":deny-body", opIdx, principal, body, wantVal, otherVal)
		return
	}
	if !statusOK {
		// Never assert must-200 for an allowed call (matches FuzzKeyorixHTTPAPISequence's
		// own convention) -- but whatever came back still gets zero tolerance.
		scanZeroTolerance(t, channel+":allow-nonOK-body", opIdx, principal, body, wantVal, otherVal)
		return
	}
	if gotValue != wantVal {
		t.Fatalf("op #%d [%s]: INTEGRITY -- authorized read by %s returned a value that does not match the requested secret's canary (got len=%d want len=%d) -- possible cross-secret leak",
			opIdx, channel, principal, len(gotValue), len(wantVal))
	}
	// The OTHER secret's canary must never ride along with this legitimate disclosure.
	scanZeroTolerance(t, channel+":allow-body-cross-check", opIdx, principal, body, otherVal)
}

var canaryTableNameRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// scanDBGeneric introspects the live schema (sqlite_master + PRAGMA table_info) and
// scans every column of every table for every canary variant. Introspection, not a
// hand-enumerated table list, on purpose -- this codebase's own standing lesson is
// that a hand-maintained enumeration of call/storage shapes reliably misses one (see
// CLAUDE.md's "an enumeration is only as complete as the idioms it knows about").
// This single mechanism is what makes audit_events, notifications, anomaly_alerts,
// secret_metadata_histories, dynamic_secret_configs/leases, mfa_secrets, and
// secret_versions.encrypted_value all covered without a per-table special case.
func scanDBGeneric(t *testing.T, sqlDB *sql.DB, canaries []string) {
	t.Helper()
	rows, err := sqlDB.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatalf("db scan: list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			t.Fatalf("db scan: scan table name: %v", err)
		}
		if canaryTableNameRe.MatchString(n) {
			tables = append(tables, n)
		}
	}
	rows.Close()

	for _, tbl := range tables {
		colRows, err := sqlDB.Query("PRAGMA table_info(" + tbl + ")")
		if err != nil {
			t.Fatalf("db scan: table_info %s: %v", tbl, err)
		}
		var cols []string
		for colRows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dflt interface{}
			if err := colRows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
				colRows.Close()
				t.Fatalf("db scan: table_info scan %s: %v", tbl, err)
			}
			if canaryTableNameRe.MatchString(name) {
				cols = append(cols, name)
			}
		}
		colRows.Close()
		if len(cols) == 0 {
			continue
		}

		quoted := make([]string, len(cols))
		for i, c := range cols {
			quoted[i] = `"` + c + `"`
		}
		dataRows, err := sqlDB.Query("SELECT " + strings.Join(quoted, ",") + " FROM " + tbl) //nolint:gosec -- table/col names are schema-introspected (sqlite_master/PRAGMA), not attacker input, and regex-validated above
		if err != nil {
			t.Fatalf("db scan: select %s: %v", tbl, err)
		}
		dest := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range dest {
			ptrs[i] = &dest[i]
		}
		for dataRows.Next() {
			if err := dataRows.Scan(ptrs...); err != nil {
				dataRows.Close()
				t.Fatalf("db scan: row scan %s: %v", tbl, err)
			}
			for i, v := range dest {
				b := cellBytes(v)
				if b == nil {
					continue
				}
				for _, c := range canaries {
					if c == "" {
						continue
					}
					for _, variant := range canaryVariants(c) {
						if idx := bytes.Index(b, variant); idx >= 0 {
							dataRows.Close()
							t.Fatalf("CANARY LEAK [db:%s.%s] matched %q -- %s", tbl, cols[i], string(variant), snippetAround(b, idx, len(variant)))
						}
					}
				}
			}
		}
		dataRows.Close()
	}
}

func cellBytes(v interface{}) []byte {
	switch x := v.(type) {
	case nil:
		return nil
	case []byte:
		return x
	case string:
		return []byte(x)
	default:
		return []byte(fmt.Sprintf("%v", x))
	}
}

// scanRawDBFile scans the raw on-disk SQLite file bytes -- the literal plaintext-
// at-rest check the RULES call for, distinct from and in addition to scanDBGeneric's
// column-level scan (this also catches anything sitting in freelist/overflow pages a
// column-level SELECT wouldn't surface). Requires a FILE-backed DB, not :memory: --
// see buildCanaryWorld.
func scanRawDBFile(t *testing.T, path string, canaries []string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec -- path is this fuzz target's own f.TempDir()-scoped file, not user input
	if err != nil {
		t.Fatalf("db scan: read raw file %s: %v", path, err)
	}
	for _, c := range canaries {
		if c == "" {
			continue
		}
		for _, variant := range canaryVariants(c) {
			if idx := bytes.Index(data, variant); idx >= 0 {
				t.Fatalf("CANARY LEAK [db:raw-file] matched %q at byte offset %d in %s", string(variant), idx, path)
			}
		}
	}
}

// buildCanaryWorld stands up the real production stack once per fuzz worker PROCESS
// (Go's native fuzzer runs each -fuzz worker as a separate OS process; within one
// process, f.Fuzz iterations run sequentially on one goroutine, so buildCanaryWorld's
// single shared world is never touched by two iterations concurrently -- only by the
// occasional goSafe background goroutine, which is why logBuf needs its own mutex).
//
// Unlike the sibling fuzz harnesses in this package, this world is FILE-backed SQLite
// (not :memory:) -- the RULES require scanning the raw on-disk file, which is only
// meaningful for a real file -- and wires a REAL encryption.Service, so the
// plaintext-at-rest assertion is live, not vacuous.
func buildCanaryWorld(f *testing.F) *canaryWorld {
	f.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		f.Fatalf("i18n: %v", err)
	}

	dbPath := filepath.Join(f.TempDir(), "canary.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		f.Fatalf("migrate: %v", err)
	}
	for _, ix := range []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active ON project_memberships (project_id, user_id) WHERE state <> 'revoked'",
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_legal_holds_active ON legal_holds (released) WHERE released = false",
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_break_glass_active_project_user ON break_glass_activations (project_id, user_id) WHERE state = 'active'",
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active ON users (LOWER(email)) WHERE deleted_at IS NULL AND email <> ''",
	} {
		_ = db.Exec(ix).Error
	}

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, f.TempDir())
	if err := enc.Initialize("canary-fuzz-test-passphrase"); err != nil {
		f.Fatalf("encryption init: %v", err)
	}

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetSecretValueEncryptor(enc)
	if !c.SecretValueEncryptionActive() {
		f.Fatalf("encryption did not activate -- plaintext-at-rest check would be vacuous")
	}
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	ls := store.NewLocalStorage(db)
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

	pA, err := ls.CreateProject(ctx, &models.Project{Name: "canary-proja"})
	if err != nil {
		f.Fatalf("projA: %v", err)
	}
	eA, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: pA.ID})
	if err != nil {
		f.Fatalf("envA: %v", err)
	}
	pB, err := ls.CreateProject(ctx, &models.Project{Name: "canary-projb"})
	if err != nil {
		f.Fatalf("projB: %v", err)
	}
	eB, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: pB.ID})
	if err != nil {
		f.Fatalf("envB: %v", err)
	}

	var perm models.Permission
	if e := db.Where("name = ?", "secrets.read").First(&perm).Error; e != nil {
		perm = models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		if e2 := db.Create(&perm).Error; e2 != nil {
			f.Fatalf("seed permission: %v", e2)
		}
	}
	role := models.Role{Name: "canary-fuzz-reader", NameFolded: "canary-fuzz-reader"}
	if e := db.Create(&role).Error; e != nil {
		f.Fatalf("seed role: %v", e)
	}
	if e := db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error; e != nil {
		f.Fatalf("seed role-permission: %v", e)
	}

	sA, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "sa", Value: []byte("kxcanary-initial-a"), ProjectID: pA.ID, EnvironmentID: eA.ID,
		Type: "password", CreatedBy: "testadmin", OwnerID: admin.ID,
	})
	if err != nil || sA == nil {
		f.Fatalf("secretA: %v", err)
	}
	sB, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "sb", Value: []byte("kxcanary-initial-b"), ProjectID: pB.ID, EnvironmentID: eB.ID,
		Type: "password", CreatedBy: "testadmin", OwnerID: admin.ID,
	})
	if err != nil || sB == nil {
		f.Fatalf("secretB: %v", err)
	}

	mkPrincipal := func(uname, email string) canaryPrincipal {
		u, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: uname, Email: email, Password: apiFuzzPrincipalPassword})
		if err != nil || u == nil {
			f.Fatalf("create user %s: %v", uname, err)
		}
		tok := ""
		if sess, _, lerr := c.Login(ctx, &core.LoginRequest{Username: uname, Password: apiFuzzPrincipalPassword}); lerr == nil && sess != nil {
			tok = sess.SessionToken
		} else {
			f.Logf("principal %s could not obtain a session (%v) -- treated as no-token", uname, lerr)
		}
		return canaryPrincipal{id: u.ID, token: tok}
	}
	principals := []canaryPrincipal{
		mkPrincipal("canary-readera", "canary-readera@x.io"),
		mkPrincipal("canary-readerb", "canary-readerb@x.io"),
		mkPrincipal("canary-outsider", "canary-outsider@x.io"),
	}

	r, err := NewRouter(&config.Config{}, c)
	if err != nil {
		f.Fatalf("router: %v", err)
	}

	grpcSrv, err := keyorixgrpc.NewServer(&config.Config{}, c)
	if err != nil {
		f.Fatalf("grpc server: %v", err)
	}
	lis := bufconn.Listen(1 << 20)
	go func() { _ = grpcSrv.Serve(lis) }()
	f.Cleanup(grpcSrv.Stop)
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		f.Fatalf("grpc dial: %v", err)
	}
	f.Cleanup(func() { _ = conn.Close() })

	lb := &lockedBuffer{}
	prevOut := log.Writer()
	log.SetOutput(lb)
	f.Cleanup(func() { log.SetOutput(prevOut) })

	return &canaryWorld{
		router: r, grpc: pb.NewSecretServiceClient(conn), db: db, dbPath: dbPath, c: c,
		readerRole: role.ID, adminTok: adminSess.SessionToken, adminID: admin.ID,
		projAID: pA.ID, projBID: pB.ID, envAID: eA.ID, envBID: eB.ID,
		secAID: sA.ID, secBID: sB.ID,
		refA: "canary-proja/prod/sa", refB: "canary-projb/prod/sb",
		principals: principals, logBuf: lb,
	}
}

func FuzzCanarySecretLeakage(f *testing.F) {
	w := buildCanaryWorld(f)
	f.Cleanup(i18n.ResetForTesting)

	f.Add([]byte{0, 0, 0, 2, 0, 3, 4, 2, 5, 9, 1, 4})
	f.Add([]byte{2, 0, 0})
	f.Add([]byte{9, 1, 0})
	f.Add([]byte{11, 0, 0, 10, 1, 0})
	f.Add([]byte{})

	var probeSeq atomic.Int64

	f.Fuzz(func(t *testing.T, program []byte) {
		ctx := context.Background()
		opIdx := 0

		// Per-iteration reset: drop fuzz-principal grants (no token-cache flush -- the
		// permission check re-reads grants from the DB every request; flushing writes a
		// negative tombstone that would mask an authorized read -- see the sibling
		// FuzzKeyorixHTTPAPISequence's own comment on this exact trap).
		w.db.Exec("DELETE FROM user_roles WHERE user_id IN (?,?,?)",
			w.principals[0].id, w.principals[1].id, w.principals[2].id)
		canRead := map[uint]map[uint]bool{}
		for _, p := range w.principals {
			canRead[p.id] = map[uint]bool{w.projAID: false, w.projBID: false}
		}

		// Deterministic fixture anchor required by spec: principals[0] may read A, may
		// not read B (never granted); principals[2] stays the "outsider" anchor. The
		// fuzzed grant/revoke ops below can still perturb this further -- canRead tracks
		// truth throughout regardless of who ends up granted what.
		if err := w.c.AssignUserRole(ctx, 0, w.principals[0].id, w.readerRole, core.Scope{ProjectID: w.projAID}, false); err == nil {
			canRead[w.principals[0].id][w.projAID] = true
		}

		// Regenerate both canaries for this iteration, deterministically from the input.
		valA := deriveCanary("A", program)
		valB := deriveCanary("B", program)
		usedCanaries := []string{valA, valB}

		rotate := func(id uint, newVal string) {
			opIdx++
			rec := w.adminReq(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotate", id), fmt.Sprintf(`{"new_value":%q}`, newVal))
			w.scanOp(t, opIdx, "http:rotate-admin-setup", "admin", rec, valA, valB)
		}
		rotate(w.secAID, valA)
		rotate(w.secBID, valB)

		projFor := func(sel byte) uint {
			if sel%2 == 1 {
				return w.projBID
			}
			return w.projAID
		}
		secretFor := func(which byte) (id uint, ref, val, other string, projID uint) {
			if which%2 == 1 {
				return w.secBID, w.refB, valB, valA, w.projBID
			}
			return w.secAID, w.refA, valA, valB, w.projAID
		}
		tokenFor := func(mode, who byte) (label, token string, pid uint) {
			switch mode % 5 {
			case 0:
				return "no-token", "", 0
			case 1:
				return "garbage-token", "garbage-not-a-real-token", 0
			case 2:
				return "admin", w.adminTok, w.adminID
			case 3:
				p := w.principals[int(who)%len(w.principals)]
				return "principal", p.token, p.id
			default:
				p := w.principals[2]
				return "outsider", p.token, p.id
			}
		}
		isAllowed := func(label string, pid, projID uint) bool {
			return label == "admin" || ((label == "principal" || label == "outsider") && canRead[pid][projID])
		}

		readByRef := func(mode, which byte) {
			opIdx++
			_, ref, val, other, projID := secretFor(which)
			label, tok, pid := tokenFor(mode, which)
			allowed := isAllowed(label, pid, projID)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/value?ref="+ref, nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			statusOK := rec.Code == http.StatusOK
			var env valueEnvelope
			if statusOK {
				_ = json.Unmarshal(rec.Body.Bytes(), &env)
			}
			checkValueEndpoint(t, opIdx, "http:ref", label, allowed, statusOK, env.Data.Value, rec.Code, rec.Body.Bytes(), []byte(fmt.Sprintf("%v", rec.Header())), val, other)
			scanZeroTolerance(t, "log", opIdx, label, w.drainLog(), val, other)
		}

		readByID := func(mode, which byte) {
			opIdx++
			id, _, val, other, projID := secretFor(which)
			label, tok, pid := tokenFor(mode, which)
			allowed := isAllowed(label, pid, projID)
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			statusOK := rec.Code == http.StatusOK
			var env valueEnvelope
			if statusOK {
				_ = json.Unmarshal(rec.Body.Bytes(), &env)
			}
			checkValueEndpoint(t, opIdx, "http:id", label, allowed, statusOK, env.Data.Value, rec.Code, rec.Body.Bytes(), []byte(fmt.Sprintf("%v", rec.Header())), val, other)
			scanZeroTolerance(t, "log", opIdx, label, w.drainLog(), val, other)
		}

		readGRPC := func(mode, which byte) {
			opIdx++
			id, _, val, other, projID := secretFor(which)
			label, tok, pid := tokenFor(mode, which)
			allowed := isAllowed(label, pid, projID)
			gctx := context.Background()
			if tok != "" {
				gctx = metadata.NewOutgoingContext(gctx, metadata.Pairs("authorization", "Bearer "+tok))
			}
			var hdr, trl metadata.MD
			resp, err := w.grpc.GetSecretValue(gctx, &pb.GetSecretRequest{Id: uint32(id), IncludeValue: true}, grpc.Header(&hdr), grpc.Trailer(&trl))
			scanZeroTolerance(t, "grpc:metadata", opIdx, label, []byte(fmt.Sprintf("%v %v", hdr, trl)), val, other)
			statusOK := err == nil
			gotVal := ""
			var body []byte
			if statusOK {
				gotVal = resp.GetValue()
			} else {
				body = []byte(err.Error())
			}
			checkValueEndpoint(t, opIdx, "grpc", label, allowed, statusOK, gotVal, 0, body, nil, val, other)
			scanZeroTolerance(t, "log", opIdx, label, w.drainLog(), val, other)
		}

		listSecrets := func(mode, which byte) {
			opIdx++
			_, _, _, _, projID := secretFor(which)
			label, tok, _ := tokenFor(mode, which)
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/?project_id=%d", projID), nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			w.scanOp(t, opIdx, "http:list", label, rec, valA, valB)
		}

		getVersions := func(mode, which byte) {
			opIdx++
			id, _, _, _, _ := secretFor(which)
			label, tok, _ := tokenFor(mode, which)
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions", id), nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			w.scanOp(t, opIdx, "http:versions", label, rec, valA, valB)
		}

		diffVersions := func(mode, which byte) {
			opIdx++
			id, _, _, _, _ := secretFor(which)
			label, tok, _ := tokenFor(mode, which)
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions/1/diff/2", id), nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			w.scanOp(t, opIdx, "http:diff", label, rec, valA, valB)
		}

		accessLogExport := func(mode, which byte) {
			opIdx++
			id, _, _, _, _ := secretFor(which)
			label, tok, _ := tokenFor(mode, which)
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/access-log/export", id), nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			w.scanOp(t, opIdx, "http:access-log-export", label, rec, valA, valB)
		}

		auditSearch := func(mode byte) {
			opIdx++
			label, tok, _ := tokenFor(mode, 0)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/search", nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			w.scanOp(t, opIdx, "http:audit-search", label, rec, valA, valB)
		}

		inventoryCSV := func(mode byte) {
			opIdx++
			label, tok, _ := tokenFor(mode, 0)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/inventory.csv", nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			w.scanOp(t, opIdx, "http:inventory-csv", label, rec, valA, valB)
		}

		auditExportCSV := func(mode byte) {
			opIdx++
			label, tok, _ := tokenFor(mode, 0)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/export.csv", nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			w.scanOp(t, opIdx, "http:audit-export-csv", label, rec, valA, valB)
		}

		// hostileMutate drives rotation/update/delete attempts -- incl. malformed,
		// wrong-content-type, and oversized bodies that BAIT the current canary directly
		// into the request -- against the FIXED fixture secrets A/B, but is restricted to
		// non-admin tokens only. The only grantable role in this fuzzer is read-only
		// (readerRole = secrets.read), so a non-admin attempt against A/B can never
		// actually succeed regardless of grant state -- this keeps A/B's state stable for
		// the later integrity anchors while still exercising the real hostile-input/deny
		// code paths. A surprise success is itself treated as a finding.
		hostileMutate := func(mode, which, kind byte) {
			opIdx++
			id, _, val, other, _ := secretFor(which)
			label, tok, _ := tokenFor(mode, which)
			if label == "admin" {
				label, tok = "no-token", ""
			}
			var req *http.Request
			switch kind % 4 {
			case 0:
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotate", id), strings.NewReader(fmt.Sprintf(`{"new_value":%q}`, val)))
				req.Header.Set("Content-Type", "application/json")
			case 1: // truncated JSON, bait
				req = httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", id), strings.NewReader(fmt.Sprintf(`{"value":"%s`, val)))
				req.Header.Set("Content-Type", "application/json")
			case 2: // wrong content-type
				req = httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", id), strings.NewReader(fmt.Sprintf(`{"value":%q}`, val)))
				req.Header.Set("Content-Type", "text/plain")
			default: // oversized, bait
				oversized := strings.Repeat("A", 200_000) + val
				req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", id), strings.NewReader(oversized))
				req.Header.Set("Content-Type", "application/json")
			}
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			if rec.Code >= 200 && rec.Code < 300 {
				t.Fatalf("op #%d [http:hostile-mutate]: unexpected success (code=%d) for non-admin principal=%s against a fixture secret -- fixture-corruption risk, investigate authz before trusting later anchors", opIdx, rec.Code, label)
			}
			w.scanOp(t, opIdx, "http:hostile-mutate", label, rec, val, other)
		}

		// mutationLifecycleProbe drives a full admin-authenticated create/rotate/update/
		// read/delete/post-delete-read lifecycle against a FRESH throwaway secret (never
		// A/B), each step with its own fresh canary, so the confidentiality oracle gets
		// exercised across the whole CRUD surface without risking the A/B fixtures.
		mutationLifecycleProbe := func() {
			n := probeSeq.Add(1)
			name := fmt.Sprintf("canary-probe-%d", n)
			probeVal := deriveCanary(fmt.Sprintf("probe-%d", n), program)
			usedCanaries = append(usedCanaries, probeVal)
			defer w.db.Exec("DELETE FROM secret_nodes WHERE name = ? AND project_id = ?", name, w.projAID)

			createBody := fmt.Sprintf(`{"name":%q,"value":%q,"project_id":%d,"environment_id":%d,"type":"password"}`, name, probeVal, w.projAID, w.envAID)
			rec := w.adminReq(http.MethodPost, "/api/v1/secrets/", createBody)
			opIdx++
			w.scanOp(t, opIdx, "http:probe-create", "admin", rec, probeVal)
			if rec.Code != http.StatusCreated {
				return
			}
			var node models.SecretNode
			if e := w.db.Where("name = ? AND project_id = ?", name, w.projAID).First(&node).Error; e != nil || node.ID == 0 {
				return
			}
			sid := node.ID

			rotVal := deriveCanary(fmt.Sprintf("probe-%d-rot", n), program)
			usedCanaries = append(usedCanaries, rotVal)
			rec = w.adminReq(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotate", sid), fmt.Sprintf(`{"new_value":%q}`, rotVal))
			opIdx++
			w.scanOp(t, opIdx, "http:probe-rotate", "admin", rec, probeVal, rotVal)

			updVal := deriveCanary(fmt.Sprintf("probe-%d-upd", n), program)
			usedCanaries = append(usedCanaries, updVal)
			rec = w.adminReq(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", sid), fmt.Sprintf(`{"value":%q}`, updVal))
			opIdx++
			w.scanOp(t, opIdx, "http:probe-update", "admin", rec, probeVal, rotVal, updVal)

			rec = w.adminReq(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", sid), "")
			opIdx++
			var env valueEnvelope
			if rec.Code == http.StatusOK {
				_ = json.Unmarshal(rec.Body.Bytes(), &env)
			}
			checkValueEndpoint(t, opIdx, "http:probe-read", "admin", true, rec.Code == http.StatusOK, env.Data.Value, rec.Code, rec.Body.Bytes(), []byte(fmt.Sprintf("%v", rec.Header())), updVal, "")
			scanZeroTolerance(t, "log", opIdx, "admin", w.drainLog(), probeVal, rotVal, updVal)

			rec = w.adminReq(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", sid), "")
			opIdx++
			w.scanOp(t, opIdx, "http:probe-delete", "admin", rec, probeVal, rotVal, updVal)

			rec = w.adminReq(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", sid), "")
			opIdx++
			w.scanOp(t, opIdx, "http:probe-post-delete-read", "admin", rec, probeVal, rotVal, updVal)
		}

		const maxSteps = 40
		for i := 0; i+2 < len(program) && i < maxSteps*3; i += 3 {
			switch program[i] % 12 {
			case 0:
				p := w.principals[int(program[i+1])%len(w.principals)]
				projID := projFor(program[i+2])
				if err := w.c.AssignUserRole(ctx, 0, p.id, w.readerRole, core.Scope{ProjectID: projID}, false); err == nil {
					canRead[p.id][projID] = true
				}
			case 1:
				p := w.principals[int(program[i+1])%len(w.principals)]
				projID := projFor(program[i+2])
				if err := w.c.RemoveUserRole(ctx, 0, p.id, w.readerRole, core.Scope{ProjectID: projID}); err == nil {
					canRead[p.id][projID] = false
				}
			case 2:
				readByRef(program[i+1], program[i+2])
			case 3:
				readByID(program[i+1], program[i+2])
			case 4:
				readGRPC(program[i+1], program[i+2])
			case 5:
				listSecrets(program[i+1], program[i+2])
			case 6:
				getVersions(program[i+1], program[i+2])
			case 7:
				diffVersions(program[i+1], program[i+2])
			case 8:
				accessLogExport(program[i+1], program[i+2])
			case 9:
				hostileMutate(program[i+1], program[i+2], program[i+2])
			case 10:
				auditSearch(program[i+1])
			default: // 11
				if program[i+1]%2 == 0 {
					inventoryCSV(program[i+1])
				} else {
					auditExportCSV(program[i+1])
				}
			}
		}

		// Anchors, every iteration regardless of input.
		readByRef(2, 0) // admin reads A -> integrity/round-trip
		readByRef(4, 1) // outsider anchor reads B -> fail-closed (unless fuzzed grants happened to change canRead)

		opIdx++
		mrec := httptest.NewRecorder()
		w.router.ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		w.scanOp(t, opIdx, "http:metrics", "n/a", mrec, valA, valB)

		opIdx++
		hrec := httptest.NewRecorder()
		w.router.ServeHTTP(hrec, httptest.NewRequest(http.MethodGet, "/health", nil))
		w.scanOp(t, opIdx, "http:health", "n/a", hrec, valA, valB)

		// Gate the heavier full-lifecycle probe to keep average throughput high.
		if len(program) >= 1 && program[0]%2 == 0 {
			mutationLifecycleProbe()
		}

		// Sequence-end: full generic DB scan + raw-file plaintext-at-rest scan. A short
		// best-effort settle absorbs the async goSafe audit write -- see file header.
		time.Sleep(50 * time.Millisecond)
		sqlDB, err := w.db.DB()
		if err != nil {
			t.Fatalf("db scan: get sql.DB: %v", err)
		}
		scanDBGeneric(t, sqlDB, usedCanaries)
		scanRawDBFile(t, w.dbPath, usedCanaries)
	})
}
