package http

// soak_bounded_growth_test.go -- a long-lived SOAK that drives sustained, seeded,
// replayable MIXED operations against an in-process, fully-wired Keyorix server
// (the real chi NewRouter + auth middleware + handlers + core + crypto + storage),
// file-backed SQLite always and PostgreSQL when KEYORIX_TEST_PG_DSN is set, and
// asserts BOUNDED GROWTH of resource/consistency metrics that per-input fuzzers
// cannot see because they rebuild or reset state every iteration.
//
// Six oracle families:
//
//  1. goroutine count          -- runtime.NumGoroutine after quiescing async writers
//  2. open file descriptors    -- entries in /proc/self/fd (Linux; skipped elsewhere)
//  3. heap in use after GC     -- runtime.MemStats.HeapInuse after two GCs. SQLite is
//     FILE-backed on purpose: an in-memory DB keeps its pages in the Go heap, so
//     legitimate audit/version growth would masquerade as a heap leak. On disk, the
//     heap reflects only Go-side state (caches, goroutine stacks, un-pruned maps).
//  4. DB + WAL size per logical record -- on-disk bytes (db+wal+shm on SQLite,
//     pg_total_relation_size on PG) divided by logical rows (audit_events +
//     secret_versions + sessions + projects + environments). Flat if no per-op leak.
//  5. audit-chain integrity    -- VerifyAuditChain is Valid, every stored event is in
//     the verified chain (ChainedEvents+UnchainedEvents == COUNT), and the event
//     count never shrinks and is >= the number of mutations we drove (no skipped or
//     dropped audit write -- the property a RED plant of a missing audit trips).
//  6. latency drift            -- p95 of a FIXED probe read (a stable pre-created
//     secret), late vs early, within a tolerance.
//
// Growth oracles (1-4) fit a least-squares line over the SECOND HALF of the samples
// and fail ONLY when the slope-per-10k-ops exceeds a calibrated threshold AND the
// trend is monotonic (a solid majority of consecutive second-half deltas are
// positive) -- so a one-off spike or oscillation does not fail the run. Thresholds
// are stated as consts below, calibrated from a baseline run.
//
// Deterministic & replayable: the whole operation stream is a math/rand sequence
// seeded by KEYORIX_SOAK_SEED; a given (seed, op-count) reproduces byte-for-byte.
// Duration is env-driven: short by default (CI), long on a soak host.
//
// What these oracles do NOT verify, in brief: schedulers/rotation background loops are NOT wired here (NewRouter+core,
// not server/main's startSchedulers), so their growth is out of scope; the HTTP
// transport uses a real httptest.Server + keep-alive client, so socket FDs ARE
// exercised, but a remote client's connection pool is not; and the audit oracle is
// a LOWER bound (mutations <= events), not an exact 1:1 op<->event mapping, because
// some operations emit zero or several events.

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// --- calibrated growth thresholds (slope per 10,000 operations) ---
//
// Calibrated from a baseline SQLite run (baseline run). A healthy server
// is flat on every axis; these ceilings are set a few multiples above baseline
// noise so a real leak (unclosed goroutine/fd per request, an unbounded map, a WAL
// that never checkpoints) is caught while an idle run stays green.
const (
	// goroutines: must be essentially flat. A per-request goroutine leak is >= 1
	// per op == 10,000 per 10k ops, so even a loose ceiling catches it instantly.
	soakMaxGoroutineSlopePer10k = 8.0
	// file descriptors: likewise flat; a leaked fd per request swamps this.
	soakMaxFDSlopePer10k = 8.0
	// heap in use after GC (bytes per 10k ops). Go-side caches settle; a leaked
	// allocation per op (even 1 KiB) is 10 MiB per 10k ops, far above this. The
	// ceiling is set above the worst warm-up-contaminated SHORT-run second-half
	// slope observed at baseline (~2.5 MiB/10k over 1.5k ops, where warm-up still
	// bleeds into the second half); on a long run the steady-state slope is ~0
	// (baseline run), so this comfortably catches a real per-request leak
	// while staying green on an honest run of any length.
	soakMaxHeapSlopePer10kBytes = 6 << 20 // 6 MiB
	// DB+WAL bytes per logical record (bytes-per-record slope per 10k ops). Flat
	// means storage grows only with legitimate content; a positive slope means
	// each record is costing more over time (orphan rows, un-checkpointed WAL).
	soakMaxDBBytesPerRecordSlopePer10k = 64.0
	// latency drift: late p95 may be at most this multiple of early p95.
	soakLatencyDriftTolerance = 4.0
	// below this early p95 the drift ratio is too noisy to assert (sub-threshold).
	soakLatencyDriftFloor = 30 * time.Microsecond
	// fraction of positive consecutive second-half deltas required to call a
	// growth trend "monotonic" (and therefore a candidate failure).
	soakMonotonicFraction = 0.6
)

type soakConfig struct {
	maxOps      int
	duration    time.Duration
	seed        uint64
	sampleEvery int
	targetLive  int
	probeIters  int
}

// soakConfigFromEnv reads the run shape. Defaults are SHORT so this is a normal CI
// test; a soak host sets KEYORIX_SOAK_OPS / KEYORIX_SOAK_DURATION large.
func soakConfigFromEnv(tb testing.TB) soakConfig {
	tb.Helper()
	cfg := soakConfig{
		maxOps:      1500,
		seed:        0x50A6B0C0DE, // default deterministic seed
		sampleEvery: 150,
		targetLive:  120,
		probeIters:  24,
	}
	if v := os.Getenv("KEYORIX_SOAK_OPS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.maxOps = n
		}
	}
	if v := os.Getenv("KEYORIX_SOAK_DURATION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.duration = d
			// A duration run must not be capped by the default op count.
			if os.Getenv("KEYORIX_SOAK_OPS") == "" {
				cfg.maxOps = 1 << 30
			}
		}
	}
	if v := os.Getenv("KEYORIX_SOAK_SEED"); v != "" {
		if n, err := strconv.ParseUint(v, 0, 64); err == nil {
			cfg.seed = n
		}
	}
	if v := os.Getenv("KEYORIX_SOAK_SAMPLE_EVERY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.sampleEvery = n
		}
	}
	// Keep at least ~10 samples regardless of op count so the regression has data.
	if cfg.maxOps < 1<<29 && cfg.sampleEvery > cfg.maxOps/10 && cfg.maxOps >= 100 {
		cfg.sampleEvery = cfg.maxOps / 10
	}
	return cfg
}

type soakWorld struct {
	backend       string
	srv           *httptest.Server
	client        *http.Client
	db            *gorm.DB
	c             *core.KeyorixCore
	adminTok      string
	projID, envID uint
	probeSecretID uint
	churnUser     string
	churnPass     string
	dbPath        string // SQLite file path; "" for Postgres
	nameSeq       int64  // monotonic, for process-unique secret names
	fuzzLive      []uint // live secret ids persisted across fuzz iterations
}

const soakChurnPassword = "Zq3#Vt8$Lm1@Pw6!"

func buildSoakWorldSQLite(tb testing.TB) *soakWorld {
	tb.Helper()
	dir := tb.TempDir()
	dbPath := filepath.Join(dir, "soak.db")
	// Production SQLite shape: file-backed, WAL, FK on, immediate txlock (see
	// internal/storage/factory_local.go sqliteDSN). File-backed is REQUIRED for the
	// heap oracle -- an in-memory DB would put page growth on the Go heap.
	dsn := "file:" + dbPath + "?_foreign_keys=1&_busy_timeout=30000&_journal_mode=WAL&_txlock=immediate&_synchronous=FULL"
	db := fuzzworld.OpenSQLite(tb, dsn, 1)
	fuzzworld.Bootstrap(tb, db)
	return buildSoakWorld(tb, fuzzworld.BackendSQLite, db, dbPath)
}

func buildSoakWorldPostgres(tb testing.TB) *soakWorld {
	tb.Helper()
	db := fuzzworld.OpenPostgres(tb, "i5soak")
	if db == nil {
		return nil
	}
	fuzzworld.Bootstrap(tb, db)
	return buildSoakWorld(tb, fuzzworld.BackendPostgres, db, "")
}

func buildSoakWorld(tb testing.TB, backend string, db *gorm.DB, dbPath string) *soakWorld {
	tb.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		tb.Fatalf("i18n: %v", err)
	}
	tb.Cleanup(i18n.ResetForTesting)
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		tb.Fatalf("migrate test models (%s): %v", backend, err)
	}

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	// Wire the auth-cache invalidator exactly as server startup does, so a logout's
	// cache eviction is real (not a no-op) -- the churn op relies on it.
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	c.SetBootstrapToken("soak-bootstrap-token")
	if _, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "soakadmin", Email: "soakadmin@example.com",
		Password: "SoakPassword123!", Token: "soak-bootstrap-token",
	}); err != nil {
		tb.Logf("bootstrap (%s): %v (may already be initialised)", backend, err)
	}
	adminSess, _, err := c.Login(ctx, &core.LoginRequest{Username: "soakadmin", Password: "SoakPassword123!"})
	if err != nil {
		tb.Fatalf("admin login (%s): %v", backend, err)
	}
	admin, err := ls.GetUserByUsername(ctx, "soakadmin")
	if err != nil || admin == nil {
		tb.Fatalf("admin lookup (%s): %v", backend, err)
	}

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "soakproj"})
	if err != nil {
		tb.Fatalf("project (%s): %v", backend, err)
	}
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	if err != nil {
		tb.Fatalf("env (%s): %v", backend, err)
	}

	// A stable probe secret: never updated or deleted, so its read latency is a
	// clean fixed-work signal across the whole run.
	probe, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "soak-probe", Value: []byte("PROBE-VALUE-0001"), ProjectID: proj.ID, EnvironmentID: env.ID,
		Type: "password", CreatedBy: "soakadmin", OwnerID: admin.ID,
	})
	if err != nil || probe == nil {
		tb.Fatalf("probe secret (%s): %v", backend, err)
	}

	// A dedicated churn principal for login/logout (token issue/revoke) churn, so
	// the admin session is never disturbed and sessions created here are net-zero
	// in steady state (logout must delete them).
	churnUser := "soakchurn"
	if _, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: churnUser, Email: "soakchurn@example.com", Password: soakChurnPassword}); err != nil {
		tb.Fatalf("churn user (%s): %v", backend, err)
	}

	router, err := NewRouter(&config.Config{}, c)
	if err != nil {
		tb.Fatalf("router (%s): %v", backend, err)
	}
	srv := httptest.NewServer(router)
	tb.Cleanup(srv.Close)

	return &soakWorld{
		backend:       backend,
		srv:           srv,
		client:        &http.Client{Timeout: 30 * time.Second},
		db:            db,
		c:             c,
		adminTok:      adminSess.SessionToken,
		projID:        proj.ID,
		envID:         env.ID,
		probeSecretID: probe.ID,
		churnUser:     churnUser,
		churnPass:     soakChurnPassword,
		dbPath:        dbPath,
	}
}

// do issues one request over the real keep-alive client and fully drains the body
// (so a connection is reused, not leaked -- otherwise the harness itself would trip
// the fd oracle it is trying to measure).
func (w *soakWorld) do(method, path, token, body string) (int, []byte) {
	var rdr *strings.Reader
	var req *http.Request
	var err error
	if body != "" {
		rdr = strings.NewReader(body)
		req, err = http.NewRequest(method, w.srv.URL+path, rdr)
	} else {
		req, err = http.NewRequest(method, w.srv.URL+path, nil)
	}
	if err != nil {
		return 0, nil
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if rerr != nil {
			break
		}
	}
	return resp.StatusCode, buf
}

// envelopeID extracts {"data":{"id":N}} from a create response.
func envelopeID(b []byte) uint {
	var resp struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &resp) == nil {
		return resp.Data.ID
	}
	return 0
}

// envelopeToken extracts {"data":{"token":"..."}} from a login response.
func envelopeToken(b []byte) string {
	var resp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &resp) == nil {
		return resp.Data.Token
	}
	return ""
}

type soakStats struct {
	auditedMutations int
	byKind           map[string]int
}

// step drives exactly one operation, chosen from a weighted mix with create/delete
// steering to hold the live-secret set near cfg.targetLive (so DB-size-per-record
// is a meaningful signal rather than being dominated by an ever-growing live set).
func (w *soakWorld) step(rng *rand.Rand, live *[]uint, stats *soakStats, cfg soakConfig) {
	kind := w.pickKind(rng, len(*live), cfg)
	w.stepKind(kind, rng, live, stats, cfg)
}

// soakOpKinds is the full set of operation kinds, used by the fuzz target to map
// corpus bytes directly onto an operation sequence.
var soakOpKinds = []string{"create", "read", "update", "rotate", "delete", "audit", "churn", "project"}

// stepKind executes a single named operation. rng supplies only per-op value
// jitter and target selection, never the op choice (the caller decides that), so a
// fuzzer can drive a fully deterministic operation SEQUENCE from its input bytes.
func (w *soakWorld) stepKind(kind string, rng *rand.Rand, live *[]uint, stats *soakStats, cfg soakConfig) {
	stats.byKind[kind]++
	switch kind {
	case "create":
		w.nameSeq++
		name := fmt.Sprintf("soak-%016x-%d", cfg.seed, w.nameSeq)
		body := fmt.Sprintf(`{"name":%q,"value":"v-%d","project_id":%d,"environment_id":%d,"type":"password"}`,
			name, w.nameSeq, w.projID, w.envID)
		code, b := w.do(http.MethodPost, "/api/v1/secrets/", w.adminTok, body)
		if code == http.StatusCreated {
			if id := envelopeID(b); id != 0 {
				*live = append(*live, id)
			}
			stats.auditedMutations++
		}
	case "read":
		if len(*live) == 0 {
			return
		}
		id := (*live)[rng.Intn(len(*live))]
		w.do(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), w.adminTok, "")
	case "update":
		if len(*live) == 0 {
			return
		}
		id := (*live)[rng.Intn(len(*live))]
		code, _ := w.do(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", id), w.adminTok,
			fmt.Sprintf(`{"value":"u-%d"}`, rng.Int63()))
		if code == http.StatusOK {
			stats.auditedMutations++
		}
	case "rotate":
		if len(*live) == 0 {
			return
		}
		id := (*live)[rng.Intn(len(*live))]
		code, _ := w.do(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotate", id), w.adminTok,
			fmt.Sprintf(`{"new_value":"r-%d"}`, rng.Int63()))
		if code == http.StatusOK {
			stats.auditedMutations++
		}
	case "delete":
		if len(*live) == 0 {
			return
		}
		i := rng.Intn(len(*live))
		id := (*live)[i]
		code, _ := w.do(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", id), w.adminTok, "")
		if code == http.StatusNoContent {
			*live = slices.Delete(*live, i, i+1)
			stats.auditedMutations++
		}
	case "audit":
		w.do(http.MethodGet, "/api/v1/audit/logs", w.adminTok, "")
	case "churn":
		// token issue + revoke: login the churn user, then log that session out.
		code, b := w.do(http.MethodPost, "/auth/login", "",
			fmt.Sprintf(`{"username":%q,"password":%q}`, w.churnUser, w.churnPass))
		if code == http.StatusOK {
			if tok := envelopeToken(b); tok != "" {
				w.do(http.MethodPost, "/auth/logout", tok, "")
			}
		}
	case "project":
		w.nameSeq++
		// project/env churn: creating a project also seeds default environments.
		w.do(http.MethodPost, "/api/v1/projects",
			w.adminTok, fmt.Sprintf(`{"name":"soakp-%016x-%d"}`, cfg.seed, w.nameSeq))
	}
}

// pickKind returns a weighted operation kind, steering create vs delete to hold the
// live set near target.
func (w *soakWorld) pickKind(rng *rand.Rand, liveCount int, cfg soakConfig) string {
	// Hard steer at the edges so the live set can neither collapse nor explode.
	if liveCount < cfg.targetLive/2 {
		if rng.Intn(100) < 70 {
			return "create"
		}
	}
	if liveCount > cfg.targetLive*3/2 {
		if rng.Intn(100) < 70 {
			return "delete"
		}
	}
	// Weighted mix (sums to 100): read-heavy, with steady write/churn pressure.
	r := rng.Intn(100)
	switch {
	case r < 38:
		return "read"
	case r < 53:
		return "create"
	case r < 68:
		return "delete"
	case r < 80:
		return "update"
	case r < 89:
		return "rotate"
	case r < 95:
		return "churn"
	case r < 99:
		return "audit"
	default:
		return "project"
	}
}

type soakSample struct {
	ops         int
	goroutines  int
	fds         int // -1 when not measurable (non-Linux)
	heapInuse   uint64
	dbBytes     uint64
	logicalRows int64
	auditEvents int64
	probeP95    time.Duration
}

// quiesce waits for transient async workers (the handlers fire audit writes in a
// detached goroutine) to drain, so the goroutine sample reflects steady state.
func (w *soakWorld) quiesce() {
	prev := runtime.NumGoroutine()
	for range 40 {
		time.Sleep(25 * time.Millisecond)
		n := runtime.NumGoroutine()
		if n <= prev {
			prev = n
			// two consecutive non-increasing reads == settled.
			time.Sleep(25 * time.Millisecond)
			if runtime.NumGoroutine() <= n {
				return
			}
		}
		prev = n
	}
}

func (w *soakWorld) capture(tb testing.TB, ops int, probeIters int) soakSample {
	tb.Helper()
	w.quiesce()
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s := soakSample{
		ops:         ops,
		goroutines:  runtime.NumGoroutine(),
		fds:         countOpenFDs(),
		heapInuse:   ms.HeapInuse,
		dbBytes:     w.dbSizeBytes(),
		logicalRows: w.logicalRows(),
		auditEvents: w.countRows("audit_events"),
		probeP95:    w.probeLatencyP95(probeIters),
	}
	return s
}

// countOpenFDs counts entries in /proc/self/fd (Linux). Returns -1 elsewhere.
func countOpenFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

func (w *soakWorld) countRows(table string) int64 {
	var n int64
	// table is a hardcoded literal from this file only, never external input.
	w.db.Table(table).Count(&n)
	return n
}

func (w *soakWorld) logicalRows() int64 {
	return w.countRows("audit_events") +
		w.countRows("secret_versions") +
		w.countRows("sessions") +
		w.countRows("projects") +
		w.countRows("environments")
}

// dbSizeBytes is the on-disk footprint: db+wal+shm file sizes on SQLite,
// pg_total_relation_size summed over the run's schema on Postgres.
func (w *soakWorld) dbSizeBytes() uint64 {
	if w.backend == fuzzworld.BackendPostgres {
		var size int64
		w.db.Raw(`SELECT COALESCE(SUM(pg_total_relation_size(quote_ident(schemaname)||'.'||quote_ident(tablename))),0)
		          FROM pg_tables WHERE schemaname = current_schema()`).Scan(&size)
		if size < 0 {
			return 0
		}
		return uint64(size)
	}
	var total uint64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if fi, err := os.Stat(w.dbPath + suffix); err == nil {
			total += uint64(fi.Size())
		}
	}
	return total
}

// probeLatencyP95 reads the fixed probe secret probeIters times and returns the
// p95 of the per-request wall time.
func (w *soakWorld) probeLatencyP95(iters int) time.Duration {
	if iters <= 0 {
		return 0
	}
	path := fmt.Sprintf("/api/v1/secrets/%d?include_value=true", w.probeSecretID)
	ds := make([]time.Duration, 0, iters)
	for range iters {
		t0 := time.Now()
		w.do(http.MethodGet, path, w.adminTok, "")
		ds = append(ds, time.Since(t0))
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	idx := int(math.Ceil(0.95*float64(len(ds)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(ds) {
		idx = len(ds) - 1
	}
	return ds[idx]
}

// fitSlopePer10k fits y = a + b*x (x = ops) over the second half of samples by
// least squares and returns (slope-per-10k-ops, monotonic). monotonic is true when
// at least soakMonotonicFraction of consecutive second-half deltas are positive.
func fitSlopePer10k(samples []soakSample, get func(soakSample) float64) (per10k float64, monotonic bool) {
	n := len(samples)
	if n < 4 {
		return 0, false
	}
	half := samples[n/2:]
	m := len(half)
	var sx, sy, sxx, sxy float64
	for _, s := range half {
		x := float64(s.ops)
		y := get(s)
		sx += x
		sy += y
		sxx += x * x
		sxy += x * y
	}
	denom := float64(m)*sxx - sx*sx
	if denom == 0 {
		return 0, false
	}
	b := (float64(m)*sxy - sx*sy) / denom
	pos := 0
	for i := 1; i < m; i++ {
		if get(half[i]) > get(half[i-1]) {
			pos++
		}
	}
	monotonic = m > 1 && float64(pos)/float64(m-1) >= soakMonotonicFraction
	return b * 10000.0, monotonic
}

// checkGrowth fails tb only when the second-half slope exceeds threshold AND the
// trend is monotonic. Always logs the slope for the report's growth tables.
func checkGrowth(tb testing.TB, label string, samples []soakSample, threshold float64, get func(soakSample) float64) float64 {
	tb.Helper()
	per10k, monotonic := fitSlopePer10k(samples, get)
	verdict := "OK"
	if per10k > threshold && monotonic {
		verdict = "LEAK"
	}
	tb.Logf("GROWTH %-26s slope=%+.3f/10k-ops threshold=%.3f monotonic=%v -> %s",
		label, per10k, threshold, monotonic, verdict)
	if per10k > threshold && monotonic {
		tb.Errorf("BOUNDED-GROWTH VIOLATION [%s]: slope %+.3f per 10k ops exceeds threshold %.3f and is monotonic over the second half",
			label, per10k, threshold)
	}
	return per10k
}

// verifyAuditChain asserts audit-trail integrity and completeness (oracle 5).
func (w *soakWorld) verifyAuditChain(tb testing.TB, samples []soakSample, auditedMutations int) {
	tb.Helper()
	ctx := context.Background()
	v, err := w.c.VerifyAuditChain(ctx)
	if err != nil {
		tb.Fatalf("AUDIT: VerifyAuditChain error: %v", err)
	}
	if !v.Valid || v.FirstBrokenID != nil {
		tb.Errorf("AUDIT: chain not valid: valid=%v firstBroken=%v reason=%q", v.Valid, v.FirstBrokenID, v.Reason)
	}
	total := w.countRows("audit_events")
	// Every stored event must be accounted for by the walk (chained or the leading
	// legacy run) -- no event may sit outside what VerifyAuditChain inspected.
	if v.ChainedEvents+v.UnchainedEvents != total {
		tb.Errorf("AUDIT: chained(%d)+unchained(%d) != stored(%d) -- events outside the verified chain",
			v.ChainedEvents, v.UnchainedEvents, total)
	}
	if v.ChainedEvents == 0 {
		tb.Errorf("AUDIT: zero chained events -- the hash chain never formed (fixture wiring bug or a real regression)")
	}
	// Completeness: every successful secret mutation (create/update/rotate/delete)
	// must leave exactly its own attributable event. This is asserted against the
	// MUTATION event types specifically, not the total -- comparing the total to
	// the mutation count is too weak (login/churn/audit-read events mask a skipped
	// mutation audit; a RED plant that drops the mutation audit row still left the
	// total above the mutation count, so that check passed while the trail was
	// broken). Mutation audit rows commit in the mutation's own transaction
	// (AUDIT-MUTATION-TX-1), so this read is race-free.
	var mutEvents int64
	w.db.Raw(`SELECT COUNT(*) FROM audit_events WHERE event_type IN (?,?,?,?)`,
		"secret.created", "secret.updated", "secret.rotated", "secret.deleted").Scan(&mutEvents)
	if mutEvents < int64(auditedMutations) {
		tb.Errorf("AUDIT COMPLETENESS: secret-mutation events %d < secret mutations driven %d -- an audit write was skipped",
			mutEvents, auditedMutations)
	}
	// Monotonic non-decrease across samples: audit rows must never vanish mid-run.
	for i := 1; i < len(samples); i++ {
		if samples[i].auditEvents < samples[i-1].auditEvents {
			tb.Errorf("AUDIT: event count went backwards between samples (%d -> %d) at ops %d",
				samples[i-1].auditEvents, samples[i].auditEvents, samples[i].ops)
		}
	}
	tb.Logf("AUDIT ok: valid=%v chained=%d unchained=%d stored=%d mutationEvents=%d mutationsDriven=%d",
		v.Valid, v.ChainedEvents, v.UnchainedEvents, total, mutEvents, auditedMutations)
}

// checkLatencyDrift asserts oracle 6: late p95 within tolerance of early p95.
func checkLatencyDrift(tb testing.TB, samples []soakSample) {
	tb.Helper()
	if len(samples) < 4 {
		return
	}
	q := len(samples) / 4
	if q == 0 {
		q = 1
	}
	early := medianP95(samples[:q])
	late := medianP95(samples[len(samples)-q:])
	tb.Logf("LATENCY probe p95 early=%v late=%v tolerance=%.1fx", early, late, soakLatencyDriftTolerance)
	if early < soakLatencyDriftFloor {
		tb.Logf("LATENCY: early p95 %v below floor %v -- drift ratio too noisy to assert", early, soakLatencyDriftFloor)
		return
	}
	if float64(late) > float64(early)*soakLatencyDriftTolerance {
		tb.Errorf("LATENCY DRIFT: probe p95 grew from %v to %v (> %.1fx)", early, late, soakLatencyDriftTolerance)
	}
}

func medianP95(ss []soakSample) time.Duration {
	ds := make([]time.Duration, 0, len(ss))
	for _, s := range ss {
		ds = append(ds, s.probeP95)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[len(ds)/2]
}

// runSoak drives the op loop with periodic sampling and returns the samples +
// stats. Shared by TestSoakBoundedGrowth and the fuzz target.
func (w *soakWorld) runSoak(tb testing.TB, cfg soakConfig) ([]soakSample, *soakStats) {
	tb.Helper()
	rng := rand.New(rand.NewSource(int64(cfg.seed))) //nolint:gosec // deterministic replay, not security
	stats := &soakStats{byKind: map[string]int{}}
	live := make([]uint, 0, cfg.targetLive*2)

	var samples []soakSample
	// Warm-up sample at op 0 so the first interval's transients are excluded.
	samples = append(samples, w.capture(tb, 0, cfg.probeIters))

	var deadline time.Time
	if cfg.duration > 0 {
		deadline = time.Now().Add(cfg.duration)
	}
	ops := 0
	for ops < cfg.maxOps {
		if !deadline.IsZero() && time.Now().After(deadline) {
			break
		}
		w.step(rng, &live, stats, cfg)
		ops++
		if ops%cfg.sampleEvery == 0 {
			samples = append(samples, w.capture(tb, ops, cfg.probeIters))
		}
	}
	if samples[len(samples)-1].ops != ops {
		samples = append(samples, w.capture(tb, ops, cfg.probeIters))
	}
	return samples, stats
}

// logGrowthTable prints the full per-sample table.
func logGrowthTable(tb testing.TB, backend string, samples []soakSample, stats *soakStats) {
	tb.Helper()
	tb.Logf("=== SOAK growth table (%s) === ops=%d  op-mix=%v", backend, samples[len(samples)-1].ops, stats.byKind)
	tb.Logf("%8s %6s %5s %12s %12s %8s %12s %10s", "ops", "gor", "fds", "heapInuse", "dbBytes", "rows", "b/rec", "probeP95")
	for _, s := range samples {
		var bpr float64
		if s.logicalRows > 0 {
			bpr = float64(s.dbBytes) / float64(s.logicalRows)
		}
		tb.Logf("%8d %6d %5d %12d %12d %8d %12.1f %10v",
			s.ops, s.goroutines, s.fds, s.heapInuse, s.dbBytes, s.logicalRows, bpr, s.probeP95)
	}
}

// runAndAssert runs one backend's soak and applies every oracle.
func runAndAssert(tb testing.TB, w *soakWorld, cfg soakConfig) {
	tb.Helper()
	samples, stats := w.runSoak(tb, cfg)
	logGrowthTable(tb, w.backend, samples, stats)

	checkGrowth(tb, "goroutines/"+w.backend, samples, soakMaxGoroutineSlopePer10k,
		func(s soakSample) float64 { return float64(s.goroutines) })
	if samples[0].fds >= 0 {
		checkGrowth(tb, "open-fds/"+w.backend, samples, soakMaxFDSlopePer10k,
			func(s soakSample) float64 { return float64(s.fds) })
	} else {
		tb.Logf("GROWTH open-fds/%s: not measurable on this platform, skipped", w.backend)
	}
	checkGrowth(tb, "heap-inuse/"+w.backend, samples, soakMaxHeapSlopePer10kBytes,
		func(s soakSample) float64 { return float64(s.heapInuse) })
	checkGrowth(tb, "db-bytes-per-record/"+w.backend, samples, soakMaxDBBytesPerRecordSlopePer10k,
		func(s soakSample) float64 {
			if s.logicalRows == 0 {
				return 0
			}
			return float64(s.dbBytes) / float64(s.logicalRows)
		})
	w.verifyAuditChain(tb, samples, stats.auditedMutations)
	checkLatencyDrift(tb, samples)
}

func TestSoakBoundedGrowth(t *testing.T) {
	if testing.Short() {
		t.Skip("soak: skipped under -short")
	}
	cfg := soakConfigFromEnv(t)
	t.Logf("SOAK config: maxOps=%d duration=%v seed=0x%x sampleEvery=%d targetLive=%d",
		cfg.maxOps, cfg.duration, cfg.seed, cfg.sampleEvery, cfg.targetLive)

	t.Run("sqlite", func(t *testing.T) {
		runAndAssert(t, buildSoakWorldSQLite(t), cfg)
	})
	t.Run("postgres", func(t *testing.T) {
		w := buildSoakWorldPostgres(t)
		if w == nil {
			t.Skip("KEYORIX_TEST_PG_DSN not set -- Postgres soak skipped")
		}
		runAndAssert(t, w, cfg)
	})
}
