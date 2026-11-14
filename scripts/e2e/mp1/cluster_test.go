//go:build e2e

// Package mp1 drives REAL multi-process races against ONE PostgreSQL database
// (task MP1 / backlog I1). It boots N separate keyorix-server OS processes —
// the ADR-039 HA shape: stateless replicas, no leader election, one shared
// Postgres holding sessions, secrets, the audit chain and the advisory locks —
// and drives them concurrently through the real REST API from a Go fuzz
// harness (cluster_fuzz_test.go) and a set of seeded oracle tests
// (oracles_test.go).
//
// This is distinct from the in-process cross-replica harnesses already in the
// tree (FuzzCrossReplicaInvariants, FuzzCrossReplicaOps, the schedule-race
// fuzzer): those run "replicas" as goroutines inside ONE process sharing one
// Storage object and one address space. Here every replica is a real,
// separately-scheduled OS process with its own connection pool, its own
// per-process caches, and its own log file — the only shared state is the
// database, exactly as a load-balanced HA deployment has it.
//
// Requires the `e2e` build tag (it shells out to `go build`, spawns real
// server subprocesses and binds real TCP ports) and a PostgreSQL DSN in
// KEYORIX_TEST_PG_DSN (skips otherwise). It reuses scripts/e2e/harness for the
// build/boot/bootstrap/port mechanics but manages the cluster's lifetime
// itself (manual temp dirs, process kills in TestMain) so the servers survive
// across every fuzz iteration rather than being torn down by any one
// iteration's t.Cleanup.
package mp1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// masterPassword is the KEK input every replica shares (ADR-038/039): the KEK
// is PBKDF2(master password, on-disk salt), so two replicas that did not share
// both could not unwrap the same DEK and could not read each other's
// ciphertext. harness.StartServer derives the identical string for the
// "postgres" backend; this cluster mirrors it exactly.
const masterPassword = "e2e-smoke-master-password-postgres"

// bootstrapToken is the one-shot token POST /system/init consumes to claim the
// first admin. 32+ chars so it clears the server's boot-time strength floor.
const bootstrapToken = "mp1-multiproc-bootstrap-token-0123456789"

// dbPasswordFallback is used only when the DSN carries no password and
// KEYORIX_TEST_PG_PASSWORD is unset.
const dbPasswordFallback = "keyorix-e2e-smoke"

// pgTarget is the parsed KEYORIX_TEST_PG_DSN, enough to render the server's
// storage.database block and to open an admin connection for CREATE DATABASE.
type pgTarget struct {
	Host, Port, DBName, User, Password, SSLMode string
	raw                                         string
}

// parsePGURL parses the postgres:// URL form KEYORIX_TEST_PG_DSN takes in this
// environment. Kept deliberately small (URL form only): the scripts/e2e
// package's own parseLibpqDSN handles the key=value form but not a URL, and
// this session's DSN is a URL.
func parsePGURL(t *testing.T, dsn string) pgTarget {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("KEYORIX_TEST_PG_DSN is not a valid URL: %v", err)
	}
	pw, _ := u.User.Password()
	tg := pgTarget{
		Host:     u.Hostname(),
		Port:     u.Port(),
		DBName:   strings.TrimPrefix(u.Path, "/"),
		User:     u.User.Username(),
		Password: pw,
		SSLMode:  u.Query().Get("sslmode"),
		raw:      dsn,
	}
	if tg.Port == "" {
		tg.Port = "5432"
	}
	if tg.SSLMode == "" {
		tg.SSLMode = "disable"
	}
	return tg
}

// withDBName returns the DSN URL with the database path swapped for name.
func (tg pgTarget) withDBName(name string) string {
	u, _ := url.Parse(tg.raw)
	u.Path = "/" + name
	return u.String()
}

// storageYAML renders the storage.database.* block (password travels in
// KEYORIX_DB_PASSWORD, never the file — this repo's convention).
func (tg pgTarget) storageYAML(dbName string) string {
	return fmt.Sprintf("    host: %s\n    port: \"%s\"\n    name: %s\n    user: %s\n    ssl_mode: %s\n",
		tg.Host, tg.Port, dbName, tg.User, tg.SSLMode)
}

// mp1DBCounter makes every created database name unique within this process.
var mp1DBCounter atomic.Int64

// createIsolatedDB creates a fresh, empty `mp1_<pid>_<n>` database on tg and
// returns its DSN. The DROP is registered on the package teardown list, not on
// t.Cleanup, so the database outlives the fuzz iteration that happened to
// create the cluster. Only `mp1_*` databases are ever created or dropped.
func createIsolatedDB(t *testing.T, tg pgTarget) (dsn, name string) {
	t.Helper()
	name = fmt.Sprintf("mp1_%d_%d", os.Getpid(), mp1DBCounter.Add(1))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, tg.raw)
	if err != nil {
		t.Fatalf("connect to %s to create %s: %v", tg.Host, name, err)
	}
	defer conn.Close(ctx) //nolint:errcheck
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("CREATE DATABASE %s: %v", name, err)
	}
	registerTeardown(func() {
		c, err := pgx.Connect(context.Background(), tg.raw)
		if err != nil {
			return
		}
		defer c.Close(context.Background()) //nolint:errcheck
		_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	return tg.withDBName(name), name
}

// Cluster is a set of real keyorix-server processes sharing one Postgres DB.
type Cluster struct {
	ServerBin  string
	DSN        string
	DBName     string
	Target     pgTarget
	DBPassword string
	Replicas   []*harness.Server
	AdminToken string
	ProjID     int
	EnvID      int
	ProjName   string
}

// Replica returns replica i (wrapping, so a fuzz byte can address any).
func (c *Cluster) Replica(i int) *harness.Server { return c.Replicas[i%len(c.Replicas)] }

// configExtra builds the storage: block spliced into each replica's generated
// config. anomalySchedule (e.g. "2s") drives the scheduler-singleton oracle
// without waiting out the 1h default; pass "" to leave anomaly at its default.
func (c *Cluster) configExtra(anomalySchedule string) string {
	block := fmt.Sprintf("storage:\n  type: postgres\n  database:\n%s  encryption:\n    enabled: true\n    dek_path: keys/dek.key\n    salt_path: keys/kek.salt\n",
		c.Target.storageYAML(c.DBName))
	if anomalySchedule != "" {
		block += fmt.Sprintf("anomaly_alerts:\n  schedule: %q\n", anomalySchedule)
	}
	return block
}

// spliceStorage replaces admin-init's generated storage: block (sqlite
// default) with configExtra — the same splice harness.StartServer performs
// internally but does not export.
func spliceStorage(t *testing.T, dir, configExtra string) {
	t.Helper()
	path := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(path) //nolint:gosec // fixed temp path
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	text := string(raw)
	start := strings.Index(text, "storage:")
	if start < 0 {
		t.Fatalf("generated config has no storage: block:\n%s", text)
	}
	rest := text[start:]
	end := strings.Index(rest, "\nsecrets:")
	if end < 0 {
		t.Fatalf("generated config's storage: block has no following secrets: key:\n%s", text)
	}
	newText := text[:start] + configExtra + rest[end+1:]
	if err := os.WriteFile(path, []byte(newText), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
}

// disableMFA flips the shipped require_mfa: true default to false in the
// generated config. Stated reason: this harness exercises concurrent
// secret/PAT/session races across replicas; MFA enrolment is orthogonal to
// every oracle here and would add a TOTP step to every login. (harness.StartServer
// offers the same opt-out via DBBackend.NoMFAReason; this cluster boots its
// replicas manually so it performs the edit itself.)
func disableMFA(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(path) //nolint:gosec // fixed temp path
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	const on, off = "\n  require_mfa: true\n", "\n  require_mfa: false\n"
	if !strings.Contains(string(raw), on) {
		t.Fatalf("generated config has no %q line (template changed?)", strings.TrimSpace(on))
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), on, off, 1)), 0o600); err != nil {
		t.Fatalf("disable require_mfa: %v", err)
	}
}

// mkReplicaDir makes a persistent temp dir (NOT t.TempDir — that is removed at
// the end of the iteration that created the cluster, which would pull the
// config/keys/log out from under a still-running server). Removed by teardown.
func mkReplicaDir(t *testing.T, label string) string {
	t.Helper()
	dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "mp1-"+label+"-")
	if err != nil {
		t.Fatalf("mkdir replica dir: %v", err)
	}
	registerTeardown(func() { _ = os.RemoveAll(dir) })
	return dir
}

// StartCluster boots n real server processes against one fresh mp1_ database.
// Replica 0 runs the full fresh-install sequence (admin init -> splice config
// -> admin encryption init -> admin migrate -> boot -> POST /system/init);
// replicas 1..n-1 copy replica 0's key material, splice the same config, pick
// their own port, and just boot (no second encryption init, no re-bootstrap,
// no migrate — the DB is already migrated and `admin migrate` would conflict
// with replica 0's live presence lock). anomalySchedule is passed through to
// every replica's config.
func StartCluster(t *testing.T, n int, anomalySchedule string) *Cluster {
	t.Helper()
	if n < 1 {
		t.Fatalf("StartCluster: n must be >= 1, got %d", n)
	}
	serverBin, _ := harness.BuildBinaries(t)

	base := os.Getenv("KEYORIX_TEST_PG_DSN")
	tg := parsePGURL(t, base)
	dbPassword := os.Getenv("KEYORIX_TEST_PG_PASSWORD")
	if dbPassword == "" {
		dbPassword = tg.Password
	}
	if dbPassword == "" {
		dbPassword = dbPasswordFallback
	}

	dsn, dbName := createIsolatedDB(t, tg)
	c := &Cluster{
		ServerBin: serverBin, DSN: dsn, DBName: dbName, Target: tg, DBPassword: dbPassword,
	}

	env := append(harness.BaseServerEnv(""), "KEYORIX_MASTER_PASSWORD="+masterPassword,
		"KEYORIX_DB_PASSWORD="+dbPassword)
	// BaseServerEnv("") still returns PATH/TMPDIR; HOME is set per-replica below.

	// ── Replica 0: full fresh install ──────────────────────────────────────
	dir0 := mkReplicaDir(t, "r0")
	env0 := replicaEnv(env, dir0)
	runAdmin(t, serverBin, dir0, env0, "init", "--dev", "--config", "./keyorix.yaml")
	disableMFA(t, dir0)
	spliceStorage(t, dir0, c.configExtra(anomalySchedule))
	runAdmin(t, serverBin, dir0, env0, "encryption", "init", "--config", "./keyorix.yaml")
	runAdmin(t, serverBin, dir0, env0, "migrate", "--config", "./keyorix.yaml")
	port0 := harness.FreeTCPPort(t)
	harness.RewritePort(t, dir0, port0)
	s0 := harness.BootAndBootstrap(t, serverBin, dir0, env0, "./keyorix.yaml", port0,
		bootstrapToken, "mp1admin", "mp1admin@example.invalid", harness.BootstrapAdminPassword)
	c.Replicas = append(c.Replicas, s0)

	// ── Replicas 1..n-1: share replica 0's keys, boot only ─────────────────
	for i := 1; i < n; i++ {
		diri := mkReplicaDir(t, "r"+strconv.Itoa(i))
		envi := replicaEnv(env, diri)
		runAdmin(t, serverBin, diri, envi, "init", "--dev", "--config", "./keyorix.yaml")
		disableMFA(t, diri)
		spliceStorage(t, diri, c.configExtra(anomalySchedule))
		copyKeys(t, dir0, diri)
		porti := harness.FreeTCPPort(t)
		harness.RewritePort(t, diri, porti)
		si := &harness.Server{
			T: t, Dir: diri, ConfigPath: "./keyorix.yaml",
			BaseURL: "http://127.0.0.1:" + porti, Binary: serverBin, Env: envi,
			LogPath: filepath.Join(diri, "server.log"),
			Backend: harness.DBBackend{Name: "postgres"},
		}
		serverEnv := append(append([]string{}, envi...), "KEYORIX_CONFIG_PATH=./keyorix.yaml")
		harness.StartBackgroundProcess(t, si, serverEnv)
		harness.WaitHealthy(t, si)
		c.Replicas = append(c.Replicas, si)
	}

	// Record all replicas on the teardown kill-list immediately, so even a
	// later fatal in this function leaves nothing running.
	for _, s := range c.Replicas {
		registerTeardown(s.Close)
	}

	c.AdminToken = c.login(t, c.Replica(0), "mp1admin", harness.BootstrapAdminPassword)
	c.setupProject(t)
	return c
}

// replicaEnv returns env with HOME set to this replica's own dir (isolated
// state; the key-file permission check requires 0600 files owned by the
// server uid under a private HOME).
func replicaEnv(env []string, dir string) []string {
	out := append([]string{}, env...)
	out = append(out, "HOME="+dir)
	return out
}

func runAdmin(t *testing.T, bin, dir string, env []string, args ...string) {
	t.Helper()
	out, err := harness.RunAdminCmd(bin, dir, env, args...)
	if err != nil {
		t.Fatalf("keyorix-server admin %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func copyKeys(t *testing.T, srcDir, dstDir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dstDir, "keys"), 0o700); err != nil {
		t.Fatalf("make keys dir: %v", err)
	}
	for _, name := range []string{"dek.key", "kek.salt"} {
		raw, err := os.ReadFile(filepath.Join(srcDir, "keys", name)) //nolint:gosec // fixed temp path
		if err != nil {
			t.Fatalf("read replica 0 %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dstDir, "keys", name), raw, 0o600); err != nil {
			t.Fatalf("write replica key %s: %v", name, err)
		}
	}
}

// setupProject creates one shared project + resolves an environment, used by
// the secret oracles. Isolation between fuzz iterations is by secret name, not
// by project, so one project suffices.
func (c *Cluster) setupProject(t *testing.T) {
	t.Helper()
	c.ProjName = "mp1-shared"
	env := c.rest(t, c.Replica(0), http.MethodPost, "/api/v1/projects",
		map[string]any{"name": c.ProjName})
	if env.StatusCode != http.StatusCreated && env.StatusCode != http.StatusOK {
		t.Fatalf("create project: HTTP %d: %s", env.StatusCode, env.Raw)
	}
	c.ProjID = c.resolveProjectID(t, c.ProjName)
	c.EnvID = c.firstEnvID(t, c.ProjID)
}

// ── REST helpers (self-contained; the journeys helpers live in a package that
// does not compile here because of an SDK module the offline cache lacks) ────

type restEnvelope struct {
	StatusCode int
	Data       json.RawMessage `json:"data"`
	Message    string          `json:"message"`
	Raw        []byte
}

func (c *Cluster) rest(t *testing.T, s *harness.Server, method, path string, body any) restEnvelope {
	t.Helper()
	return c.restTok(t, s, c.AdminToken, method, path, body)
}

func (c *Cluster) restTok(t *testing.T, s *harness.Server, token, method, path string, body any) restEnvelope {
	t.Helper()
	env, err := c.restTokErr(s, token, method, path, body)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return env
}

// restTokErr is the non-fatal form used in the concurrent fuzz bursts, where a
// transport error on one goroutine must not kill the whole test.
func (c *Cluster) restTokErr(s *harness.Server, token, method, path string, body any) (restEnvelope, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return restEnvelope{}, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, s.BaseURL+path, reader)
	if err != nil {
		return restEnvelope{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return restEnvelope{}, err
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return restEnvelope{}, err
	}
	env := restEnvelope{StatusCode: resp.StatusCode, Raw: raw}
	_ = json.Unmarshal(raw, &env)
	return env, nil
}

func (c *Cluster) login(t *testing.T, s *harness.Server, username, password string) string {
	t.Helper()
	env := c.restTok(t, s, "", http.MethodPost, "/auth/login",
		map[string]string{"username": username, "password": password})
	if env.StatusCode != http.StatusOK {
		t.Fatalf("login %s: HTTP %d: %s", username, env.StatusCode, env.Raw)
	}
	var d struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(env.Data, &d); err != nil || d.Token == "" {
		t.Fatalf("login %s: no token in %s", username, env.Raw)
	}
	return d.Token
}

func (c *Cluster) resolveProjectID(t *testing.T, name string) int {
	t.Helper()
	env := c.rest(t, c.Replica(0), http.MethodGet, "/api/v1/projects", nil)
	var d struct {
		Projects []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(env.Data, &d); err != nil {
		t.Fatalf("decode projects: %v\n%s", err, env.Data)
	}
	for _, p := range d.Projects {
		if p.Name == name {
			return p.ID
		}
	}
	t.Fatalf("project %q not found: %s", name, env.Data)
	return 0
}

func (c *Cluster) firstEnvID(t *testing.T, projID int) int {
	t.Helper()
	env := c.rest(t, c.Replica(0), http.MethodGet,
		fmt.Sprintf("/api/v1/projects/%d/environments", projID), nil)
	var d struct {
		Environments []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"environments"`
	}
	if err := json.Unmarshal(env.Data, &d); err != nil {
		t.Fatalf("decode environments: %v\n%s", err, env.Data)
	}
	if len(d.Environments) == 0 {
		// No default env — create one.
		ce := c.rest(t, c.Replica(0), http.MethodPost,
			fmt.Sprintf("/api/v1/projects/%d/environments", projID),
			map[string]any{"name": "development"})
		if ce.StatusCode != http.StatusCreated && ce.StatusCode != http.StatusOK {
			t.Fatalf("create environment: HTTP %d: %s", ce.StatusCode, ce.Raw)
		}
		return c.firstEnvID(t, projID)
	}
	return d.Environments[0].ID
}

// ── package teardown (TestMain) ────────────────────────────────────────────

var (
	teardownMu sync.Mutex
	teardowns  []func()
)

func registerTeardown(fn func()) {
	teardownMu.Lock()
	teardowns = append(teardowns, fn)
	teardownMu.Unlock()
}

// runTeardowns runs every registered teardown in LIFO order (kill servers
// before dropping their database and removing their dirs).
func runTeardowns() {
	teardownMu.Lock()
	fns := teardowns
	teardowns = nil
	teardownMu.Unlock()
	for _, fn := range slices.Backward(fns) {
		fn()
	}
}

// exitCmd runs a command for its exit behaviour; used only by tests.
var _ = exec.Command

// ── Pure oracle decision functions (shared by the live oracles and the
// red-proof tests, so both exercise the SAME logic) ─────────────────────────

// allEqual reports whether every string in vals is identical (cross-replica
// convergence). An empty or single-element slice is trivially converged.
func allEqual(vals []string) bool {
	for i := 1; i < len(vals); i++ {
		if vals[i] != vals[0] {
			return false
		}
	}
	return true
}

// serialEquivViolation reports whether final is a value NO successful write
// set — the checkable necessary condition for serial equivalence of a single
// register: the surviving value must come from some operation that returned
// success, never a torn/phantom/failed-write value.
func serialEquivViolation(final string, success map[string]struct{}) bool {
	_, ok := success[final]
	return !ok
}

// scanLogForSecrets returns every canary value (length >= minLen) that appears
// verbatim in logText. A non-empty result is a confidentiality leak.
func scanLogForSecrets(logText string, values []string, minLen int) []string {
	var hits []string
	for _, v := range values {
		if len(v) >= minLen && strings.Contains(logText, v) {
			hits = append(hits, v)
		}
	}
	return hits
}
