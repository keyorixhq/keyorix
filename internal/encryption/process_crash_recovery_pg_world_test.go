//go:build !windows

package encryption_test

// process_crash_recovery_pg_world_test.go builds one real PostgreSQL install for
// FuzzProcessCrashRecoveryPG: key files and a keyorix.yaml on disk, and a
// database named w5_* per run on the server named by KEYORIX_TEST_PG_DSN. Every
// database it creates is dropped by the test that created it. Nothing here
// touches a database whose name it did not generate.

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"gopkg.in/yaml.v3"
)

const (
	envPCrashPGDSN      = "KEYORIX_TEST_PG_DSN"
	pcrashPGDBPrefix    = "w5_"
	pcrashPGQuiesceWait = 60 * time.Second
	// A migrate or restore makes hundreds of round trips, each 170 ms or more
	// through a remote tunnel, so the SQLite leg's 3-minute limit is too short.
	pcrashPGChildDeadline = 8 * time.Minute
)

var pcrashPGNameOK = regexp.MustCompile(`^w5_[a-z0-9_]+$`)

// pcrashPGServer is the connection details of KEYORIX_TEST_PG_DSN and an admin
// handle used only for CREATE/DROP DATABASE of generated names and for reading
// pg_stat_activity about them.
type pcrashPGServer struct {
	host, port, user, password string
	admin                      *sql.DB
}

var pcrashPGSeq atomic.Int64

func newPCrashPGServer(tb testing.TB) *pcrashPGServer {
	tb.Helper()
	raw := os.Getenv(envPCrashPGDSN)
	if raw == "" {
		tb.Skip(envPCrashPGDSN + " not set: the PostgreSQL crash-recovery leg needs a real server")
	}
	cc, err := pgx.ParseConfig(raw)
	if err != nil {
		tb.Fatalf("parse %s (value not shown): %T", envPCrashPGDSN, err)
	}
	if cc.TLSConfig != nil {
		tb.Fatalf("%s uses TLS; the crash seam needs a plaintext connection (sslmode=disable)", envPCrashPGDSN)
	}
	admin := stdlib.OpenDB(*cc)
	admin.SetMaxOpenConns(4)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		_ = admin.Close()
		tb.Fatalf("PostgreSQL at the configured DSN is unreachable: %v", pcrashPGScrub(err, cc.Password))
	}
	began := time.Now()
	for range 10 {
		var one int
		if err := admin.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
			tb.Fatalf("round-trip probe: %v", pcrashPGScrub(err, cc.Password))
		}
	}
	tb.Logf("PostgreSQL round trip: %s average", (time.Since(began) / 10).Round(100*time.Microsecond))
	s := &pcrashPGServer{host: cc.Host, port: strconv.Itoa(int(cc.Port)), user: cc.User, password: cc.Password, admin: admin}
	tb.Cleanup(func() { _ = admin.Close() })
	return s
}

// pcrashPGScrub removes the password from an error so a log can never carry it.
func pcrashPGScrub(err error, password string) string {
	msg := err.Error()
	if password != "" {
		msg = strings.ReplaceAll(msg, password, "<password>")
	}
	return msg
}

func (s *pcrashPGServer) target() string { return net.JoinHostPort(s.host, s.port) }

func pcrashPGQuote(v string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `'`, `\'`) + "'"
}

// dsn is a keyword DSN that starts with the real address; the child rewrites
// exactly that prefix to its proxy (pcrashPGPointConfigAt).
func (s *pcrashPGServer) dsn(dbName string) string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		s.host, s.port, pcrashPGQuote(s.user), pcrashPGQuote(s.password), dbName)
}

func pcrashPGName(kind string) string {
	return fmt.Sprintf("%s%s_%d_%d", pcrashPGDBPrefix, kind, os.Getpid(), pcrashPGSeq.Add(1))
}

func (s *pcrashPGServer) exec(ctx context.Context, stmt string) error {
	_, err := s.admin.ExecContext(ctx, stmt)
	return err
}

func (s *pcrashPGServer) createDB(ctx context.Context, name, template string) error {
	if !pcrashPGNameOK.MatchString(name) {
		return fmt.Errorf("refusing to create database %q: not a generated w5_ name", name)
	}
	stmt := "CREATE DATABASE " + name + " TEMPLATE template0"
	if template != "" {
		if !pcrashPGNameOK.MatchString(template) {
			return fmt.Errorf("refusing template %q: not a generated w5_ name", template)
		}
		stmt = "CREATE DATABASE " + name + " TEMPLATE " + template
	}
	return s.exec(ctx, stmt)
}

func (s *pcrashPGServer) dropDB(ctx context.Context, name string) error {
	if !pcrashPGNameOK.MatchString(name) {
		return fmt.Errorf("refusing to drop database %q: not a generated w5_ name", name)
	}
	return s.exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
}

// quiesce waits until no backend serves name: a killed client's transaction has
// been rolled back and its session locks released. That is the server state a
// restart meets; a restart that runs first waits on or fails on those locks,
// which is a matter of timing and not of the state being checked.
func (s *pcrashPGServer) quiesce(ctx context.Context, name string) error {
	deadline := time.Now().Add(pcrashPGQuiesceWait)
	for {
		var n int
		err := s.admin.QueryRowContext(ctx, "SELECT count(*) FROM pg_stat_activity WHERE datname = $1", name).Scan(&n)
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%d backend(s) still connected to %s after %s", n, name, pcrashPGQuiesceWait)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// pcrashPGInst is one install: its directory, database and canonical config.
type pcrashPGInst struct {
	dir  string
	db   string
	yaml []byte
}

func (i *pcrashPGInst) restoreYAML() error {
	return os.WriteFile(filepath.Join(i.dir, "keyorix.yaml"), i.yaml, 0o600)
}

// pcrashPGCalibration is a clean run of an operation: seams, the labels in
// order, and the after state's roles and decisions.
type pcrashPGCalibration struct {
	seams int64
	trace []string
	ref   *pcrashModel
}

// pcrashPGWorld is the template install. dir has keys and config; templateDB
// holds the seeded data. freshDir is keys and config with no schema.
type pcrashPGWorld struct {
	*pcrashWorld
	srv        *pcrashPGServer
	templateDB string
	yamlText   string // canonical yaml, with the template database name
	freshDir   string

	calMu   sync.Mutex
	pgCal   map[string]pcrashPGCalibration
	pgMig   *pcrashPGCalibration
	pgMigDB string
	// prepared is the observed template state, kept so an exec with stateRaw 0
	// spends no extra 100-second reopen building it (see prepareCached).
	prepared  *pcrashExecState
	buildStep int
}

const pcrashPGBuildSteps = 6

// run spawns a PG child; it mirrors runPCrashChild with the seam's own environment.
func (w *pcrashPGWorld) run(dir, pass, action string, args []string, killAt int64, mode, split string, trace bool) (pcrashPGRun, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pcrashPGChildDeadline)
	defer cancel()
	bin, err := os.Executable()
	if err != nil {
		return pcrashPGRun{}, err
	}
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return pcrashPGRun{}, err
	}
	resultFile, err := os.CreateTemp("", "pcrash-pg-result-*")
	if err != nil {
		return pcrashPGRun{}, err
	}
	_ = resultFile.Close()
	defer func() { _ = os.Remove(resultFile.Name()) }()
	cmd := exec.CommandContext(ctx, bin, "-test.run=^TestProcessCrashPGChild$") //nolint:gosec // this test binary, re-executed
	cmd.Dir = dir
	cmd.WaitDelay = 5 * time.Second
	if mode == "" {
		mode = pcrashPGModeKill
	}
	cmd.Env = []string{
		"HOME=" + dir,
		"PATH=/usr/bin:/bin",
		"TMPDIR=" + os.TempDir(),
		envPCrashPass + "=" + pass,
		envPCrashPGChild + "=" + action,
		envPCrashPGKillAt + "=" + strconv.FormatInt(killAt, 10),
		envPCrashPGMode + "=" + mode,
		envPCrashPGResult + "=" + resultFile.Name(),
		envPCrashPGArgs + "=" + string(argsJSON),
		envPCrashPGTarget + "=" + w.srv.target(),
	}
	if trace {
		cmd.Env = append(cmd.Env, envPCrashPGTrace+"=1")
	}
	if split != "" {
		cmd.Env = append(cmd.Env, envPCrashPGSplit+"="+split)
	}
	out, runErr := cmd.CombinedOutput()
	r := pcrashPGRun{pcrashChildRun: pcrashChildRun{output: string(out)}}
	if ctx.Err() != nil {
		return r, fmt.Errorf("child %s passed its deadline: %s", action, pcrashTail(pcrashPGScrub(errors.New(string(out)), w.srv.password)))
	}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
		r.killed = ws.Signaled() && ws.Signal() == syscall.SIGKILL
		r.exit = ws.ExitStatus()
	}
	if _, isExit := errors.AsType[*exec.ExitError](runErr); runErr != nil && !isExit {
		return r, fmt.Errorf("start child: %w", runErr)
	}
	if b, err := os.ReadFile(resultFile.Name()); err == nil && len(b) > 0 {
		var res pcrashPGChildResult
		if json.Unmarshal(b, &res) == nil {
			r.seams, r.label, r.cut, r.trace = res.Seams, res.Label, res.Cut, res.Trace
		}
	}
	return r, nil
}

// pcrashPGRun is a PG child's outcome: a pcrashChildRun plus the cut flag and
// the seam labels of a traced run.
type pcrashPGRun struct {
	pcrashChildRun
	cut   bool
	trace []string
}

// buildPCrashPGWorld makes the template install with the real admin commands,
// then quiesces the template database so CREATE DATABASE ... TEMPLATE can copy it.
func buildPCrashPGWorld(tb testing.TB) *pcrashPGWorld {
	tb.Helper()
	srv := newPCrashPGServer(tb)
	ctx := context.Background()
	keep := *pcrashFlagWorld != ""
	if keep {
		if w, ok := loadPCrashPGWorld(tb, srv); ok {
			if w.buildStep >= pcrashPGBuildSteps {
				return w
			}
			w.finishBuild(tb) // a run that hit its time budget left a partial build
			return w
		}
	}
	root := ""
	if keep {
		root = *pcrashFlagWorld
		if err := os.MkdirAll(root, 0o700); err != nil {
			tb.Fatal(err)
		}
	}
	dir, err := os.MkdirTemp(root, "pcrash-pg-template-*")
	if err != nil {
		tb.Fatal(err)
	}
	fresh, err := os.MkdirTemp(root, "pcrash-pg-fresh-*")
	if err != nil {
		tb.Fatal(err)
	}
	name := pcrashPGName("t")
	if err := srv.createDB(ctx, name, ""); err != nil {
		tb.Fatalf("create template database: %v", pcrashPGScrub(err, srv.password))
	}
	if !keep {
		tb.Cleanup(func() {
			_ = srv.dropDB(context.Background(), name)
			_ = os.RemoveAll(dir)
			_ = os.RemoveAll(fresh)
		})
	}
	w := &pcrashPGWorld{
		pcrashWorld: &pcrashWorld{dir: dir, fresh: fresh, cal: map[string]pcrashCalibration{}},
		srv:         srv,
		templateDB:  name,
		freshDir:    fresh,
		pgCal:       map[string]pcrashPGCalibration{},
	}
	w.finishBuild(tb)
	return w
}

// finishBuild runs the template's remaining steps, saving after each so a run
// stopped by its time budget resumes at the next step instead of starting over.
func (w *pcrashPGWorld) finishBuild(tb testing.TB) {
	tb.Helper()
	dir := w.dir
	for w.buildStep < pcrashPGBuildSteps {
		switch w.buildStep {
		case 0:
			// init with --storage-type postgres writes a config and stops, because
			// it has no connection yet; the DSN is added and init runs again.
			w.runBuild(tb, dir, "admin", []string{"init", "--dev", "--storage-type", "postgres", "--config", "./keyorix.yaml"})
			w.yamlText = w.withDSN(tb, dir, w.templateDB)
		case 1:
			w.runBuild(tb, dir, "admin", []string{"init", "--dev", "--config", "./keyorix.yaml"})
		case 2:
			w.runBuild(tb, dir, "admin", []string{"encryption", "init", "--config", "./keyorix.yaml"})
			if err := pcrashCopyTree(dir, w.freshDir); err != nil {
				tb.Fatal(err)
			}
		case 3:
			w.runBuild(tb, dir, "admin", pcrashMigrateArgs)
		case 4:
			w.runBuild(tb, dir, "seed", nil)
		case 5:
			_ = os.Remove(filepath.Join(dir, "archive.tar.gz")) // a stopped earlier attempt's partial file
			w.runBuild(tb, dir, "admin", []string{"backup", "--config", "./keyorix.yaml", "--output", "./archive.tar.gz"})
			if err := os.WriteFile(filepath.Join(dir, "newpass"), []byte(pcrashPass2), 0o600); err != nil {
				tb.Fatal(err)
			}
			seed, err := readPCrashSeed(dir)
			if err != nil {
				tb.Fatal(err)
			}
			w.seed = seed
			if err := w.srv.quiesce(context.Background(), w.templateDB); err != nil {
				tb.Fatal(err)
			}
		}
		w.buildStep++
		w.save(tb)
	}
}

// pcrashPGTransient reports whether output names a dropped connection to the
// server (the SSH tunnel, or the shared server), not anything the command did.
func pcrashPGTransient(output string) bool {
	for _, s := range []string{"unexpected EOF", "connection reset", "broken pipe", "connection refused", "server closed the connection", "bad connection"} {
		if strings.Contains(output, s) {
			return true
		}
	}
	return false
}

func (w *pcrashPGWorld) runBuild(tb testing.TB, dir, action string, args []string) {
	tb.Helper()
	for attempt := 1; ; attempt++ {
		began := time.Now()
		r, err := runPCrashChild(dir, pcrashPass, action, args, 0)
		if err != nil {
			tb.Fatalf("template: %s %v: %v", action, args, err)
		}
		tb.Logf("template: %s %v took %s", action, args, time.Since(began).Round(time.Millisecond))
		if r.exit == 0 {
			return
		}
		if attempt < 3 && pcrashPGTransient(r.output) {
			tb.Logf("template: %s %v lost its connection, attempt %d, retrying", action, args, attempt)
			_ = os.Remove(filepath.Join(dir, "archive.tar.gz"))
			continue
		}
		tb.Fatalf("template: %s %v exited %d: %s", action, args, r.exit, pcrashTail(pcrashPGScrub(errors.New(r.output), w.srv.password)))
	}
}

// pcrashPGCalFile and pcrashPGWorldFile are what -pcrash.world keeps on disk.
type pcrashPGCalFile struct {
	Seams int64
	Trace []string
	Ref   *pcrashModel
}

type pcrashPGWorldFile struct {
	TemplateDB, Dir, Fresh, YAML string
	Seed                         pcrashSeed
	Cal                          map[string]pcrashPGCalFile
	MigSeams                     int64
	MigTrace                     []string
	MigSchema                    string
	Before                       *pcrashModel
	Cipher                       map[uint][]byte
	BuildStep                    int
}

func pcrashPGWorldPath() string { return filepath.Join(*pcrashFlagWorld, "world.json") }

// save writes the template and calibrations; the caller holds calMu.
func (w *pcrashPGWorld) save(tb testing.TB) {
	tb.Helper()
	if *pcrashFlagWorld == "" {
		return
	}
	f := pcrashPGWorldFile{TemplateDB: w.templateDB, Dir: w.dir, Fresh: w.freshDir, YAML: w.yamlText, Seed: w.seed, Cal: map[string]pcrashPGCalFile{}, BuildStep: w.buildStep}
	for name, c := range w.pgCal {
		f.Cal[name] = pcrashPGCalFile{Seams: c.seams, Trace: c.trace, Ref: c.ref}
	}
	if w.pgMig != nil {
		f.MigSeams, f.MigTrace, f.MigSchema = w.pgMig.seams, w.pgMig.trace, w.pgMigDB
	}
	if w.prepared != nil {
		f.Before = w.prepared.before
		f.Cipher = map[uint][]byte{}
		for id, c := range w.prepared.cipher {
			f.Cipher[id] = []byte(c)
		}
	}
	b, err := json.Marshal(f)
	if err != nil {
		tb.Fatal(err)
	}
	tmp := pcrashPGWorldPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		tb.Fatal(err)
	}
	if err := os.Rename(tmp, pcrashPGWorldPath()); err != nil {
		tb.Fatal(err)
	}
}

// loadPCrashPGWorld reuses a kept template; ok is false when there is none.
func loadPCrashPGWorld(tb testing.TB, srv *pcrashPGServer) (*pcrashPGWorld, bool) {
	tb.Helper()
	b, err := os.ReadFile(pcrashPGWorldPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, false
	}
	if err != nil {
		tb.Fatal(err)
	}
	var f pcrashPGWorldFile
	if err := json.Unmarshal(b, &f); err != nil {
		tb.Fatal(err)
	}
	var exists bool
	if err := srv.admin.QueryRowContext(context.Background(), "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", f.TemplateDB).Scan(&exists); err != nil {
		tb.Fatal(err)
	}
	if !exists {
		tb.Fatalf("the kept template database %s is gone; delete %s and rebuild", f.TemplateDB, pcrashPGWorldPath())
	}
	w := &pcrashPGWorld{
		pcrashWorld: &pcrashWorld{dir: f.Dir, fresh: f.Fresh, seed: f.Seed, cal: map[string]pcrashCalibration{}},
		srv:         srv, templateDB: f.TemplateDB, yamlText: f.YAML, freshDir: f.Fresh, pgCal: map[string]pcrashPGCalibration{}, buildStep: f.BuildStep,
	}
	for name, c := range f.Cal {
		w.pgCal[name] = pcrashPGCalibration{seams: c.Seams, trace: c.Trace, ref: c.Ref}
	}
	if f.MigSchema != "" {
		w.pgMig, w.pgMigDB = &pcrashPGCalibration{seams: f.MigSeams, trace: f.MigTrace}, f.MigSchema
	}
	if f.Before != nil {
		w.prepared = &pcrashExecState{before: f.Before, cipher: map[uint]string{}}
		for id, c := range f.Cipher {
			w.prepared.cipher[id] = string(c)
		}
	}
	return w, true
}

// withDSN writes storage.database.dsn into dir's keyorix.yaml and returns the
// text, keeping the rest of the file the init command wrote.
func (w *pcrashPGWorld) withDSN(tb testing.TB, dir, dbName string) string {
	tb.Helper()
	path := filepath.Join(dir, "keyorix.yaml")
	b, err := os.ReadFile(path) //nolint:gosec // test-generated path
	if err != nil {
		tb.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		tb.Fatal(err)
	}
	st, ok := doc["storage"].(map[string]any)
	if !ok {
		tb.Fatalf("keyorix.yaml has no storage section")
	}
	db, ok := st["database"].(map[string]any)
	if !ok {
		db = map[string]any{}
		st["database"] = db
	}
	db["dsn"] = w.srv.dsn(dbName)
	out, err := yaml.Marshal(doc)
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		tb.Fatal(err)
	}
	return string(out)
}

// yamlFor is the canonical config with a different database name.
func (w *pcrashPGWorld) yamlFor(dbName string) []byte {
	return []byte(strings.Replace(w.yamlText, "dbname="+w.templateDB+" ", "dbname="+dbName+" ", 1))
}

// newInstall is a fresh copy of the template install on its own database.
func (w *pcrashPGWorld) newInstall(t *testing.T, templateDB, srcDir string) *pcrashPGInst {
	t.Helper()
	dir := t.TempDir()
	if err := pcrashCopyTree(srcDir, dir); err != nil {
		t.Fatalf("copy install: %v", err)
	}
	name := pcrashPGName("e")
	ctx := context.Background()
	if err := w.srv.createDB(ctx, name, templateDB); err != nil {
		t.Fatalf("clone database: %v", pcrashPGScrub(err, w.srv.password))
	}
	t.Cleanup(func() { _ = w.srv.dropDB(context.Background(), name) })
	inst := &pcrashPGInst{dir: dir, db: name, yaml: w.yamlFor(name)}
	if err := inst.restoreYAML(); err != nil {
		t.Fatal(err)
	}
	return inst
}

var pcrashPGGenerated = regexp.MustCompile(`^w5_[tep]_[0-9]+_[0-9]+$`)

// TestProcessCrashPGDropLeftovers removes databases a killed test run left
// behind. It drops only names matching the exact pattern pcrashPGName generates.
func TestProcessCrashPGDropLeftovers(t *testing.T) {
	if *pcrashFlagDropLeftovers == "" {
		t.Skip("pass -args -pcrash.drop-leftovers=exec|all to drop leftover generated databases")
	}
	srv := newPCrashPGServer(t)
	ctx := context.Background()
	rows, err := srv.admin.QueryContext(ctx, "SELECT datname FROM pg_database WHERE datname LIKE 'w5\\_%'")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	_ = rows.Close()
	dropped := 0
	for _, n := range names {
		if !pcrashPGGenerated.MatchString(n) || (*pcrashFlagDropLeftovers == "exec" && !strings.HasPrefix(n, "w5_e_")) {
			t.Logf("left alone: %s", n)
			continue
		}
		if err := srv.dropDB(ctx, n); err != nil {
			t.Errorf("drop %s: %s", n, pcrashPGScrub(err, srv.password))
			continue
		}
		dropped++
	}
	t.Logf("dropped %d leftover database(s)", dropped)
}

// pgSchema is the sorted text of the database's public-schema objects.
func (w *pcrashPGWorld) pgSchema(ctx context.Context, name string) (string, error) {
	cc, err := pgx.ParseConfig(w.srv.dsn(name))
	if err != nil {
		return "", err
	}
	db := stdlib.OpenDB(*cc)
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(ctx, `
		SELECT 'column ' || table_name || ' ' || column_name || ' ' || data_type || ' ' || is_nullable || ' ' || COALESCE(column_default, '')
		  FROM information_schema.columns WHERE table_schema = 'public'
		UNION ALL SELECT 'index ' || indexname || ' ' || indexdef FROM pg_indexes WHERE schemaname = 'public'
		UNION ALL SELECT 'constraint ' || conrelid::regclass || ' ' || conname || ' ' || pg_get_constraintdef(oid)
		  FROM pg_constraint WHERE connamespace = 'public'::regnamespace
		ORDER BY 1`)
	if err != nil {
		return "", err
	}
	defer func() { _ = rows.Close() }()
	var b strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return "", err
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String(), rows.Err()
}
