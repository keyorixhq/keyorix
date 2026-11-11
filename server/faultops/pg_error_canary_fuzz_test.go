package faultops

// pg_error_canary_fuzz_test.go -- the PostgreSQL leg of the panic-dump target, and a
// gRPC / real-CLI target that drives a request to a PostgreSQL error.
//
// FuzzPanicDumpCanaryPG runs FuzzPanicDumpCanary's oracle over a reused PostgreSQL
// world. FuzzGRPCPGErrorCanary sends a gRPC request PostgreSQL rejects (a duplicate
// key, a NUL-free but index-breaking name) and judges the status message and every
// process channel. TestCLIAgainstPGCanary runs the real binary against the real
// router over PostgreSQL, so an error PostgreSQL raised and the API returned is
// judged again as CLI output.
//
// Skips without KEYORIX_TEST_PG_DSN. Everything happens in w7_* databases.

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/canary"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgcanary"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// newPanicDumpPGFixture points the fault worlds at a w7_ database and makes every
// execution reuse one migrated schema: the SQLite target's fresh world per execution
// would migrate over the network every time.
func newPanicDumpPGFixture(tb testing.TB) *panicDumpFixture {
	tb.Helper()
	tb.Setenv(pgDSNEnv, pgcanary.EmptyDatabase(tb, "panic"))
	fx := newPanicDumpFixture(tb)
	w := buildReusableFaultWorld(tb, nil)
	fx.newWorld = func(t *testing.T) *faultWorld {
		w.resetForReuse(t, nil)
		return w
	}
	return fx
}

// FuzzPanicDumpCanaryPG is FuzzPanicDumpCanary over PostgreSQL.
func FuzzPanicDumpCanaryPG(f *testing.F) {
	if err := i18n.InitializeForTesting(); err != nil {
		f.Fatal(err)
	}
	f.Cleanup(i18n.ResetForTesting)
	fx := newPanicDumpPGFixture(f)
	for _, in := range panicDumpCorpus() {
		f.Add(in.op, in.method, in.nth, in.seed)
	}
	f.Fuzz(func(t *testing.T, opSel, method, nth uint8, seed []byte) {
		res := runPanicDump(t, fx, panicDumpInput{opSel, method, nth, seed}, panicDumpRules(), nil)
		if res.invalid != "" {
			t.Fatal(res.invalid)
		}
		if !res.fired {
			t.Skip("the armed storage call was not reached on this run")
		}
		if !res.panicked {
			t.Fatalf("INVALID RUN: the fault fired but no panic was logged: the panic path was not exercised")
		}
		if len(res.findings) > 0 {
			t.Fatalf("CANARY LEAK (%d):\n%s", len(res.findings), strings.Join(res.findings, "\n"))
		}
	})
}

// TestPanicDumpCanaryPGOracle is TestPanicDumpCanaryOracle's two load-bearing cases
// on PostgreSQL: a clean corpus input really panics and reports nothing, and a panic
// value carrying the canary is reported.
func TestPanicDumpCanaryPGOracle(t *testing.T) {
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(i18n.ResetForTesting)
	fx := newPanicDumpPGFixture(t)
	t.Run("clean", func(t *testing.T) {
		res := runPanicDump(t, fx, panicDumpInput{op: 0, seed: []byte("seed-0")}, panicDumpRules(), nil)
		if res.invalid != "" {
			t.Fatal(res.invalid)
		}
		if !res.fired || !res.panicked || len(res.findings) != 0 {
			t.Fatalf("fired=%v panicked=%v findings=%v", res.fired, res.panicked, res.findings)
		}
	})
	t.Run("red-panic-value-in-log", func(t *testing.T) {
		res := runPanicDump(t, fx, panicDumpInput{op: 0, seed: []byte("seed-0")}, panicDumpRules(), &panicDumpPlant{panicErr: func(v string) error { return fmt.Errorf("storage: %s", v) }})
		if res.invalid != "" {
			t.Fatal(res.invalid)
		}
		if !slices.ContainsFunc(res.findings, func(s string) bool { return strings.Contains(s, "channel="+canary.ChannelLog) }) {
			t.Fatalf("planted panic value was not reported: %v", res.findings)
		}
	})
}

const pgErrAdminPassword = "FaultFuzzAdmin123!"

// pgErrFixture is one worker's world: a migrated, seeded database, and the fixed
// parts of the transport.
type pgErrFixture struct {
	world     *pgcanary.World
	enc       *encryption.Service
	adminID   uint
	projectID uint
	envID     uint
	capture   *canary.Capture
	control   *prometheus.GaugeVec
	dir       string
}

// newPGErrFixture builds and snapshots the world. It uses the fault world's core
// wiring (newWorldCore), so gRPC and REST behave as in every other world here.
func newPGErrFixture(tb testing.TB) *pgErrFixture {
	tb.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(i18n.ResetForTesting)
	dir, err := os.MkdirTemp("", "pg-err-canary-*")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(dir) })
	world := pgcanary.Open(tb, "grpc", "")
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, dir)
	if err := enc.Initialize("pg-err-canary-passphrase"); err != nil {
		tb.Fatalf("encryption: %v", err)
	}
	c := newWorldCore(tb, faultstorage.NewFaultyStorage(world.Storage(), nil))
	c.SetSecretValueEncryptor(enc)
	c.SetAuthEncryptor(enc)
	ctx := context.Background()
	if _, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{Username: "faultadmin", Email: "faultadmin@example.com", Password: pgErrAdminPassword, Token: "fault-fuzz-bootstrap"}); err != nil {
		tb.Fatalf("bootstrap: %v", err)
	}
	ls := world.Storage()
	admin, err := ls.GetUserByUsername(ctx, "faultadmin")
	if err != nil || admin == nil {
		tb.Fatalf("admin: %v", err)
	}
	proj, err := ls.CreateProject(ctx, &models.Project{Name: "canary-proj"})
	if err != nil {
		tb.Fatalf("project: %v", err)
	}
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	if err != nil {
		tb.Fatalf("env: %v", err)
	}
	drainAllBackgroundGoroutines()
	world.Snapshot(tb)

	fx := &pgErrFixture{world: world, enc: enc, adminID: admin.ID, projectID: proj.ID, envID: env.ID, capture: canary.NewCapture(), dir: dir}
	tb.Cleanup(fx.capture.Uninstall)
	fx.control = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "keyorix_pg_err_canary_control", Help: "Harness control for the metrics capture."}, []string{"v"})
	if err := prometheus.Register(fx.control); err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { prometheus.Unregister(fx.control) })
	return fx
}

// world builds one execution's world on the reset database, reusing every faultWorld
// helper: only the storage underneath differs.
func (fx *pgErrFixture) newExec(t *testing.T) *faultWorld {
	t.Helper()
	if err := fx.world.Reset(); err != nil {
		t.Fatalf("INVALID RUN: %v", err)
	}
	t.Cleanup(drainAllBackgroundGoroutines)
	if err := fx.capture.InstallOnce(fx.dir, os.Create); err != nil {
		t.Fatalf("capture: %v", err)
	}
	faulty := faultstorage.NewFaultyStorage(fx.world.Storage(), nil)
	c := newWorldCore(t, faulty)
	c.SetSecretValueEncryptor(fx.enc)
	c.SetAuthEncryptor(fx.enc)
	w := &faultWorld{t: t, db: fx.world.DB, backend: "postgres", core: c, faulty: faulty, httpClient: &http.Client{Timeout: 30 * time.Second}, scimToken: faultopsSCIMToken}
	w.rebuildTransport(t)
	t.Cleanup(func() {
		w.httpServer.Close()
		_ = w.grpcConn.Close()
		w.grpcSrv.Stop()
	})
	expires := time.Now().Add(time.Hour)
	s, err := c.Storage().CreateSession(context.Background(), &models.Session{UserID: fx.adminID, SessionToken: fmt.Sprintf("pgerr-%d-%d", time.Now().UnixNano(), os.Getpid()), ExpiresAt: &expires})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	w.adminToken = s.SessionToken
	w.grpcCtx = metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+s.SessionToken))
	fx.capture.Drain()
	fx.world.Tracer.Drain()
	return w
}

// pgErrInput selects the provocation. seed makes the canaries replayable.
type pgErrInput struct {
	kind uint8
	seed []byte
}

const pgErrKinds = 5

type pgErrResult struct {
	findings []string
	invalid  string
	codes    map[string]int
	details  int
	grpcCode string
}

// runGRPCPGError is one execution: the control secret first, the provocation, then
// the same channel scan as the other targets.
func runGRPCPGError(t *testing.T, fx *pgErrFixture, in pgErrInput, shim func(*faultWorld, string) string) pgErrResult {
	t.Helper()
	w := fx.newExec(t)
	secret := canary.New("value", canary.Secret, in.seed, len(in.seed)%2 == 0)
	control := canary.New("control", canary.Secret, in.seed, false)
	name := canary.New("name", canary.Metadata, in.seed, false)
	otherName := canary.New("other-name", canary.Metadata, in.seed, false)
	probe := canary.New("probe", canary.Metadata, in.seed, false)
	scanner := canary.NewScanner(secret, control, name, otherName, probe)
	res := pgErrResult{codes: map[string]int{}}

	client := pb.NewSecretServiceClient(w.grpcConn)
	created, err := client.CreateSecret(w.grpcCtx, &pb.CreateSecretRequest{Name: name.Raw, Value: control.Raw, ProjectId: uint32(fx.projectID), EnvironmentId: uint32(fx.envID), Type: "generic"})
	if err != nil {
		res.invalid = "INVALID RUN: control secret: " + err.Error()
		return res
	}
	reveal, err := client.GetSecretValue(w.grpcCtx, &pb.GetSecretRequest{Id: created.GetId(), IncludeValue: true})
	if err != nil || !slices.ContainsFunc(scanner.Scan("reveal", []byte(reveal.String())), func(h canary.Hit) bool { return h.Label == control.Label }) {
		res.invalid = fmt.Sprintf("INVALID RUN: the reveal did not return the control canary: %v", err)
		return res
	}
	drainAllBackgroundGoroutines()
	fx.capture.Drain()
	fx.world.Tracer.Drain()

	status := ""
	if in.kind%pgErrKinds == 0 {
		// A duplicate key: 23505 with the name in DETAIL. It must be a PROJECT, not a
		// secret: core.CreateSecret pre-checks the name at the application layer and
		// returns before any INSERT, so a duplicate secret never reaches the server.
		// Project names are enforced only by the unique index. That index is
		// case-folded, but the canary's core is lower-case hex, so the scanner still
		// matches it in the (folded) DETAIL.
		pc := pb.NewProjectServiceClient(w.grpcConn)
		if _, err := pc.CreateProject(w.grpcCtx, &pb.CreateProjectRequest{Name: name.Raw}); err != nil {
			res.invalid = "INVALID RUN: seed project: " + err.Error()
			return res
		}
		if _, err := pc.CreateProject(w.grpcCtx, &pb.CreateProjectRequest{Name: name.Raw}); err != nil {
			status = err.Error()
			res.grpcCode = strings.SplitN(status, " ", 2)[0]
		}
	} else {
		req := &pb.CreateSecretRequest{Value: secret.Raw, ProjectId: uint32(fx.projectID), EnvironmentId: uint32(fx.envID), Type: "generic"}
		switch in.kind % pgErrKinds {
		case 1: // past the index size limit
			req.Name = strings.Repeat(otherName.Raw, 80)
		case 2: // the hostile wrapper
			req.Name = "p\"'\\%" + otherName.Raw
		case 3: // an unknown project id: a foreign key if it gets that far
			req.Name = otherName.Raw
			req.ProjectId = 4294967
		case 4: // the value canary under a name that also fails
			req.Name = name.Raw
			req.Value = strings.Repeat(secret.Raw, 400)
		}
		if _, err := client.CreateSecret(w.grpcCtx, req); err != nil {
			status = err.Error()
			res.grpcCode = strings.SplitN(status, " ", 2)[0]
		}
	}
	if shim != nil {
		status += shim(w, secret.Raw)
	}
	drainAllBackgroundGoroutines()
	entries := fx.world.Tracer.Drain()
	for _, e := range entries {
		if e.SQLState != "" {
			res.codes[e.SQLState]++
		}
	}
	for _, o := range pgcanary.RawOutputs(entries) {
		if o.Channel == "pg-raw:detail" {
			res.details += len(scanner.Scan(o.Channel, o.Data))
		}
	}

	judge := func(channel string, data []byte) {
		for _, h := range scanner.Scan(channel, data) {
			if h.Label == probe.Label {
				continue
			}
			res.findings = append(res.findings, fmt.Sprintf("kind=%d %s", in.kind%pgErrKinds, h))
		}
	}
	judge("grpc-status", []byte(status))
	for _, o := range fx.capture.Drain() {
		judge(o.Channel, o.Data)
	}
	// Controls: each capture proves it can still show a canary.
	log.Print(probe.Raw)
	_, _ = fmt.Fprintln(os.Stdout, probe.Raw)
	fmt.Fprintln(os.Stderr, probe.Raw)
	fx.control.WithLabelValues(probe.Raw).Set(1)
	outputs := fx.capture.Drain()
	for _, ch := range []string{canary.ChannelLog, canary.ChannelStdout, canary.ChannelStderr} {
		found := slices.ContainsFunc(outputs, func(o canary.Output) bool {
			return o.Channel == ch && slices.ContainsFunc(scanner.Scan(ch, o.Data), func(h canary.Hit) bool { return h.Label == probe.Label })
		})
		if !found {
			res.invalid = "INVALID RUN: the probe did not reach channel " + ch
			return res
		}
	}
	for _, o := range outputs {
		judge(o.Channel, o.Data)
	}
	metrics, err := scrapeMetrics(context.Background(), w)
	if err != nil {
		res.invalid = "INVALID RUN: metrics: " + err.Error()
		return res
	}
	fx.control.Reset()
	if !slices.ContainsFunc(scanner.Scan("metrics", []byte(metrics)), func(h canary.Hit) bool { return h.Label == probe.Label }) {
		res.invalid = "INVALID RUN: the probe is not in /metrics"
		return res
	}
	judge("metrics", []byte(metrics))

	dump, err := fx.world.Dump()
	if err != nil {
		res.invalid = "INVALID RUN: dump: " + err.Error()
		return res
	}
	if !slices.ContainsFunc(scanner.ScanAll(dump), func(h canary.Hit) bool { return h.Label == name.Label }) {
		res.invalid = "INVALID RUN: the control name is in no column, so the database scan sees nothing"
		return res
	}
	// Audit rows and the secret's own row name it by design; a secret canary still
	// has no permitted cell.
	for _, h := range scanner.ScanAll(dump) {
		if h.Class == canary.Metadata {
			continue
		}
		res.findings = append(res.findings, fmt.Sprintf("kind=%d %s", in.kind%pgErrKinds, h))
	}
	return res
}

// FuzzGRPCPGErrorCanary fails when a gRPC request PostgreSQL rejected leaves a canary
// in the status message or any process channel.
func FuzzGRPCPGErrorCanary(f *testing.F) {
	fx := newPGErrFixture(f)
	for k := range pgErrKinds {
		f.Add(uint8(k), []byte(fmt.Sprintf("seed-%d", k)))
	}
	f.Fuzz(func(t *testing.T, kind uint8, seed []byte) {
		res := runGRPCPGError(t, fx, pgErrInput{kind, seed}, nil)
		if res.invalid != "" {
			t.Fatal(res.invalid)
		}
		if len(res.findings) > 0 {
			t.Fatalf("CANARY LEAK (%d):\n%s", len(res.findings), strings.Join(res.findings, "\n"))
		}
	})
}

// TestGRPCPGErrorCanary proves the provocations reach the server (duplicate key,
// DETAIL carrying the canary), that a clean run reports nothing, and that a shim
// quoting the failing value in the status message is reported.
func TestGRPCPGErrorCanary(t *testing.T) {
	fx := newPGErrFixture(t)
	all := map[string]int{}
	details := 0
	for k := range pgErrKinds {
		res := runGRPCPGError(t, fx, pgErrInput{uint8(k), []byte(fmt.Sprintf("seed-%d", k))}, nil)
		if res.invalid != "" {
			t.Fatal(res.invalid)
		}
		if len(res.findings) != 0 {
			t.Errorf("kind %d reported: %v", k, res.findings)
		}
		t.Logf("kind %d: status=%q codes=%v", k, res.grpcCode, res.codes)
		for c, n := range res.codes {
			all[c] += n
		}
		details += res.details
	}
	t.Logf("server errors: %v; canaries in DETAIL: %d", all, details)
	if all["23505"] == 0 || details == 0 {
		t.Errorf("no real duplicate-key failure carried a canary: codes %v details %d", all, details)
	}
	t.Run("shim-quoting-the-value-is-reported", func(t *testing.T) {
		res := runGRPCPGError(t, fx, pgErrInput{0, []byte("seed-0")}, func(_ *faultWorld, value string) string { return " pg detail: " + value })
		if res.invalid != "" {
			t.Fatal(res.invalid)
		}
		if !slices.ContainsFunc(res.findings, func(s string) bool { return strings.Contains(s, "channel=grpc-status") }) {
			t.Fatalf("shim not reported: %v", res.findings)
		}
	})
	t.Run("control-after-shim-is-silent", func(t *testing.T) {
		res := runGRPCPGError(t, fx, pgErrInput{0, []byte("seed-0")}, nil)
		if res.invalid != "" || len(res.findings) != 0 {
			t.Fatalf("invalid=%q findings=%v", res.invalid, res.findings)
		}
	})
}

// buildPGErrCLI builds the real binary; see buildCanaryCLI for why GOWORK=off.
func buildPGErrCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "keyorix")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = filepath.Join("..", "..", "cli")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

// TestCLIAgainstPGCanary sends the real CLI through a real PostgreSQL failure and
// scans what it prints. It is a fixed table rather than a fuzz target because each
// case is a process launch and a tunnel round trip; every vector's canary is
// replayable and derived per case.
func TestCLIAgainstPGCanary(t *testing.T) {
	fx := newPGErrFixture(t)
	bin := buildPGErrCLI(t)
	vectors := []struct {
		name string
		args []string
	}{
		{"duplicate-name", []string{"project", "create", "--name", "@M@"}},
		{"over-long-name", []string{"secret", "create", "--name", "@L@", "--from-file", "-"}},
		{"hostile-name", []string{"secret", "create", "--name", "p\"'\\%@M@", "--from-file", "-"}},
		{"unknown-project", []string{"secret", "create", "--name", "@M@", "--project-id", "4294967", "--from-file", "-"}},
		{"get-by-name-missing", []string{"secret", "get", "--name", "@M@"}},
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			w := fx.newExec(t)
			secret := canary.New("secret", canary.Secret, []byte(v.name), true)
			meta := canary.New("meta", canary.Metadata, []byte(v.name), false)
			control := canary.New("control", canary.Secret, []byte(v.name), false)
			scanner := canary.NewScanner(secret, meta, control)
			if v.name == "duplicate-name" {
				// Seed a project named after the metadata canary so the CLI's own
				// `project create` collides on the unique index: a real 23505 the API
				// then returns. A duplicate SECRET would be pre-checked by core before
				// any INSERT and never reach the server (see runGRPCPGError kind 0).
				if _, err := pb.NewProjectServiceClient(w.grpcConn).CreateProject(w.grpcCtx, &pb.CreateProjectRequest{Name: meta.Raw}); err != nil {
					t.Fatalf("INVALID RUN: seed: %v", err)
				}
			}
			args := make([]string, 0, len(v.args)+2)
			for _, a := range v.args {
				a = strings.ReplaceAll(a, "@M@", meta.Raw)
				args = append(args, strings.ReplaceAll(a, "@L@", strings.Repeat(meta.Raw, 80)))
			}
			fx.world.Tracer.Drain()
			home := t.TempDir()
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Dir = home
			cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "KEYORIX_SERVER=" + w.httpServer.URL, "KEYORIX_TOKEN=" + w.adminToken, "NO_COLOR=1", "XDG_CONFIG_HOME=" + filepath.Join(home, "config")}
			cmd.Stdin = strings.NewReader(secret.Raw)
			var so, se strings.Builder
			cmd.Stdout, cmd.Stderr = &so, &se
			runErr := cmd.Run()
			if ctx.Err() != nil {
				t.Fatalf("INVALID RUN: timed out: %v", args)
			}
			entries := fx.world.Tracer.Drain()
			codes := map[string]int{}
			for _, e := range entries {
				codes[e.SQLState]++
			}
			t.Logf("exit=%v codes=%v", runErr, codes)
			// A metadata canary may come back on stderr to the user who typed it (W2's
			// meta-stderr rule); a secret canary may not appear anywhere.
			allow := canary.NewAllowlist(canary.Rule{ID: "meta-stderr", Channel: canary.ChannelStderr, MetadataOnly: true}, canary.Rule{ID: "meta-stdout", Channel: canary.ChannelStdout, MetadataOnly: true})
			var findings []string
			for ch, data := range map[string][]byte{canary.ChannelStdout: []byte(so.String()), canary.ChannelStderr: []byte(se.String())} {
				for _, h := range scanner.Scan(ch, data) {
					if allow.Permit(h, v.name) == "" {
						findings = append(findings, h.String())
					}
				}
			}
			err := filepath.WalkDir(home, func(p string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				data, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				for _, h := range scanner.Scan("file:"+d.Name(), data) {
					if h.Class == canary.Secret {
						findings = append(findings, h.String())
					}
				}
				return nil
			})
			if err != nil {
				t.Fatalf("INVALID RUN: home scan: %v", err)
			}
			if len(findings) > 0 {
				t.Fatalf("CANARY LEAK:\n%s", strings.Join(findings, "\n"))
			}
			if v.name == "duplicate-name" && codes["23505"] == 0 {
				t.Errorf("the duplicate did not reach the server as a 23505: %v (stderr len %d)", codes, len(se.String()))
			}
		})
	}
	// Positive control: the same binary and channels show a canary on the permitted
	// route, so a silent scan above means the channel was empty of it, not unwatched.
	t.Run("control-reveal", func(t *testing.T) {
		w := fx.newExec(t)
		control := canary.New("control", canary.Secret, []byte("cli-control"), false)
		secretName := "cli-control-" + control.Core
		client := pb.NewSecretServiceClient(w.grpcConn)
		if _, err := client.CreateSecret(w.grpcCtx, &pb.CreateSecretRequest{Name: secretName, Value: control.Raw, ProjectId: uint32(fx.projectID), EnvironmentId: uint32(fx.envID), Type: "generic"}); err != nil {
			t.Fatalf("INVALID RUN: seed: %v", err)
		}
		home := t.TempDir()
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "secret", "get", "--ref", "canary-proj/prod/"+secretName)
		cmd.Dir = home
		cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "KEYORIX_SERVER=" + w.httpServer.URL, "KEYORIX_TOKEN=" + w.adminToken, "NO_COLOR=1", "XDG_CONFIG_HOME=" + filepath.Join(home, "config")}
		out, err := cmd.CombinedOutput()
		if !slices.ContainsFunc(canary.NewScanner(control).Scan("cli", out), func(h canary.Hit) bool { return h.Label == control.Label }) {
			t.Fatalf("INVALID RUN: the CLI reveal did not print the control canary: %v (output length %d)", err, len(out))
		}
	})
}
