package core

// secret_ops_canary_pg_fuzz_test.go -- FuzzCorePGCanaryLeak.
//
// The PostgreSQL leg of FuzzCoreSecretOpsCanaryLeak: the same operation program over
// a real server, plus operations built to make PostgreSQL itself complain about a
// value carrying a canary (a NUL, invalid UTF-8, a value too long for its index, a
// duplicate key, a duplicate that only two racing writers can produce). The
// PostgreSQL error fields are recorded by a pgx tracer so a test can prove the
// provocation really reached the server; the oracle is the same as the SQLite one,
// with one addition: a canary from a row the caller never sent (label "stored-")
// may not appear in a returned error even though it is metadata.
//
// Skips without KEYORIX_TEST_PG_DSN. Everything happens in w7_* databases.

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/canary"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"github.com/keyorixhq/keyorix/internal/testutil/pgcanary"
)

const (
	corePGW2OpCount = 14 // the SQLite target's operations, run unchanged here
	corePGOpCount   = 15

	corePGVariantCount = 7
)

// corePGCanaryAllow is coreCanaryAllow for a database with no raw file, with the one
// tightening described in the file comment.
func corePGCanaryAllow() *canary.Allowlist {
	return canary.NewAllowlist(
		canary.Rule{ID: "value-reveal", Channel: coreChanReveal, Origin: "read-value", Why: "GetSecretValueWithPermissionCheck is the authorised read"},
		canary.Rule{ID: "meta-result", Channel: coreChanResult, MetadataOnly: true, Why: "names, descriptions, tags and metadata are returned by the operations that manage them"},
		canary.Rule{ID: "meta-error", Channel: coreChanError, MetadataOnly: true, DenyLabelPrefix: "stored-", Why: "a rejected field is named in the error returned to the caller who sent it; never a value of a row the caller did not send"},
		canary.Rule{ID: "meta-db", Channel: canary.ChannelDBPrefix + "*", MetadataOnly: true, Why: "stored in plaintext by design"},
	)
}

type corePGFixture struct {
	*coreCanaryFixture
	world *pgcanary.World
}

func newCorePGFixture(tb testing.TB, isolation string) *corePGFixture {
	tb.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		tb.Fatalf("i18n: %v", err)
	}
	dir, err := os.MkdirTemp("", "core-pg-canary-*")
	if err != nil {
		tb.Fatalf("mkdir: %v", err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(dir) })

	world := pgcanary.Open(tb, "core", isolation)
	base := &fuzzworld.World{Backend: fuzzworld.BackendPostgres, DB: world.DB}
	if err := base.Reset(coreSeqResetTables); err != nil {
		tb.Fatalf("reset: %v", err)
	}
	fx := &corePGFixture{coreCanaryFixture: &coreCanaryFixture{dir: dir}, world: world}
	fx.seed(tb, world.DB)
	world.Snapshot(tb)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, dir)
	if err := enc.Initialize("core-pg-canary-fuzz-passphrase"); err != nil {
		tb.Fatalf("encryption: %v", err)
	}
	fx.enc = enc
	fx.capture = canary.NewCapture()
	tb.Cleanup(fx.capture.Uninstall)
	fx.controlMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "keyorix_core_pg_canary_control", Help: "Harness control for the metrics capture."}, []string{"v"})
	if err := prometheus.Register(fx.controlMetric); err != nil {
		tb.Fatalf("register control metric: %v", err)
	}
	tb.Cleanup(func() { prometheus.Unregister(fx.controlMetric) })
	return fx
}

// corePGRun is one execution. Most of the machinery is coreCanaryRun's.
type corePGRun struct {
	*coreCanaryRun
	world      *pgcanary.World
	storedName string
	raced      bool
	sqlstates  map[string]int // SQLSTATE, or "client" for an error with none, across the run
	rawFields  map[string]int // "field/class" counts of canaries seen in driver errors
}

func (fx *corePGFixture) newRun(t testing.TB, dir string, seed []byte, allow *canary.Allowlist) *corePGRun {
	t.Helper()
	if err := fx.world.Reset(); err != nil {
		t.Fatalf("INVALID RUN: %v", err)
	}
	t.Cleanup(DrainBackgroundGoroutines)
	faulty := faultstorage.NewFaultyStorage(fx.world.Storage(), nil)
	c := NewKeyorixCore(faulty)
	c.SetSecretValueEncryptor(fx.enc)
	if !c.SecretValueEncryptionActive() {
		t.Fatalf("INVALID RUN: encryption inactive, every at-rest check would be vacuous")
	}
	c.SetAuthEncryptor(fx.enc)
	fx.capture.Drain()
	base := &coreCanaryRun{fx: fx.coreCanaryFixture, c: c, db: fx.world.DB, dir: dir, seed: seed, scanner: canary.NewScanner(), allow: allow, ctx: t.Context(), fault: faulty, outcomes: map[string]int{}}
	base.captureProbe = base.mint("capture-probe", canary.Metadata)
	return &corePGRun{coreCanaryRun: base, world: fx.world, sqlstates: map[string]int{}, rawFields: map[string]int{}}
}

// evidence folds the driver errors of the last operation into the run's record.
func (r *corePGRun) evidence() {
	entries := r.world.Tracer.Drain()
	for _, e := range entries {
		code := e.SQLState
		if code == "" {
			code = "client"
		}
		r.sqlstates[code]++
	}
	for _, o := range pgcanary.RawOutputs(entries) {
		for _, h := range r.scanner.Scan(o.Channel, o.Data) {
			r.rawFields[strings.TrimPrefix(o.Channel, "pg-raw:")+"/"+h.Class.String()]++
		}
	}
}

// stored mints a canary for a column of a row no provoking request sends.
func (r *corePGRun) stored(field string) string {
	r.serial++
	c := canary.New(fmt.Sprintf("stored-%s-%d", field, r.serial), canary.Metadata, r.seed, false)
	r.scanner.Add(c)
	return c.Raw
}

func (r *corePGRun) pgPrologue() {
	r.prologue()
	r.storedName = r.meta("name")
	s, err := r.c.CreateSecret(r.ctx, &CreateSecretRequest{
		Name: r.storedName, Value: r.value(), ProjectID: r.fx.projectID, EnvironmentID: r.fx.envID,
		Type: "password", CreatedBy: "canary-admin", OwnerID: coreCanaryAdminID,
		Description: r.stored("desc"),
		Metadata:    map[string]string{"owner-note": r.stored("meta")},
		Tags:        []string{r.stored("tag")},
	})
	if err != nil || s == nil {
		coreFail("INVALID RUN: stored secret was not created: %v", err)
	}
	r.secrets = append(r.secrets, s.ID)
	r.observe("pg-prologue", s, nil)
	r.evidence()
}

// variant wraps a fresh metadata canary in one of the shapes PostgreSQL treats
// specially. Its result is a name for the database layer, so only the bare canary
// is registered: the scanner finds it inside any of the shapes.
func (r *corePGRun) variant(prefix string, flag byte) string {
	c := r.meta(prefix)
	switch int(flag) % corePGVariantCount {
	case 0:
		return c + "\x00" + c // NUL: 22021
	case 1:
		return c + "\xff\xfe" // invalid UTF-8: 22021
	case 2:
		return c[:len(c)/2] + "\xc3\x28" + c[len(c)/2:] // invalid continuation byte inside the value
	case 3:
		return strings.Repeat(c, 80) // past the 1/3-page btree limit: 54000 on an indexed column
	case 4:
		return strings.Repeat(c, 4000) // past 100 KiB
	case 5:
		return "p\"\\<&>'%+ /é" + c + "é/ +%'>&<\\\"s" // the hostile wrapper; valid UTF-8
	default:
		return c
	}
}

func (r *corePGRun) createWith(mod func(*CreateSecretRequest)) (*CreateSecretRequest, *corePGCreateResult) {
	req := &CreateSecretRequest{
		Name: r.meta("name"), Value: r.value(), ProjectID: r.fx.projectID, EnvironmentID: r.fx.envID,
		Type: "password", CreatedBy: "canary-admin", OwnerID: coreCanaryAdminID,
	}
	mod(req)
	s, err := r.c.CreateSecret(r.ctx, req)
	return req, &corePGCreateResult{s, err}
}

type corePGCreateResult struct {
	s   any
	err error
}

func (r *corePGRun) observeCreate(origin string, res *corePGCreateResult) {
	var v any
	if res.err == nil {
		v = res.s
	}
	r.observe(origin, v, res.err)
	r.evidence()
}

// pg runs PostgreSQL-specific operation kind (see corePGOpCount).
func (r *corePGRun) pg(kind int, sel, flag byte) {
	switch kind {
	case 0:
		_, res := r.createWith(func(q *CreateSecretRequest) { q.Name = r.variant("name", flag) })
		r.observeCreate("pg-name", res)
	case 1:
		_, res := r.createWith(func(q *CreateSecretRequest) { q.Description = r.variant("desc", flag) })
		r.observeCreate("pg-desc", res)
	case 2:
		_, res := r.createWith(func(q *CreateSecretRequest) { q.Metadata = map[string]string{"k": r.variant("meta", flag)} })
		r.observeCreate("pg-meta-value", res)
	case 3:
		_, res := r.createWith(func(q *CreateSecretRequest) { q.Metadata = map[string]string{r.variant("metakey", flag): "x"} })
		r.observeCreate("pg-meta-key", res)
	case 4:
		_, res := r.createWith(func(q *CreateSecretRequest) { q.Tags = []string{r.variant("tag", flag)} })
		r.observeCreate("pg-tag", res)
	case 5:
		_, res := r.createWith(func(q *CreateSecretRequest) { q.Type = r.variant("type", flag) })
		r.observeCreate("pg-type", res)
	case 6:
		_, res := r.createWith(func(q *CreateSecretRequest) { q.CreatedBy = r.variant("created-by", flag) })
		r.observeCreate("pg-created-by", res)
	case 7:
		// The value is secret-class and never reaches SQL as text; this proves that
		// no code path turns the rejected bytes into an error.
		hostile := r.mint("value", canary.Secret)
		bad := append(append([]byte(hostile.Raw), 0, 0xff, 0xfe), hostile.Raw...)
		_, res := r.createWith(func(q *CreateSecretRequest) { q.Value = bad })
		r.observeCreate("pg-value-bytes", res)
	case 8: // 23505 on the secret name
		_, res := r.createWith(func(q *CreateSecretRequest) { q.Name = r.storedName; q.Description = r.meta("desc") })
		r.observeCreate("pg-duplicate-secret", res)
	case 9:
		name := r.variant("project", flag)
		p, err := r.c.CreateProject(r.ctx, name, r.variant("project-desc", flag))
		r.observe("pg-project", p, err)
		r.evidence()
		p2, err := r.c.CreateProject(r.ctx, name, "")
		r.observe("pg-project-dup", p2, err)
		r.evidence()
	case 10:
		name := r.variant("env", flag)
		e, err := r.c.CreateEnvironment(r.ctx, r.fx.projectID, name)
		r.observe("pg-env", e, err)
		r.evidence()
		e2, err := r.c.CreateEnvironment(r.ctx, r.fx.projectID, name)
		r.observe("pg-env-dup", e2, err)
		r.evidence()
	case 11:
		name := r.variant("role", flag)
		ro, _, err := r.c.CreateRole(r.ctx, coreCanaryAdminID, name, r.variant("role-desc", flag), nil)
		r.observe("pg-role", ro, err)
		r.evidence()
		ro2, _, err := r.c.CreateRole(r.ctx, coreCanaryAdminID, name, "", nil)
		r.observe("pg-role-dup", ro2, err)
		r.evidence()
		gn := r.variant("group", flag)
		g, err := r.c.CreateGroup(r.ctx, coreCanaryAdminID, &CreateGroupRequest{Name: gn, Description: r.meta("group-desc")})
		r.observe("pg-group", g, err)
		r.evidence()
		g2, err := r.c.CreateGroup(r.ctx, coreCanaryAdminID, &CreateGroupRequest{Name: gn})
		r.observe("pg-group-dup", g2, err)
		r.evidence()
	case 12:
		uname := r.variant("user", flag)
		email := fmt.Sprintf("%x@x.io", r.serial)
		password := r.mint("value", canary.Secret).Raw // a secret: must not be quoted anywhere
		u, err := r.c.CreateUser(r.ctx, &CreateUserRequest{Username: uname, Email: email, DisplayName: r.variant("display", flag), Password: password})
		r.observe("pg-user", u, err)
		r.evidence()
		u2, err := r.c.CreateUser(r.ctx, &CreateUserRequest{Username: uname, Email: email, DisplayName: "x", Password: password})
		r.observe("pg-user-dup", u2, err)
		r.evidence()
	case 13:
		desc := r.variant("desc", flag)
		s, err := r.c.UpdateSecret(r.ctx, &UpdateSecretRequest{ID: r.mutable(sel), Value: r.value(), Description: &desc, Metadata: map[string]string{r.variant("metakey", flag): r.variant("meta", flag)}, Tags: []string{r.variant("tag", flag)}, UpdatedBy: "canary-admin", UserID: coreCanaryAdminID})
		r.observe("pg-update", s, err)
		r.evidence()
	case 14:
		if !r.raced { // a pair costs up to the pause limit; once per program is enough
			r.raced = true
			r.pgRacingDuplicate()
		}
	}
}

// corePGWaitReached waits for a paused statement. A request that a validator rejects
// never reaches the statement; that is an outcome of the input, not a hang.
func corePGWaitReached(reached <-chan struct{}) bool {
	select {
	case <-reached:
		return true
	case <-time.After(10 * time.Second):
		return false
	}
}

// pgRacingDuplicate gives two creates of one name a defined order: A stops just
// before its INSERT, B runs to the end, and A then inserts into B's committed row.
// The application's own check passes for both, so the unique index is what fires.
func (r *corePGRun) pgRacingDuplicate() {
	name := r.meta("name")
	reached, release := r.world.Tracer.PauseOn(`INSERT INTO "secret_nodes"`)
	defer release()
	type result struct {
		s   any
		err error
	}
	a := make(chan result, 1)
	go func() {
		s, err := r.c.CreateSecret(r.ctx, &CreateSecretRequest{Name: name, Value: r.value(), ProjectID: r.fx.projectID, EnvironmentID: r.fx.envID, Type: "password", CreatedBy: "canary-admin", OwnerID: coreCanaryAdminID})
		a <- result{s, err}
	}()
	if !corePGWaitReached(reached) {
		release()
		got := <-a
		r.observe("pg-race-a-unpaused", nil, got.err)
		r.evidence()
		return
	}
	s, err := r.c.CreateSecret(r.ctx, &CreateSecretRequest{Name: name, Value: r.value(), ProjectID: r.fx.projectID, EnvironmentID: r.fx.envID, Type: "password", CreatedBy: "canary-admin", OwnerID: coreCanaryAdminID})
	r.observe("pg-race-b", s, err)
	r.evidence()
	release()
	got := <-a
	var v any
	if got.err == nil {
		v = got.s
	}
	r.observe("pg-race-a", v, got.err)
	r.evidence()
}

func (r *corePGRun) apply2(op, sel, flag byte) {
	n := int(op) % (corePGW2OpCount + corePGOpCount)
	if n < corePGW2OpCount {
		r.apply(byte(n), sel, flag)
		r.evidence()
		return
	}
	r.pg(n-corePGW2OpCount, sel, flag)
}

// finishPG is coreCanaryRun.finish with a database dump in place of the raw-file
// scan, keeping every positive control.
func (r *corePGRun) finishPG(leak coreCanaryLeak) {
	DrainBackgroundGoroutines()
	r.fx.controlMetric.Reset()
	if leak != nil {
		leak(r.coreCanaryRun, r.controlValue.Raw)
		DrainBackgroundGoroutines()
	}
	v, err := r.c.GetSecretValueWithPermissionCheck(r.ctx, r.controlID, coreCanaryAdminID)
	if err != nil {
		coreFail("INVALID RUN: control reveal failed: %v", err)
	}
	r.requireHit(coreChanReveal, v, r.controlValue, "the reveal of the control secret")

	log.Print(r.captureProbe.Raw)
	fmt.Fprintln(os.Stdout, r.captureProbe.Raw)
	fmt.Fprintln(os.Stderr, r.captureProbe.Raw)
	r.fx.controlMetric.WithLabelValues(r.captureProbe.Raw).Set(1)
	outputs := r.fx.capture.Drain()
	for _, ch := range []string{canary.ChannelLog, canary.ChannelStdout, canary.ChannelStderr} {
		if !r.outputHasProbe(outputs, ch) {
			coreFail("INVALID RUN: the capture probe did not reach channel %s, so that channel is not being captured", ch)
		}
	}
	r.judge("end-of-run", outputs)

	metrics := r.gatherMetrics()
	r.requireHit(coreChanMetric, metrics, r.captureProbe, "the metrics capture")
	r.judge("end-of-run", []canary.Output{{Channel: coreChanMetric, Data: metrics}})

	dump, err := r.world.Dump()
	if err != nil {
		coreFail("INVALID RUN: database dump: %v", err)
	}
	if !r.anyHit(dump, r.controlName) {
		coreFail("INVALID RUN: the control secret's name is not in any database column, so the database scan sees nothing")
	}
	r.judge("end-of-run", dump)
	r.evidence()
}

func runCorePGProgram(t testing.TB, fx *corePGFixture, dir string, program []byte, allow *canary.Allowlist, leak coreCanaryLeak, shim func(*corePGRun)) (r *corePGRun, invalid string) {
	t.Helper()
	if err := fx.capture.InstallOnce(fx.dir, os.Create); err != nil {
		t.Fatalf("capture: %v", err)
	}
	r = fx.newRun(t, dir, program, allow)
	if shim != nil {
		shim(r)
	}
	pgcanary.RunGuarded(t.Fatalf, "core pg canary program", func() {
		defer func() {
			if p := recover(); p != nil {
				msg, ok := p.(coreInvalid)
				if !ok {
					panic(p)
				}
				invalid = string(msg)
			}
		}()
		r.pgPrologue()
		for i := 0; i+3 <= len(program) && i/3 < coreCanaryMaxOps; i += 3 {
			r.apply2(program[i], program[i+1], program[i+2])
		}
		r.finishPG(leak)
	})
	return r, invalid
}

// corePGCorpus exercises every PG operation with every value shape, and the W2 corpus.
func corePGCorpus() [][]byte {
	var out [][]byte
	out = append(out, coreCanaryCorpus...)
	for kind := range corePGOpCount {
		op := byte(corePGW2OpCount + kind)
		var p []byte
		for flag := range corePGVariantCount {
			p = append(p, op, 0, byte(flag))
		}
		out = append(out, p)
	}
	return out
}

// FuzzCorePGCanaryLeak fails when a canary from a secret-operation program over
// PostgreSQL reaches a channel corePGCanaryAllow does not name.
func FuzzCorePGCanaryLeak(f *testing.F) {
	fx := newCorePGFixture(f, "")
	f.Cleanup(i18n.ResetForTesting)
	for _, p := range corePGCorpus() {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, program []byte) {
		r, invalid := runCorePGProgram(t, fx, t.TempDir(), program, corePGCanaryAllow(), nil, nil)
		if invalid != "" {
			t.Fatal(invalid)
		}
		if len(r.findings) > 0 {
			t.Fatalf("CANARY LEAK (%d):\n%s", len(r.findings), strings.Join(r.findings, "\n"))
		}
	})
}

// corePGWantSQLStates are the server errors the corpus must really produce, so a
// change that stops an input from reaching PostgreSQL fails here instead of quietly
// emptying the fuzz target.
var corePGWantSQLStates = []string{"23505"}

// TestCorePGProvocationsReachServer guards against a vacuous oracle: the corpus
// really makes PostgreSQL raise the classes of error it exists to provoke, every
// outcome the target claims happens, and no finding results from any of it.
func TestCorePGProvocationsReachServer(t *testing.T) {
	fx := newCorePGFixture(t, "")
	allow := corePGCanaryAllow()
	codes := map[string]int{}
	raw := map[string]int{}
	outcomes := map[string]int{}
	for i, p := range corePGCorpus() {
		start := time.Now()
		r, invalid := runCorePGProgram(t, fx, t.TempDir(), p, allow, nil, nil)
		t.Logf("corpus program %d: %d ops in %v", i, len(p)/3, time.Since(start))
		if invalid != "" {
			t.Fatalf("corpus program %d: %s; driver errors: %+v", i, invalid, r.world.Tracer.Drain())
		}
		if len(r.findings) > 0 {
			t.Errorf("corpus program %d (%d bytes):\n%s", i, len(p), strings.Join(r.findings, "\n"))
		}
		for k, n := range r.sqlstates {
			codes[k] += n
		}
		for k, n := range r.rawFields {
			raw[k] += n
		}
		maps.Copy(outcomes, r.outcomes)
	}
	t.Logf("server errors by SQLSTATE: %v", codes)
	t.Logf("canaries seen in raw driver fields (field/class): %v", raw)
	t.Logf("operation outcomes: %v", outcomes)
	for _, code := range corePGWantSQLStates {
		if codes[code] == 0 {
			t.Errorf("the corpus never made the server raise %s; got %v", code, codes)
		}
	}
	if raw["detail/M"] == 0 {
		t.Errorf("no server DETAIL quoted a canary, so the channel the oracle guards was never put under test; got %v", raw)
	}
	if unused := allow.Unused(); len(unused) > 0 {
		t.Logf("allowlist rules no corpus program needed: %v", unused)
	}
}

// corePGDuplicateProgram makes the server raise a real 23505 with the canary in
// DETAIL. It is a duplicate-environment create (op kind 10), not a duplicate
// secret: core.CreateSecret pre-checks name uniqueness at the application layer
// (internal/core/secrets.go) and returns before any INSERT, so a duplicate secret
// never reaches the server. CreateEnvironment has no such pre-check and, unlike
// CreateProject (whose dup error core sanitizes in translateProjectNameError),
// returns the raw driver error up to the caller, so a shim-planted value reaches
// the op-error channel. Flag 6 selects the bare-canary name variant so the first
// create succeeds and only the duplicate fails.
var corePGDuplicateProgram = []byte{byte(corePGW2OpCount + 10), 0, 6}

const corePGShimName = "w7:pg-error-quoting-shim"

// corePGShim installs a gorm callback that does what the harness must catch: it takes
// a real PostgreSQL failure and copies its DETAIL, plus failingValue, into the error
// the storage layer returns, as a careless wrapper would.
func corePGShim(failingValue func(*corePGRun) string) func(*corePGRun) {
	return func(r *corePGRun) {
		fn := func(db *gorm.DB) {
			pg, ok := errors.AsType[*pgconn.PgError](db.Error)
			if !ok {
				return
			}
			extra := ""
			if failingValue != nil {
				extra = " Failing row contains (" + failingValue(r) + ")."
			}
			db.Error = fmt.Errorf("%w DETAIL: %s.%s", db.Error, pg.Detail, extra)
		}
		if err := r.world.DB.Callback().Create().After("gorm:create").Register(corePGShimName, fn); err != nil {
			coreFail("INVALID RUN: installing the shim: %v", err)
		}
	}
}

// TestCorePGCanaryOracleCatchesPlantedLeaks is the red-proof. Every case starts from
// a real PostgreSQL failure; the shims live in this test only.
func TestCorePGCanaryOracleCatchesPlantedLeaks(t *testing.T) {
	fx := newCorePGFixture(t, "")
	// The cleanup is registered on the SUBTEST's t (passed in), not the outer t:
	// registering on the outer t would defer every removal to the end of the whole
	// test, leaving the shim installed through "shim-removed-control-is-silent-again"
	// and making that clean run report the previous shim's planted leak.
	shim := func(t *testing.T, val func(*corePGRun) string) func(*corePGRun) {
		return func(r *corePGRun) {
			corePGShim(val)(r)
			t.Cleanup(func() { _ = r.world.DB.Callback().Create().Remove(corePGShimName) })
		}
	}

	expectFinding := func(t *testing.T, r *corePGRun, invalid, want string) {
		t.Helper()
		if invalid != "" {
			t.Fatal(invalid)
		}
		if !slices.ContainsFunc(r.findings, func(f string) bool { return strings.Contains(f, want) }) {
			t.Fatalf("planted leak %q was not reported; findings: %v", want, r.findings)
		}
	}

	t.Run("no-shim-control-is-silent", func(t *testing.T) {
		r, invalid := runCorePGProgram(t, fx, t.TempDir(), corePGDuplicateProgram, corePGCanaryAllow(), nil, nil)
		if invalid != "" {
			t.Fatal(invalid)
		}
		if len(r.findings) != 0 {
			t.Fatalf("clean run reported: %v", r.findings)
		}
		if r.sqlstates["23505"] == 0 {
			t.Fatalf("the provocation did not reach the server: %v", r.sqlstates)
		}
		if r.rawFields["detail/M"] == 0 {
			t.Fatalf("the provocation did not put a canary in DETAIL: %v", r.rawFields)
		}
	})
	t.Run("shim-quoting-a-stored-column-is-reported", func(t *testing.T) {
		// A stored- canary is a value the caller did not send.
		r, invalid := runCorePGProgram(t, fx, t.TempDir(), corePGDuplicateProgram, corePGCanaryAllow(), nil, shim(t, func(r *corePGRun) string {
			for _, c := range r.scanner.Canaries() {
				if strings.HasPrefix(c.Label, "stored-desc") {
					return c.Raw
				}
			}
			coreFail("INVALID RUN: no stored canary to plant")
			return ""
		}))
		expectFinding(t, r, invalid, "channel=op-error ")
	})
	t.Run("shim-quoting-a-secret-value-is-reported", func(t *testing.T) {
		r, invalid := runCorePGProgram(t, fx, t.TempDir(), corePGDuplicateProgram, corePGCanaryAllow(), nil, shim(t, func(r *corePGRun) string { return r.controlValue.Raw }))
		expectFinding(t, r, invalid, "channel=op-error ")
	})
	t.Run("shim-removed-control-is-silent-again", func(t *testing.T) {
		r, invalid := runCorePGProgram(t, fx, t.TempDir(), corePGDuplicateProgram, corePGCanaryAllow(), nil, nil)
		if invalid != "" {
			t.Fatal(invalid)
		}
		if len(r.findings) != 0 {
			t.Fatalf("clean run after the shim was removed reported: %v", r.findings)
		}
	})
	for _, tc := range []struct {
		name, want string
		leak       coreCanaryLeak
	}{
		{"stdlib-log", canary.ChannelLog, func(_ *coreCanaryRun, v string) { log.Print("oops " + v) }},
		{"slog", canary.ChannelSlog, func(_ *coreCanaryRun, v string) { slog.Info("oops", "v", v) }},
		{"stdout", canary.ChannelStdout, func(_ *coreCanaryRun, v string) { fmt.Fprintln(os.Stdout, v) }},
		{"stderr", canary.ChannelStderr, func(_ *coreCanaryRun, v string) { fmt.Fprintln(os.Stderr, v) }},
		{"metric-label", coreChanMetric, func(r *coreCanaryRun, v string) { r.fx.controlMetric.WithLabelValues(v).Set(1) }},
		{"db-cell", canary.ChannelDBPrefix + "w7_redproof", func(r *coreCanaryRun, v string) {
			if err := r.db.Exec("CREATE TABLE IF NOT EXISTS w7_redproof (x TEXT)").Error; err != nil {
				coreFail("INVALID RUN: %v", err)
			}
			if err := r.db.Exec("INSERT INTO w7_redproof (x) VALUES (?)", v).Error; err != nil {
				coreFail("INVALID RUN: %v", err)
			}
		}},
	} {
		t.Run("channel-"+tc.name, func(t *testing.T) {
			r, invalid := runCorePGProgram(t, fx, t.TempDir(), []byte{0, 0, 0}, corePGCanaryAllow(), tc.leak, nil)
			expectFinding(t, r, invalid, "channel="+tc.want+" ")
		})
	}
	t.Run("encodings", func(t *testing.T) {
		probe := canary.New("value-1", canary.Secret, []byte{0, 0, 0}, false)
		for _, v := range probe.Variants() {
			r, invalid := runCorePGProgram(t, fx, t.TempDir(), []byte{0, 0, 0}, corePGCanaryAllow(), func(r *coreCanaryRun, _ string) {
				log.Print("x ", string(canaryVariantOf(r.controlValue, v.Name)), " y")
			}, nil)
			if invalid != "" || len(r.findings) == 0 {
				t.Errorf("encoding %s not reported (invalid=%q findings=%d)", v.Name, invalid, len(r.findings))
			}
		}
	})
}

// TestCorePGSerializationFailureNoCanary drives a concurrent pair to a real 40001
// under SERIALIZABLE and checks that the serialization-failure error text carries no
// canary even when the rows being written do.
//
// No product operation reaches a 40001, so this cannot be driven through core:
//   - UpdateSecret with a Value inserts a new secret_versions row, so a concurrent
//     pair collides on the version unique index (23505) before SSI can act.
//   - A description-only UpdateSecret reads the row OUTSIDE its write transaction, so
//     the transaction's snapshot is taken at the UPDATE itself — after the other
//     writer has committed — and the write succeeds cleanly with no conflict.
//   - The product runs exclusively at READ COMMITTED; 40001 never arises there.
//
// This test therefore drives the 40001 directly at the driver, over the world's
// traced native pool (opened with default_transaction_isolation = serializable), with
// two transactions that each read the seeded row and then write it: the read-write
// dependency makes SERIALIZABLE abort the second writer. It proves the harness records
// a serialization failure and that PostgreSQL's 40001 message quotes no value, so the
// oracle's channels stay clean. It is a driver-level capability check, not a claim
// that the product can produce a 40001.
func TestCorePGSerializationFailureNoCanary(t *testing.T) {
	fx := newCorePGFixture(t, "serializable")
	r, invalid := runCorePGProgram(t, fx, t.TempDir(), nil, corePGCanaryAllow(), nil, nil)
	if invalid != "" {
		t.Fatal(invalid)
	}
	r.world.Tracer.Drain()
	id := r.secrets[1]
	// Canaries written into the rows the pair touches; registered so the scan below
	// would catch either one if the 40001 error quoted it.
	descA := r.meta("serial-a")
	descB := r.meta("serial-b")

	ctx := r.ctx
	ca, err := r.world.Pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire A: %v", err)
	}
	defer ca.Release()
	cb, err := r.world.Pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire B: %v", err)
	}
	defer cb.Release()

	// Both pool connections default to SERIALIZABLE (set in pgcanary.Open).
	txA, err := ca.Begin(ctx)
	if err != nil {
		t.Fatalf("begin A: %v", err)
	}
	defer func() { _ = txA.Rollback(ctx) }()
	txB, err := cb.Begin(ctx)
	if err != nil {
		t.Fatalf("begin B: %v", err)
	}
	defer func() { _ = txB.Rollback(ctx) }()

	var scratch string
	if err := txA.QueryRow(ctx, `SELECT description FROM secret_nodes WHERE id = $1`, id).Scan(&scratch); err != nil {
		t.Fatalf("read A: %v", err)
	}
	if err := txB.QueryRow(ctx, `SELECT description FROM secret_nodes WHERE id = $1`, id).Scan(&scratch); err != nil {
		t.Fatalf("read B: %v", err)
	}
	if _, err := txA.Exec(ctx, `UPDATE secret_nodes SET description = $1 WHERE id = $2`, descA, id); err != nil {
		t.Fatalf("write A: %v", err)
	}
	if err := txA.Commit(ctx); err != nil {
		t.Fatalf("commit A: %v", err)
	}
	// B now writes a row A has already modified and committed: SERIALIZABLE aborts it.
	_, bWriteErr := txB.Exec(ctx, `UPDATE secret_nodes SET description = $1 WHERE id = $2`, descB, id)
	bCommitErr := txB.Commit(ctx)

	entries := r.world.Tracer.Drain()
	codes := map[string]int{}
	for _, e := range entries {
		codes[e.SQLState]++
	}
	t.Logf("SQLSTATEs across the pair: %v (B write err: %v, B commit err: %v)", codes, bWriteErr, bCommitErr)
	if codes["40001"] == 0 {
		t.Fatalf("the pair did not produce a serialization failure: %v", codes)
	}
	// The serialization-failure error must not quote either written value. Scan the
	// raw driver fields (message, detail, hint, where, text) the tracer recorded.
	for _, o := range pgcanary.RawOutputs(entries) {
		if hits := r.scanner.Scan(o.Channel, o.Data); len(hits) != 0 {
			t.Fatalf("the serialization failure quoted a canary on %s: %v", o.Channel, hits)
		}
	}
	if len(r.findings) != 0 {
		t.Fatalf("serialization failure surfaced a canary:\n%s", strings.Join(r.findings, "\n"))
	}
}
