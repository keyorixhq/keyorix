package core

// secret_ops_canary_fuzz_test.go -- FuzzCoreSecretOpsCanaryLeak.
//
// Drives a fuzzer-chosen sequence of secret operations straight against KeyorixCore
// (create, update, rotate, rollback, delete, share, revoke, reads, exports and
// deliberately invalid requests) with a unique canary in every value, name,
// description, tag and metadata field, and asserts that no value canary reaches any
// output channel outside coreCanaryAllow.
//
// The HTTP/gRPC canary fuzzers (server/http) only see what survives the transport
// layer. This one sees what core itself returns: an error string wrapped three
// times that a handler later replaces with a generic message is invisible from
// outside, and is still what a caller inside the process logs.
//
// Each execution copies a prebuilt database into its own t.TempDir, so nothing
// carries over between executions and a saved input replays alone.
//
// Channels: returned errors (%v and %+v), JSON of returned values, stdlib log and
// slog, os.Stdout and os.Stderr, exported files, Prometheus DefaultGatherer, every
// database column and the raw database file. Every iteration proves its own
// capture is alive (assertCoreCanaryControls); a run where it is not fails as
// INVALID, not as a pass.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/prometheus/client_golang/prometheus"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/canary"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
)

const (
	coreCanaryAdminID     = 1
	coreCanaryRecipientID = 2
	coreCanaryOutsiderID  = 3

	// Channels the harness records itself; the process-wide ones are in the canary package.
	coreChanError  = "op-error"
	coreChanResult = "op-result"
	coreChanReveal = "reveal"
	coreChanExport = "export-file"
	coreChanRawDB  = "raw-db-file"
	coreChanMetric = "metrics"

	coreCanaryMaxOps = 16
)

// coreCanaryAllow lists every place a canary may legitimately appear. Value canaries
// have one: the explicit reveal. Metadata canaries are stored and returned to the
// caller by design; a metadata canary in a log line, standard output or a metric is
// still a finding.
func coreCanaryAllow() *canary.Allowlist {
	return canary.NewAllowlist(
		canary.Rule{ID: "value-reveal", Channel: coreChanReveal, Origin: "read-value", Why: "GetSecretValueWithPermissionCheck is the authorised read"},
		canary.Rule{ID: "meta-result", Channel: coreChanResult, MetadataOnly: true, Why: "names, descriptions, tags and metadata are returned by the operations that manage them"},
		canary.Rule{ID: "meta-error", Channel: coreChanError, MetadataOnly: true, Why: "a rejected non-secret field (an export format) is named in the error returned to the caller who sent it"},
		canary.Rule{ID: "meta-db", Channel: canary.ChannelDBPrefix + "*", MetadataOnly: true, Why: "stored in plaintext by design"},
		canary.Rule{ID: "meta-rawdb", Channel: coreChanRawDB, MetadataOnly: true, Why: "stored in plaintext by design"},
	)
}

// coreCanaryFixture is built once per fuzz worker: a migrated database file that
// each execution copies, and the PBKDF2-derived encryption service, which is too
// slow to derive per execution and holds no per-execution state.
type coreCanaryFixture struct {
	dir, template string
	enc           *encryption.Service
	projectID     uint
	envID         uint
	capture       *canary.Capture
	controlMetric *prometheus.GaugeVec
}

func newCoreCanaryFixture(tb testing.TB) *coreCanaryFixture {
	tb.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		tb.Fatalf("i18n: %v", err)
	}
	dir, err := os.MkdirTemp("", "core-canary-fuzz-*")
	if err != nil {
		tb.Fatalf("mkdir: %v", err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(dir) })

	fx := &coreCanaryFixture{dir: dir, template: filepath.Join(dir, "template.db")}
	db := openCoreCanaryDB(tb, fx.template)
	fuzzworld.Bootstrap(tb, db)
	world := &fuzzworld.World{Backend: fuzzworld.BackendSQLite, DB: db}
	if err := world.Reset(coreSeqResetTables); err != nil {
		tb.Fatalf("reset: %v", err)
	}
	fx.seed(tb, db)
	sqlDB, err := db.DB()
	if err != nil {
		tb.Fatalf("db handle: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		tb.Fatalf("close template: %v", err)
	}

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, dir)
	if err := enc.Initialize("core-canary-fuzz-passphrase"); err != nil {
		tb.Fatalf("encryption: %v", err)
	}
	fx.enc = enc

	fx.capture = canary.NewCapture()
	tb.Cleanup(fx.capture.Uninstall)

	fx.controlMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "keyorix_core_canary_control", Help: "Harness control for the metrics capture."}, []string{"v"})
	if err := prometheus.Register(fx.controlMetric); err != nil {
		tb.Fatalf("register control metric: %v", err)
	}
	tb.Cleanup(func() { prometheus.Unregister(fx.controlMetric) })
	return fx
}

func (fx *coreCanaryFixture) seed(tb testing.TB, db *gorm.DB) {
	tb.Helper()
	ctx := context.Background()
	ls := store.NewLocalStorage(db)
	proj, err := ls.CreateProject(ctx, &models.Project{Name: "canary-proj"})
	if err != nil {
		tb.Fatalf("project: %v", err)
	}
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	if err != nil {
		tb.Fatalf("environment: %v", err)
	}
	fx.projectID, fx.envID = proj.ID, env.ID
	for _, v := range []any{
		&models.Role{ID: 900, Name: "canary-admin", NameFolded: "canary-admin", BypassesPermissionChecks: true},
		&models.User{ID: coreCanaryAdminID, Username: "canary-admin", UsernameFolded: "canary-admin", Email: "a@x.io", EmailFolded: "a@x.io", IsActive: true},
		&models.User{ID: coreCanaryRecipientID, Username: "canary-recipient", UsernameFolded: "canary-recipient", Email: "r@x.io", EmailFolded: "r@x.io", IsActive: true},
		&models.User{ID: coreCanaryOutsiderID, Username: "canary-outsider", UsernameFolded: "canary-outsider", Email: "o@x.io", EmailFolded: "o@x.io", IsActive: true},
		&models.UserRole{UserID: coreCanaryAdminID, RoleID: 900},
		// Sharing requires both ends to be members of the project.
		&models.Role{ID: 901, Name: "canary-reader", NameFolded: "canary-reader"},
		&models.Permission{ID: 900, Name: "secrets.read", Resource: "secrets", Action: "read"},
		&models.RolePermission{RoleID: 901, PermissionID: 900},
		&models.UserRole{UserID: coreCanaryAdminID, RoleID: 901, ProjectID: proj.ID},
		&models.UserRole{UserID: coreCanaryRecipientID, RoleID: 901, ProjectID: proj.ID},
	} {
		if err := db.Create(v).Error; err != nil {
			tb.Fatalf("seed %T: %v", v, err)
		}
	}
}

func openCoreCanaryDB(tb testing.TB, path string) *gorm.DB {
	tb.Helper()
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		tb.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		tb.Fatalf("db handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	return db
}

// coreCanaryLeak is a planted leak for the red-proof: after the program runs, it
// writes one canary into one channel through that channel's real mechanism.
type coreCanaryLeak func(r *coreCanaryRun, value string)

// coreCanaryRun is one execution.
type coreCanaryRun struct {
	fx       *coreCanaryFixture
	c        *KeyorixCore
	db       *gorm.DB
	dir      string
	seed     []byte
	scanner  *canary.Scanner
	allow    *canary.Allowlist
	findings []string
	serial   int
	ctx      context.Context

	controlID    uint
	controlValue canary.Canary
	controlName  canary.Canary
	captureProbe canary.Canary
	secrets      []uint
	names        []string
	shares       []uint
	secretsMade  int
	fault        *faultstorage.FaultyStorage // pass-through; only the red-proof arms it
	outcomes     map[string]int              // "<origin>:ok" or "<origin>:err"
}

func (fx *coreCanaryFixture) newRun(t testing.TB, dir string, seed []byte, allow *canary.Allowlist) *coreCanaryRun {
	t.Helper()
	dbPath := filepath.Join(dir, "world.db")
	data, err := os.ReadFile(fx.template)
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	if err := os.WriteFile(dbPath, data, 0o600); err != nil {
		t.Fatalf("write world db: %v", err)
	}
	db := openCoreCanaryDB(t, dbPath)
	t.Cleanup(func() {
		DrainBackgroundGoroutines()
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	c := NewKeyorixCore(faulty)
	c.SetSecretValueEncryptor(fx.enc)
	if !c.SecretValueEncryptionActive() {
		t.Fatalf("INVALID RUN: encryption inactive, every at-rest check would be vacuous")
	}
	c.SetAuthEncryptor(fx.enc)
	fx.capture.Drain() // output of anything before this execution belongs to no canary
	r := &coreCanaryRun{fx: fx, c: c, db: db, dir: dir, seed: seed, scanner: canary.NewScanner(), allow: allow, ctx: context.Background(), fault: faulty, outcomes: map[string]int{}}
	r.captureProbe = r.mint("capture-probe", canary.Metadata)
	return r
}

func (r *coreCanaryRun) mint(prefix string, class canary.Class) canary.Canary {
	r.serial++
	c := canary.New(fmt.Sprintf("%s-%d", prefix, r.serial), class, r.seed, r.serial%3 == 0)
	r.scanner.Add(c)
	return c
}

func (r *coreCanaryRun) value() []byte { return []byte(r.mint("value", canary.Secret).Raw) }

// meta mints a metadata canary with the plain charset, so names pass validation
// and the operations that use them run; hostile values go through invalidCreate.
func (r *coreCanaryRun) meta(prefix string) string {
	r.serial++
	c := canary.New(fmt.Sprintf("%s-%d", prefix, r.serial), canary.Metadata, r.seed, false)
	r.scanner.Add(c)
	return c.Raw
}

// judge scans outputs and files every hit no rule permits as a finding.
func (r *coreCanaryRun) judge(origin string, outputs []canary.Output) {
	for _, h := range r.scanner.ScanAll(outputs) {
		if strings.HasPrefix(h.Label, "capture-probe") {
			continue
		}
		if r.allow.Permit(h, origin) == "" {
			r.findings = append(r.findings, fmt.Sprintf("origin=%s %s", origin, h))
		}
	}
}

// observe records one operation's error and result and scans everything the
// operation produced.
func (r *coreCanaryRun) observe(origin string, result any, err error) {
	if err != nil {
		r.fx.capture.Record(coreChanError, fmt.Appendf(nil, "%v\n%+v\n", err, err))
		r.outcomes[origin+":err"]++
	} else {
		r.outcomes[origin+":ok"]++
	}
	if result != nil {
		data, mErr := json.Marshal(result)
		if mErr != nil {
			coreFail("INVALID RUN: marshal %s result: %v", origin, mErr)
		}
		r.fx.capture.Record(coreChanResult, data)
	}
	DrainBackgroundGoroutines()
	r.judge(origin, r.fx.capture.Drain())
}

func (r *coreCanaryRun) create(value []byte, name string) (*models.SecretNode, error) {
	return r.c.CreateSecret(r.ctx, &CreateSecretRequest{
		Name: name, Value: value, ProjectID: r.fx.projectID, EnvironmentID: r.fx.envID,
		Type: "password", CreatedBy: "canary-admin", OwnerID: coreCanaryAdminID,
		Description: r.meta("desc"),
		Metadata:    map[string]string{"owner-note": r.meta("meta")},
		Tags:        []string{r.meta("tag")},
	})
}

// target picks a secret for a read. mutable picks one for a write, never the
// control secret, whose value the end-of-run reveal asserts.
func (r *coreCanaryRun) target(sel byte) uint { return r.secrets[int(sel)%len(r.secrets)] }

func (r *coreCanaryRun) mutable(sel byte) uint {
	return r.secrets[1+int(sel)%(len(r.secrets)-1)]
}

// prologue creates the control secret every iteration reveals and one secret the
// mutating operations always have available.
func (r *coreCanaryRun) prologue() {
	r.controlValue = r.mint("value", canary.Secret)
	r.controlName = r.mint("name", canary.Metadata)
	if r.controlName.Hostile {
		r.controlName = canary.New(r.controlName.Label, canary.Metadata, r.seed, false)
		r.scanner.Add(r.controlName)
	}
	s, err := r.create([]byte(r.controlValue.Raw), r.controlName.Raw)
	if err != nil || s == nil {
		coreFail("INVALID RUN: control secret was not created: %v", err)
	}
	r.controlID = s.ID
	r.secrets = append(r.secrets, s.ID)
	r.observe("prologue", s, nil)
	second, err := r.create(r.value(), r.meta("name"))
	if err != nil || second == nil {
		coreFail("INVALID RUN: second secret was not created: %v", err)
	}
	r.secrets = append(r.secrets, second.ID)
	r.observe("prologue", second, nil)
}

func (r *coreCanaryRun) apply(op, sel, flag byte) {
	id := r.target(sel)
	switch op % 14 {
	case 0:
		r.opCreate()
	case 1:
		desc := r.meta("desc")
		s, err := r.c.UpdateSecret(r.ctx, &UpdateSecretRequest{
			ID: r.mutable(sel), Value: r.value(), Description: &desc, Metadata: map[string]string{"k": r.meta("meta")},
			Tags: []string{r.meta("tag")}, UpdatedBy: "canary-admin", UserID: coreCanaryAdminID,
		})
		r.observe("update", s, err)
	case 2:
		s, err := r.c.RotateSecret(r.ctx, r.mutable(sel), r.value(), coreCanaryAdminID, "canary-admin")
		r.observe("rotate", s, err)
	case 3:
		s, err := r.c.RollbackSecret(r.ctx, r.mutable(sel), int(flag%3)+1, coreCanaryAdminID, "canary-admin")
		r.observe("rollback", s, err)
	case 4:
		// Deleting the last mutable secret would leave the writers nothing to target.
		if len(r.secrets) > 2 {
			victim := r.mutable(sel)
			r.observe("delete", nil, r.c.DeleteSecret(r.ctx, victim))
			r.secrets = removeUint(r.secrets, victim)
		}
	case 5:
		s, err := r.c.ShareSecret(r.ctx, &ShareSecretRequest{SecretID: id, RecipientID: coreCanaryRecipientID, Permission: "read", SharedBy: coreCanaryAdminID})
		if s != nil {
			r.shares = append(r.shares, s.ID)
		}
		r.observe("share", s, err)
	case 6:
		if len(r.shares) == 0 {
			return
		}
		r.observe("revoke-share", nil, r.c.RevokeShare(r.ctx, r.shares[int(sel)%len(r.shares)], coreCanaryAdminID))
	case 7:
		list, n, err := r.c.ListSecrets(r.ctx, &storage.SecretFilter{ProjectID: &r.fx.projectID, EnvironmentID: &r.fx.envID})
		r.observe("list", struct {
			List  []*models.SecretNode
			Total int64
		}{list, n}, err)
		s, err := r.c.GetSecret(r.ctx, id)
		r.observe("get-metadata", s, err)
	case 8:
		r.opRead(id, flag)
	case 9:
		format := ExportFormatCSV
		if flag%2 == 1 {
			format = ExportFormatJSON
		}
		data, _, err := r.c.ExportSecretAccessLog(r.ctx, ActorTypeUser, coreCanaryAdminID, id, format)
		r.fx.capture.Record(coreChanExport, data)
		r.observe("export-access-log", nil, err)
	case 10:
		r.opEvidence()
	case 11:
		versions, err := r.c.GetSecretVersions(r.ctx, id)
		r.observe("versions", versions, err)
	case 12:
		r.opInvalid(id, flag)
	case 13:
		res, err := r.c.SearchAuditLogs(r.ctx, AuditSearchRequest{ResourceType: "secret"})
		r.observe("audit-search", res, err)
	}
}

func (r *coreCanaryRun) opCreate() {
	if r.secretsMade >= 6 {
		return
	}
	name := r.meta("name")
	s, err := r.create(r.value(), name)
	if s != nil {
		r.secrets = append(r.secrets, s.ID)
		r.names = append(r.names, name)
		r.secretsMade++
	}
	r.observe("create", s, err)
}

func (r *coreCanaryRun) opRead(id uint, flag byte) {
	switch flag % 3 {
	case 0: // the owner: the one allowlisted channel
		v, err := r.c.GetSecretValueWithPermissionCheck(r.ctx, id, coreCanaryAdminID)
		r.fx.capture.Record(coreChanReveal, v)
		r.observe("read-value", nil, err)
	case 1: // a stranger: denied, so the value may not appear anywhere
		v, err := r.c.GetSecretValueWithPermissionCheck(r.ctx, id, coreCanaryOutsiderID)
		r.observe("read-value-denied", v, err)
		if err == nil {
			r.findings = append(r.findings, fmt.Sprintf("origin=read-value-denied the outsider read secret %d (authorization bug, not a leak channel)", id))
		}
	default: // a share recipient: revealed to them if the share is live, else denied
		v, err := r.c.GetSecretValueWithPermissionCheck(r.ctx, id, coreCanaryRecipientID)
		r.fx.capture.Record(coreChanReveal, v)
		r.observe("read-value", nil, err)
	}
}

func (r *coreCanaryRun) opEvidence() {
	dir := filepath.Join(r.dir, "evidence")
	res, err := r.c.ExportComplianceEvidence(r.ctx, dir)
	r.observe("export-evidence", res, err)
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		return // err above says why nothing was written, and it was scanned
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			coreFail("INVALID RUN: read evidence file: %v", err)
		}
		r.fx.capture.Record(coreChanExport, data)
	}
	r.observe("export-evidence", nil, nil)
}

// opInvalid sends a request core must reject, with a value canary in it. Rejection
// paths are where a validation error tends to quote its input.
func (r *coreCanaryRun) opInvalid(id uint, flag byte) {
	hostile := r.mint("value", canary.Secret)
	// Only Value holds a secret. A hostile canary in Name or Type is metadata:
	// core accepts and stores those fields, so it is checked as metadata.
	bad := canary.New(fmt.Sprintf("name-%d", r.serial), canary.Metadata, r.seed, true)
	r.scanner.Add(bad)
	req := &CreateSecretRequest{Name: r.meta("name"), Value: []byte(hostile.Raw), ProjectID: r.fx.projectID, EnvironmentID: r.fx.envID, Type: "password", CreatedBy: "canary-admin", OwnerID: coreCanaryAdminID}
	switch flag % 8 {
	case 0: // a hostile name
		req.Name = bad.Raw
	case 1:
		req.Name = ""
	case 2: // an unknown type
		req.Type = bad.Raw
	case 3:
		req.ProjectID = 987654
	case 4:
		req.EnvironmentID = 987654
	case 5: // a name far over the length limit
		req.Name = strings.Repeat(r.meta("name"), 40)
	case 6: // a duplicate of the control secret's name
		req.Name = r.controlName.Raw
	case 7: // an empty value with a hostile description
		req.Value = nil
		req.Description = bad.Raw
	}
	s, err := r.c.CreateSecret(r.ctx, req)
	if s != nil && req.ProjectID == r.fx.projectID {
		r.secrets = append(r.secrets, s.ID)
	}
	r.observe("invalid-create", s, err)

	switch flag % 4 {
	case 0:
		s, err := r.c.UpdateSecret(r.ctx, &UpdateSecretRequest{ID: 987654, Value: []byte(hostile.Raw), UpdatedBy: "canary-admin", UserID: coreCanaryAdminID})
		r.observe("invalid-update", s, err)
	case 1:
		s, err := r.c.RotateSecret(r.ctx, 987654, []byte(hostile.Raw), coreCanaryAdminID, "canary-admin")
		r.observe("invalid-rotate", s, err)
	case 2:
		s, err := r.c.RotateSecret(r.ctx, r.mutable(flag), nil, coreCanaryAdminID, "canary-admin")
		r.observe("invalid-rotate-empty", s, err)
	case 3:
		data, _, err := r.c.ExportSecretAccessLog(r.ctx, ActorTypeUser, coreCanaryAdminID, id, bad.Raw)
		r.fx.capture.Record(coreChanExport, data)
		r.observe("invalid-export-format", nil, err)
	}
}

// finish scans the persistent channels and asserts the controls.
func (r *coreCanaryRun) finish(leak coreCanaryLeak) {
	DrainBackgroundGoroutines()
	r.fx.controlMetric.Reset()
	if leak != nil {
		leak(r, r.controlValue.Raw)
		DrainBackgroundGoroutines()
	}

	// Controls: the reveal, the probe through every capture, and a metadata row in
	// the database. Each is the proof that the matching channel can show a canary.
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

	sqlDB, err := r.db.DB()
	if err != nil {
		coreFail("INVALID RUN: db handle: %v", err)
	}
	dump, err := canary.DumpSQLite(sqlDB)
	if err != nil {
		coreFail("INVALID RUN: database dump: %v", err)
	}
	if !r.anyHit(dump, r.controlName) {
		coreFail("INVALID RUN: the control secret's name is not in any database column, so the database scan sees nothing")
	}
	r.judge("end-of-run", dump)

	raw, err := os.ReadFile(filepath.Join(r.dir, "world.db"))
	if err != nil {
		coreFail("INVALID RUN: raw database read: %v", err)
	}
	r.judge("end-of-run", []canary.Output{{Channel: coreChanRawDB, Data: raw}})
}

func (r *coreCanaryRun) requireHit(channel string, data []byte, c canary.Canary, what string) {
	if !r.hasCanary(r.scanner.Scan(channel, data), c) {
		coreFail("INVALID RUN: %s did not show its canary: the oracle would be empty", what)
	}
}

func (r *coreCanaryRun) anyHit(outputs []canary.Output, c canary.Canary) bool {
	return r.hasCanary(r.scanner.ScanAll(outputs), c)
}

func (r *coreCanaryRun) hasCanary(hits []canary.Hit, c canary.Canary) bool {
	for _, h := range hits {
		if h.Label == c.Label {
			return true
		}
	}
	return false
}

func (r *coreCanaryRun) outputHasProbe(outputs []canary.Output, channel string) bool {
	for _, o := range outputs {
		if o.Channel == channel && r.hasCanary(r.scanner.Scan(channel, o.Data), r.captureProbe) {
			return true
		}
	}
	return false
}

func (r *coreCanaryRun) gatherMetrics() []byte {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		coreFail("INVALID RUN: gather metrics: %v", err)
	}
	var b strings.Builder
	for _, f := range families {
		fmt.Fprintln(&b, f.String())
	}
	return []byte(b.String())
}

func removeUint(s []uint, v uint) []uint {
	out := s[:0]
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// coreInvalid is the panic value of coreFail.
type coreInvalid string

// coreFail aborts the program. It panics instead of calling t.Fatalf because the
// program runs on fuzzutil.Guard's goroutine, where FailNow does not stop the test.
func coreFail(format string, args ...any) { panic(coreInvalid(fmt.Sprintf(format, args...))) }

// runCoreCanaryProgram executes one program and returns the findings, or the
// reason the run proved nothing.
func runCoreCanaryProgram(t testing.TB, fx *coreCanaryFixture, dir string, program []byte, allow *canary.Allowlist, leak coreCanaryLeak) (r *coreCanaryRun, invalid string) {
	t.Helper()
	if err := fx.capture.InstallOnce(fx.dir, os.Create); err != nil {
		t.Fatalf("capture: %v", err)
	}
	r = fx.newRun(t, dir, program, allow)
	canary.RunGuarded(t.Fatalf, "core canary program", func() {
		defer func() {
			if p := recover(); p != nil {
				msg, ok := p.(coreInvalid)
				if !ok {
					panic(p)
				}
				invalid = string(msg)
			}
		}()
		r.prologue()
		for i := 0; i+3 <= len(program) && i/3 < coreCanaryMaxOps; i += 3 {
			r.apply(program[i], program[i+1], program[i+2])
		}
		r.finish(leak)
	})
	return r, invalid
}

func addCoreCanarySeeds(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1, 0, 0, 2, 0, 0, 3, 0, 0, 8, 0, 0})
	f.Add([]byte{0, 0, 0, 5, 1, 0, 8, 1, 2, 6, 0, 0, 8, 1, 2, 4, 1, 0})
	f.Add([]byte{12, 0, 0, 12, 0, 1, 12, 0, 2, 12, 0, 3, 12, 0, 4, 12, 0, 5, 12, 0, 6, 12, 0, 7})
	f.Add([]byte{9, 0, 0, 9, 0, 1, 10, 0, 0, 11, 0, 0, 13, 0, 0, 7, 0, 0, 8, 0, 1})
	f.Add([]byte{2, 0, 0, 2, 0, 0, 3, 0, 1, 11, 0, 0, 8, 0, 3, 13, 0, 0})
}

// FuzzCoreSecretOpsCanaryLeak fails when a canary from a secret-operation sequence
// reaches a channel coreCanaryAllow does not name.
func FuzzCoreSecretOpsCanaryLeak(f *testing.F) {
	fx := newCoreCanaryFixture(f)
	f.Cleanup(i18n.ResetForTesting)
	addCoreCanarySeeds(f)
	f.Fuzz(func(t *testing.T, program []byte) {
		r, invalid := runCoreCanaryProgram(t, fx, t.TempDir(), program, coreCanaryAllow(), nil)
		if invalid != "" {
			t.Fatal(invalid)
		}
		if len(r.findings) > 0 {
			t.Fatalf("CANARY LEAK (%d):\n%s", len(r.findings), strings.Join(r.findings, "\n"))
		}
	})
}

// coreCanaryCorpus is the seed corpus as a list, for the tests below. The first
// program of addCoreCanarySeeds is empty and adds nothing here.
var coreCanaryCorpus = [][]byte{
	{0, 0, 0, 1, 0, 0, 2, 0, 0, 3, 0, 0, 8, 0, 0},
	{0, 0, 0, 5, 1, 0, 8, 1, 2, 6, 0, 0, 8, 1, 2, 4, 1, 0},
	{12, 0, 0, 12, 0, 1, 12, 0, 2, 12, 0, 3, 12, 0, 4, 12, 0, 5, 12, 0, 6, 12, 0, 7},
	{9, 0, 0, 9, 0, 1, 10, 0, 0, 11, 0, 0, 13, 0, 0, 7, 0, 0, 8, 0, 1},
	{2, 0, 0, 2, 0, 0, 3, 0, 1, 11, 0, 0, 8, 0, 3, 13, 0, 0},
}

// TestCoreCanaryOperationsTakeEffect guards against a vacuous oracle: every
// operation the fuzz target claims to exercise succeeds somewhere in the corpus,
// the invalid requests are really rejected, and every allowlist rule is needed.
func TestCoreCanaryOperationsTakeEffect(t *testing.T) {
	fx := newCoreCanaryFixture(t)
	allow := coreCanaryAllow()
	got := map[string]int{}
	for _, program := range coreCanaryCorpus {
		r, invalid := runCoreCanaryProgram(t, fx, t.TempDir(), program, allow, nil)
		if invalid != "" {
			t.Fatal(invalid)
		}
		if len(r.findings) > 0 {
			t.Fatalf("corpus program %v: %s", program, strings.Join(r.findings, "\n"))
		}
		for k, n := range r.outcomes {
			got[k] += n
		}
	}
	for _, want := range []string{
		"create:ok", "update:ok", "rotate:ok", "rollback:ok", "share:ok", "revoke-share:ok", "list:ok",
		"get-metadata:ok", "versions:ok", "read-value:ok", "read-value-denied:err", "export-access-log:ok",
		"export-evidence:ok", "audit-search:ok", "invalid-create:err", "invalid-update:err", "invalid-rotate:err",
		"invalid-export-format:err",
	} {
		if got[want] == 0 {
			t.Errorf("operation outcome %q never happened in the corpus; got %v", want, got)
		}
	}
	if unused := allow.Unused(); len(unused) > 0 {
		t.Errorf("allowlist rules no corpus program needed: %v", unused)
	}
}

// TestCoreCanaryOracleCatchesPlantedLeaks is the red-proof. Each case writes the
// control value into one channel through that channel's real mechanism and asserts
// the oracle reports it. Nothing outside this file changes.
func TestCoreCanaryOracleCatchesPlantedLeaks(t *testing.T) {
	fx := newCoreCanaryFixture(t)
	program := []byte{0, 0, 0}
	cases := []struct {
		name, wantChannel string
		leak              coreCanaryLeak
	}{
		{"stdlib-log", canary.ChannelLog, func(_ *coreCanaryRun, v string) { log.Print("oops " + v) }},
		{"slog", canary.ChannelSlog, func(_ *coreCanaryRun, v string) { slog.Info("oops", "v", v) }},
		{"stdout", canary.ChannelStdout, func(_ *coreCanaryRun, v string) { fmt.Fprintln(os.Stdout, v) }},
		{"stderr", canary.ChannelStderr, func(_ *coreCanaryRun, v string) { fmt.Fprintln(os.Stderr, v) }},
		{"error-string", coreChanError, func(r *coreCanaryRun, v string) { r.observe("planted", nil, fmt.Errorf("wrapped: %s", v)) }},
		{"driver-error-through-core", coreChanError, func(r *coreCanaryRun, v string) {
			r.fault.Arm(&faultstorage.FaultSpec{Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError, Err: fmt.Errorf("sql: Scan error on column value: %q", v)})
			s, err := r.c.RotateSecret(r.ctx, r.secrets[1], r.value(), coreCanaryAdminID, "canary-admin")
			r.fault.Arm(nil)
			r.observe("planted", s, err)
		}},
		{"result-json", coreChanResult, func(r *coreCanaryRun, v string) { r.observe("planted", map[string]string{"x": v}, nil) }},
		{"export-file", coreChanExport, func(r *coreCanaryRun, v string) {
			r.fx.capture.Record(coreChanExport, []byte(v))
			r.observe("planted", nil, nil)
		}},
		{"metric-label", coreChanMetric, func(r *coreCanaryRun, v string) { r.fx.controlMetric.WithLabelValues(v).Set(1) }},
		{"db-cell", canary.ChannelDBPrefix + "redproof.x", plantCoreCanaryRow},
		{"raw-db-file", coreChanRawDB, plantCoreCanaryRow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, invalid := runCoreCanaryProgram(t, fx, t.TempDir(), program, coreCanaryAllow(), tc.leak)
			if invalid != "" {
				t.Fatal(invalid)
			}
			want := "channel=" + tc.wantChannel + " "
			for _, f := range r.findings {
				if strings.Contains(f, want) {
					return
				}
			}
			t.Fatalf("planted leak on %s was not reported; findings: %v", tc.wantChannel, r.findings)
		})
	}

	t.Run("no-leak-is-clean", func(t *testing.T) {
		r, invalid := runCoreCanaryProgram(t, fx, t.TempDir(), program, coreCanaryAllow(), nil)
		if invalid != "" {
			t.Fatal(invalid)
		}
		if len(r.findings) != 0 {
			t.Fatalf("clean program reported: %v", r.findings)
		}
	})

	// Each encoding, planted on one channel: the scanner's own tests prove the
	// matching; this proves the harness calls it on real output with the real value.
	probe := canary.New("value-1", canary.Secret, program, false)
	for _, v := range probe.Variants() {
		t.Run("encoding-"+v.Name, func(t *testing.T) {
			r, invalid := runCoreCanaryProgram(t, fx, t.TempDir(), program, coreCanaryAllow(), func(r *coreCanaryRun, _ string) {
				encoded := canaryVariantOf(r.controlValue, v.Name)
				log.Print("x ", string(encoded), " y")
			})
			if invalid != "" {
				t.Fatal(invalid)
			}
			if len(r.findings) == 0 {
				t.Fatalf("planted %s encoding was not reported", v.Name)
			}
		})
	}
	t.Run("eight-byte-fragment", func(t *testing.T) {
		r, invalid := runCoreCanaryProgram(t, fx, t.TempDir(), program, coreCanaryAllow(), func(r *coreCanaryRun, _ string) {
			log.Print("x ", r.controlValue.Core[5:5+canary.MinWindow], " y")
		})
		if invalid != "" {
			t.Fatal(invalid)
		}
		if len(r.findings) == 0 {
			t.Fatal("planted fragment was not reported")
		}
	})
}

func canaryVariantOf(c canary.Canary, name string) []byte {
	for _, v := range c.Variants() {
		if v.Name == name {
			return v.Bytes
		}
	}
	coreFail("INVALID RUN: no variant %s", name)
	return nil
}

func plantCoreCanaryRow(r *coreCanaryRun, v string) {
	if err := r.db.Exec("CREATE TABLE redproof (x TEXT)").Error; err != nil {
		coreFail("INVALID RUN: planting row: %v", err)
	}
	if err := r.db.Exec("INSERT INTO redproof (x) VALUES (?)", v).Error; err != nil {
		coreFail("INVALID RUN: planting row: %v", err)
	}
}
