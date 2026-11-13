package http

// request_echo_canary_fuzz_test.go -- FuzzHTTPRequestEchoCanary.
//
// One execution sends one request, usually invalid, to any route of the real router,
// with a canary in every part of the request, and asserts that the canary is not
// echoed back or written anywhere outside requestEchoRules.
//
// FuzzCanaryRouteSweep sweeps the same routes for secret-class fields. This target
// differs in four ways: it also judges metadata-class fields on error responses, it
// matches any 8-byte fragment (its canaries use a denser alphabet for that), its
// request shapes are built to reach the decoders' own error text (wrong types, a
// canary as a JSON key, a canary outside any string), and each execution gets its
// own copy of the database in its own t.TempDir, so a saved input replays alone.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/canary"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

const (
	echoChanBody    = "resp-body"
	echoChanHeader  = "resp-header"
	echoChanMetrics = "metrics"
	echoChanRawDB   = "raw-db-file"
	echoChanReveal  = "reveal"
)

// requestEchoRules is the whole allowlist; requestEchoPermitted adds the two
// conditions a Rule cannot express. An unknown echo is a finding. The authorised
// reveal (GET /secrets/{id}?include_value=true by the owner) is not listed because
// only the control reads through it, and the control's result is asserted directly.
func requestEchoRules() *canary.Allowlist {
	return canary.NewAllowlist(
		// No request echo is allowed on an error response: the three the full route sweep
		// found (SSO provider, notification channel type, export format) were fixed by
		// #4059 / CORE-ERR-FAMILY-7, and an echo row here would let them come back.
		canary.Rule{ID: "meta-db", Channel: canary.ChannelDBPrefix + "*", MetadataOnly: true, Why: "names and descriptions are stored in plaintext by design"},
		canary.Rule{ID: "meta-rawdb", Channel: echoChanRawDB, MetadataOnly: true, Why: "names and descriptions are stored in plaintext by design"},
	)
}

// requestEchoFixture is built once per worker. buildCanaryWorld's bcrypt logins and
// PBKDF2 are too slow per execution, so each execution copies its database and
// opens a new core and router on the copy.
type requestEchoFixture struct {
	dbPath     string
	enc        *encryption.Service
	adminID    uint
	outsiderID uint
	projectID  uint
	envID      uint
	routes     []sweepRoute
	capture    *canary.Capture
	control    *prometheus.GaugeVec
	addrN      atomic.Uint64

	captureDir string
}

func newRequestEchoFixture(tb testing.TB) *requestEchoFixture {
	tb.Helper()
	// buildCanaryWorld points the standard logger at its own buffer and registers no
	// restore, so the original writer has to be saved first.
	origLog := log.Writer()
	tb.Cleanup(func() { log.SetOutput(origLog) })
	w := buildCanaryWorld(tb)
	tb.Cleanup(func() { w.close() })
	tb.Cleanup(i18n.ResetForTesting)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, w.tempDir)
	if err := enc.Initialize("canary-fuzz-test-passphrase"); err != nil {
		tb.Fatalf("encryption: %v", err)
	}
	fx := &requestEchoFixture{
		dbPath: w.dbPath, enc: enc, adminID: w.adminID, outsiderID: w.principals[2].id,
		projectID: w.projAID, envID: w.envAID, routes: listSweepRoutes(tb, w.router),
		capture: canary.NewCapture(),
	}
	tb.Cleanup(fx.capture.Uninstall)
	fx.captureDir = w.tempDir
	fx.control = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "keyorix_http_canary_control", Help: "Harness control for the metrics capture."}, []string{"v"})
	if err := prometheus.Register(fx.control); err != nil {
		tb.Fatalf("register control metric: %v", err)
	}
	tb.Cleanup(func() { prometheus.Unregister(fx.control) })
	return fx
}

// requestEchoRun is one execution.
type requestEchoRun struct {
	fx      *requestEchoFixture
	router  http.Handler
	db      *gorm.DB
	dbPath  string
	scanner *canary.Scanner
	allow   *canary.Allowlist

	sBody, sQuery, sHeader        canary.Canary
	mBody, mPath, mQuery, mHeader canary.Canary
	control, controlName, probe   canary.Canary

	findings []string
	status   int

	adminTok, outsiderTok string
}

func (fx *requestEchoFixture) newRun(t testing.TB, dir string, seed []byte, allow *canary.Allowlist) *requestEchoRun {
	t.Helper()
	dbPath := filepath.Join(dir, "world.db")
	data, err := os.ReadFile(fx.dbPath)
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	if err := os.WriteFile(dbPath, data, 0o600); err != nil {
		t.Fatalf("write world db: %v", err)
	}
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() {
		drainAllBackgroundGoroutines()
		_ = sqlDB.Close()
	})
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetSecretValueEncryptor(fx.enc)
	if !c.SecretValueEncryptionActive() {
		t.Fatalf("INVALID RUN: encryption inactive")
	}
	c.SetAuthEncryptor(fx.enc)
	fakeDyn := &dynamictest.FakeEngine{NativeExpiry: true}
	c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fakeDyn, nil })
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	router, err := NewRouter(&config.Config{}, c)
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	fx.capture.Drain()

	// The auth middleware's token cache is process-wide, and an execution may revoke
	// its own session. Reusing one token across executions lets that state leak into
	// the next execution, so every execution gets session tokens of its own.
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)
	mintSession := func(userID uint) string {
		s, err := c.Storage().CreateSession(ctx, &models.Session{UserID: userID, SessionToken: fmt.Sprintf("echo-%d-%d-%x", userID, fx.addrN.Add(1), sha256.Sum256(seed)), ExpiresAt: &expires})
		if err != nil {
			t.Fatalf("mint session: %v", err)
		}
		return s.SessionToken
	}
	mint := func(label string, class canary.Class, hostile bool) canary.Canary {
		return canary.New(label, class, seed, hostile)
	}
	r := &requestEchoRun{
		fx: fx, router: router, db: db, dbPath: dbPath, scanner: canary.NewScanner(), allow: allow,
		adminTok: mintSession(fx.adminID), outsiderTok: mintSession(fx.outsiderID),
		sBody: mint("s-body", canary.Secret, false), sQuery: mint("s-query", canary.Secret, true), sHeader: mint("s-header", canary.Secret, false),
		mBody: mint("m-body", canary.Metadata, false), mPath: mint("m-path", canary.Metadata, false),
		mQuery: mint("m-query", canary.Metadata, true), mHeader: mint("m-header", canary.Metadata, false),
		control: mint("control", canary.Secret, true), controlName: mint("control-name", canary.Metadata, false),
		probe: mint("probe", canary.Metadata, false),
	}
	for _, c := range []canary.Canary{r.sBody, r.sQuery, r.sHeader, r.mBody, r.mPath, r.mQuery, r.mHeader, r.control, r.controlName, r.probe} {
		r.scanner.Add(c)
	}
	return r
}

// echoInvalid is the panic value of echoFail; see coreFail in internal/core for why
// a run never calls t.Fatalf from inside fuzzutil.Guard.
type echoInvalid string

func echoFail(format string, args ...any) { panic(echoInvalid(fmt.Sprintf(format, args...))) }

// send drives one request through the real router with its own peer address, so a
// per-IP rate limit does not turn later executions into 429s.
func (r *requestEchoRun) send(req *sweepReq) *httptest.ResponseRecorder {
	n := r.fx.addrN.Add(1)
	req.RemoteAddr = fmt.Sprintf("198.18.%d.%d:4242", (n>>8)&0xff, n&0xff)
	var body *bytes.Reader
	if req.Body != nil {
		body = bytes.NewReader(req.Body)
	} else {
		body = bytes.NewReader(nil)
	}
	hreq := httptest.NewRequest(req.Method, req.Target, body)
	hreq.Header = req.Header.Clone()
	hreq.RemoteAddr = req.RemoteAddr
	rec := httptest.NewRecorder()
	r.router.ServeHTTP(rec, hreq)
	return rec
}

func (r *requestEchoRun) adminHeaders() http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+r.adminTok)
	h.Set("Content-Type", "application/json")
	return h
}

// prologue creates a secret holding the control canary and reveals it.
func (r *requestEchoRun) prologue() {
	body, err := json.Marshal(map[string]any{"name": r.controlName.Raw, "value": r.control.Raw, "project_id": r.fx.projectID, "environment_id": r.fx.envID, "type": "password"})
	if err != nil {
		echoFail("INVALID RUN: marshal: %v", err)
	}
	rec := r.send(&sweepReq{Method: http.MethodPost, Target: "/api/v1/secrets/", Header: r.adminHeaders(), Body: body})
	if rec.Code/100 != 2 {
		echoFail("INVALID RUN: control secret was not created: HTTP %d %s", rec.Code, rec.Body.String())
	}
	var decoded struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil || decoded.Data.ID == 0 {
		echoFail("INVALID RUN: decoding create response: %v (%s)", err, rec.Body.String())
	}
	rec = r.send(&sweepReq{Method: http.MethodGet, Target: fmt.Sprintf("/api/v1/secrets/%d?include_value=true", decoded.Data.ID), Header: r.adminHeaders()})
	if !hasEchoLabel(r.scanner.Scan(echoChanReveal, rec.Body.Bytes()), r.control.Label) {
		echoFail("INVALID RUN: the reveal did not return the control canary: HTTP %d", rec.Code)
	}
	r.fx.capture.Drain() // the control's own log lines are not the fuzzed request's
}

func hasEchoLabel(hits []canary.Hit, label string) bool {
	return slices.ContainsFunc(hits, func(h canary.Hit) bool { return h.Label == label })
}

// bodyObject builds a JSON object with a canary under every commonly decoded key.
func (r *requestEchoRun) bodyObject() map[string]any {
	m := map[string]any{}
	for k := range sweepSecretKeys {
		m[k] = r.sBody.Raw
	}
	for _, k := range sweepMetaKeys {
		m[k] = r.mBody.Raw
	}
	return m
}

// mustJSON marshals a value built by this file; failure is a harness bug.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		echoFail("INVALID RUN: marshal: %v", err)
	}
	return b
}

// shape returns one request. The cases exist to reach a decoder's or validator's own
// error text, which is where an input is most often quoted back.
func (r *requestEchoRun) shape(rt sweepRoute, principal string, shape uint8, mut []byte) *sweepReq {
	target := sweepParam.ReplaceAllStringFunc(rt.Pattern, func(string) string { return url.PathEscape(r.mPath.Raw) })
	req := &sweepReq{Method: rt.Method, Target: target, Header: http.Header{}, Principal: principal, Shape: fmt.Sprint(shape % 12), Route: rt.String()}
	switch principal {
	case "admin":
		req.Header.Set("Authorization", "Bearer "+r.adminTok)
	case "outsider":
		req.Header.Set("Authorization", "Bearer "+r.outsiderTok)
	case "garbage":
		req.Header.Set("Authorization", "Bearer "+r.sHeader.Raw)
	}
	req.Header.Set("Content-Type", "application/json")
	switch shape % 12 {
	case 0:
		req.Body = mustJSON(r.bodyObject())
	case 1: // every value has the wrong type
		req.Body = mustJSON(map[string]any{"name": []string{r.mBody.Raw}, "value": map[string]string{"nested": r.sBody.Raw}, "project_id": r.mBody.Raw, "environment_id": r.mBody.Raw, "id": r.mBody.Raw, "password": 12345, "expiration": r.mBody.Raw, "max_reads": r.mBody.Raw})
	case 2: // the canary is the key
		req.Body = []byte(fmt.Sprintf(`{%q:1,%q:"x"}`, r.sBody.Raw, r.mBody.Raw))
	case 3: // truncated in the middle of the canary
		whole := mustJSON(r.bodyObject())
		req.Body = whole[:len(whole)/2]
	case 4: // the canary outside any string
		req.Body = []byte(`{` + r.sBody.Raw + `}`)
	case 5:
		req.Body = []byte(`{"value":"` + r.sBody.Raw + "\xff\xfe" + `","name":"` + r.mBody.Raw + "\x00" + `"}`)
	case 6:
		v := url.Values{}
		v.Set("value", r.sBody.Raw)
		v.Set("password", r.sBody.Raw)
		v.Set("name", r.mBody.Raw)
		req.Body = []byte(v.Encode())
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case 7:
		req.Body = []byte(r.sBody.Raw)
		req.Header.Set("Content-Type", "text/plain")
	case 8:
		q := url.Values{}
		for _, k := range []string{"token", "password", "secret", "api_key", "value"} {
			q.Set(k, r.sQuery.Raw)
		}
		for _, k := range []string{"format", "ref", "q", "name", "id", "page", "page_size", "since", "sort", "filter"} {
			q.Set(k, r.mQuery.Raw)
		}
		req.Target += "?" + q.Encode()
	case 9: // a numeric path segment that parses, with the canary in query only
		req.Target = sweepParam.ReplaceAllString(rt.Pattern, "1") + "?format=" + url.QueryEscape(r.mQuery.Raw) + "&token=" + url.QueryEscape(r.sQuery.Raw)
	case 10:
		req.Header.Set("X-Request-Id", r.mHeader.Raw)
		req.Header.Set("User-Agent", r.mHeader.Raw)
		req.Header.Set("X-Api-Key", r.sHeader.Raw)
		req.Header.Set("X-Keyorix-Token", r.sHeader.Raw)
		req.Header.Set("Cookie", "session="+url.QueryEscape(r.sHeader.Raw))
		req.Header.Set("X-Forwarded-For", r.mHeader.Raw)
		req.Header.Set("Origin", "https://"+r.mHeader.Core+".example")
	case 11: // past the JSON decoder's comfort, under the body limit
		req.Body = mustJSON(map[string]any{"name": strings.Repeat(r.mBody.Raw, 200), "value": strings.Repeat(r.sBody.Raw, 200)})
	}
	if len(mut) > 0 && len(req.Body) > 0 {
		b := bytes.Clone(req.Body)
		for i, m := range mut {
			b[(int(m)*31+i*7)%len(b)] ^= mut[(i+1)%len(mut)] | 1
		}
		req.Body = b
	}
	return req
}

// requestEchoPermitted is the part of the allowlist that depends on the request: a
// metadata canary in the body of a successful response (the caller's own name came
// back from the operation that stored it), and one inside the request URI of the
// access log line of the request that carried it (the path is logged by design, and
// logSafeRequestURI redacts the parts that are credentials).
func requestEchoPermitted(h canary.Hit, req *sweepReq, status int, line []byte) bool {
	if h.Class != canary.Metadata {
		return false
	}
	if h.Channel == echoChanBody && status/100 == 2 {
		return true
	}
	if h.Channel == canary.ChannelLog {
		lo, hi, ok := accessLogURI(line, req, status)
		return ok && h.Offset >= lo && h.Offset < hi
	}
	return false
}

func (r *requestEchoRun) file(origin string, h canary.Hit) {
	if h.Label == r.probe.Label {
		return
	}
	if r.allow.Permit(h, origin) == "" {
		r.findings = append(r.findings, fmt.Sprintf("origin=%s status=%d %s", origin, r.status, h))
	}
}

func (r *requestEchoRun) judgeResponse(req *sweepReq, rec *httptest.ResponseRecorder) {
	origin := req.Route
	for _, h := range r.scanner.Scan(echoChanBody, rec.Body.Bytes()) {
		if !requestEchoPermitted(h, req, rec.Code, nil) {
			r.file(origin, h)
		}
	}
	var hb strings.Builder
	for k, v := range rec.Header() {
		hb.WriteString(k + ": " + strings.Join(v, ", ") + "\n")
	}
	for _, h := range r.scanner.Scan(echoChanHeader, []byte(hb.String())) {
		r.file(origin, h)
	}
	drainAllBackgroundGoroutines()
	for _, o := range r.fx.capture.Drain() {
		if o.Channel != canary.ChannelLog {
			for _, h := range r.scanner.Scan(o.Channel, o.Data) {
				r.file(origin, h)
			}
			continue
		}
		for line := range bytes.SplitSeq(o.Data, []byte("\n")) {
			for _, h := range r.scanner.Scan(o.Channel, line) {
				if !requestEchoPermitted(h, req, rec.Code, line) {
					r.file(origin, h)
				}
			}
		}
	}
}

// finish scans the persistent channels and proves each capture is alive.
func (r *requestEchoRun) finish(origin string, plant func(*requestEchoRun)) {
	drainAllBackgroundGoroutines()
	r.fx.control.Reset()
	if plant != nil {
		plant(r)
		drainAllBackgroundGoroutines()
	}
	log.Print(r.probe.Raw)
	_, _ = fmt.Fprintln(os.Stdout, r.probe.Raw)
	fmt.Fprintln(os.Stderr, r.probe.Raw)
	r.fx.control.WithLabelValues(r.probe.Raw).Set(1)
	outputs := r.fx.capture.Drain()
	for _, ch := range []string{canary.ChannelLog, canary.ChannelStdout, canary.ChannelStderr} {
		seen := slices.ContainsFunc(outputs, func(o canary.Output) bool {
			return o.Channel == ch && hasEchoLabel(r.scanner.Scan(ch, o.Data), r.probe.Label)
		})
		if !seen {
			echoFail("INVALID RUN: the probe did not reach channel %s, so it is not being captured", ch)
		}
	}
	for _, h := range r.scanner.ScanAll(outputs) {
		r.file(origin, h)
	}

	rec := httptest.NewRecorder()
	r.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !hasEchoLabel(r.scanner.Scan(echoChanMetrics, rec.Body.Bytes()), r.probe.Label) {
		echoFail("INVALID RUN: the probe is not in /metrics (HTTP %d), so that channel is not being captured", rec.Code)
	}
	for _, h := range r.scanner.Scan(echoChanMetrics, rec.Body.Bytes()) {
		r.file(origin, h)
	}

	sqlDB, err := r.db.DB()
	if err != nil {
		echoFail("INVALID RUN: db handle: %v", err)
	}
	dump, err := canary.DumpSQLite(sqlDB)
	if err != nil {
		echoFail("INVALID RUN: database dump: %v", err)
	}
	if !hasEchoLabel(r.scanner.ScanAll(dump), r.controlName.Label) {
		echoFail("INVALID RUN: the control secret's name is in no database column, so the database scan sees nothing")
	}
	for _, h := range r.scanner.ScanAll(dump) {
		r.file(origin, h)
	}
	raw, err := os.ReadFile(r.dbPath)
	if err != nil {
		echoFail("INVALID RUN: raw database read: %v", err)
	}
	for _, h := range r.scanner.Scan(echoChanRawDB, raw) {
		r.file(origin, h)
	}
}

// requestEchoInput is one fuzz input.
type requestEchoInput struct {
	route            uint16
	principal, shape uint8
	mut              []byte
}

func (in requestEchoInput) seed() []byte {
	return append(fmt.Appendf(nil, "%d/%d/%d/", in.route, in.principal, in.shape), in.mut...)
}

// runRequestEcho executes one input. plant is the red-proof's planted leak.
func runRequestEcho(t testing.TB, fx *requestEchoFixture, dir string, in requestEchoInput, allow *canary.Allowlist, wrap func(*requestEchoRun, http.Handler) http.Handler, plant func(*requestEchoRun)) (r *requestEchoRun, invalid string) {
	t.Helper()
	if err := fx.capture.InstallOnce(fx.captureDir, os.Create); err != nil {
		t.Fatalf("capture: %v", err)
	}
	r = fx.newRun(t, dir, in.seed(), allow)
	if wrap != nil {
		r.router = wrap(r, r.router)
	}
	rt := fx.routes[int(in.route)%len(fx.routes)]
	if rt.Method == http.MethodConnect || rt.Method == http.MethodTrace {
		return r, ""
	}
	principals := []string{"admin", "outsider", "anon", "garbage"}
	canary.RunGuarded(t.Fatalf, "request echo", func() {
		defer func() {
			if p := recover(); p != nil {
				msg, ok := p.(echoInvalid)
				if !ok {
					panic(p)
				}
				invalid = string(msg)
			}
		}()
		r.prologue()
		req := r.shape(rt, principals[int(in.principal)%len(principals)], in.shape, in.mut)
		rec := r.send(req)
		r.status = rec.Code
		r.judgeResponse(req, rec)
		r.finish(req.Route, plant)
	})
	return r, invalid
}

func addRequestEchoSeeds(f *testing.F) {
	f.Add(uint16(0), uint8(0), uint8(0), []byte(nil))
	for shape := range 12 {
		f.Add(uint16(shape*23), uint8(shape%4), uint8(shape), []byte(nil))
	}
	f.Add(uint16(5), uint8(0), uint8(3), []byte{1, 2, 3})
}

// FuzzHTTPRequestEchoCanary fails when any part of a request is echoed, or written
// anywhere, outside requestEchoRules.
func FuzzHTTPRequestEchoCanary(f *testing.F) {
	fx := newRequestEchoFixture(f)
	addRequestEchoSeeds(f)
	f.Fuzz(func(t *testing.T, route uint16, principal, shape uint8, mut []byte) {
		if len(mut) > 64 {
			mut = mut[:64]
		}
		r, invalid := runRequestEcho(t, fx, t.TempDir(), requestEchoInput{route, principal, shape, mut}, requestEchoRules(), nil, nil)
		if invalid != "" {
			t.Fatal(invalid)
		}
		if len(r.findings) > 0 {
			t.Fatalf("CANARY LEAK (%d):\n%s", len(r.findings), strings.Join(r.findings, "\n"))
		}
	})
}
