package http

// request_echo_pg_canary_fuzz_test.go -- FuzzHTTPPGRequestEchoCanary.
//
// FuzzHTTPRequestEchoCanary over PostgreSQL. All of its request shapes run unchanged,
// and pgShape adds requests that PostgreSQL itself rejects with a value in hand: a
// JSON NUL escape, an invalid byte sequence, a key past the index size limit, a
// duplicate of a stored secret's name, a canary in a typed field. A pgx tracer records
// what the server really said, so a test can prove the provocation reached it.
//
// Skips without KEYORIX_TEST_PG_DSN. Everything happens in w7_* databases.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/canary"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgcanary"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

const (
	echoW2ShapeCount = 12
	echoPGShapeCount = 10
)

type requestEchoPGFixture struct {
	*requestEchoFixture
	world *pgcanary.World
}

func newRequestEchoPGFixture(tb testing.TB) *requestEchoPGFixture {
	tb.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		tb.Fatalf("i18n: %v", err)
	}
	tb.Cleanup(i18n.ResetForTesting)
	origLog := log.Writer()
	tb.Cleanup(func() { log.SetOutput(origLog) })
	dir, err := os.MkdirTemp("", "http-pg-canary-*")
	if err != nil {
		tb.Fatalf("mkdir: %v", err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(dir) })

	world := pgcanary.Open(tb, "http", "")
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, dir)
	if err := enc.Initialize("canary-pg-fuzz-test-passphrase"); err != nil {
		tb.Fatalf("encryption: %v", err)
	}
	c := newEchoPGCore(world, enc)
	c.SetBootstrapToken("test-bootstrap-token")
	ctx := context.Background()
	if _, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{Username: "testadmin", Email: "testadmin@example.com", Password: "TestPassword123!", Token: "test-bootstrap-token"}); err != nil {
		tb.Fatalf("bootstrap: %v", err)
	}
	ls := world.Storage()
	admin, err := ls.GetUserByUsername(ctx, "testadmin")
	if err != nil || admin == nil {
		tb.Fatalf("admin lookup: %v", err)
	}
	proj, err := ls.CreateProject(ctx, &models.Project{Name: "canary-proja"})
	if err != nil {
		tb.Fatalf("project: %v", err)
	}
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	if err != nil {
		tb.Fatalf("environment: %v", err)
	}
	outsider, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "canary-outsider", Email: "canary-outsider@x.io", DisplayName: "o", Password: apiFuzzPrincipalPassword})
	if err != nil || outsider == nil {
		tb.Fatalf("outsider: %v", err)
	}
	router, err := NewRouter(&config.Config{}, c)
	if err != nil {
		tb.Fatalf("router: %v", err)
	}
	routes := listSweepRoutes(tb, router)
	drainAllBackgroundGoroutines()
	world.Snapshot(tb)

	fx := &requestEchoFixture{enc: enc, adminID: admin.ID, outsiderID: outsider.ID, projectID: proj.ID, envID: env.ID, routes: routes, capture: canary.NewCapture(), captureDir: dir}
	tb.Cleanup(fx.capture.Uninstall)
	fx.control = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "keyorix_http_pg_canary_control", Help: "Harness control for the metrics capture."}, []string{"v"})
	if err := prometheus.Register(fx.control); err != nil {
		tb.Fatalf("register control metric: %v", err)
	}
	tb.Cleanup(func() { prometheus.Unregister(fx.control) })
	return &requestEchoPGFixture{requestEchoFixture: fx, world: world}
}

func newEchoPGCore(world *pgcanary.World, enc *encryption.Service) *core.KeyorixCore {
	c := core.NewKeyorixCore(world.Storage())
	c.SetSecretValueEncryptor(enc)
	c.SetAuthEncryptor(enc)
	fakeDyn := &dynamictest.FakeEngine{NativeExpiry: true}
	c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fakeDyn, nil })
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	return c
}

// newPGRun is requestEchoFixture.newRun over the reset database.
func (fx *requestEchoPGFixture) newPGRun(t testing.TB, seed []byte, allow *canary.Allowlist) *requestEchoRun {
	t.Helper()
	if err := fx.world.Reset(); err != nil {
		t.Fatalf("INVALID RUN: %v", err)
	}
	t.Cleanup(drainAllBackgroundGoroutines)
	c := newEchoPGCore(fx.world, fx.enc)
	if !c.SecretValueEncryptionActive() {
		t.Fatalf("INVALID RUN: encryption inactive")
	}
	router, err := NewRouter(&config.Config{}, c)
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	fx.capture.Drain()
	fx.world.Tracer.Drain()

	ctx := context.Background()
	expires := time.Now().Add(time.Hour)
	mintSession := func(userID uint) string {
		s, err := c.Storage().CreateSession(ctx, &models.Session{UserID: userID, SessionToken: fmt.Sprintf("echo-pg-%d-%d-%x", userID, fx.addrN.Add(1), sha256.Sum256(seed)), ExpiresAt: &expires})
		if err != nil {
			t.Fatalf("mint session: %v", err)
		}
		return s.SessionToken
	}
	mint := func(label string, class canary.Class, hostile bool) canary.Canary {
		return canary.New(label, class, seed, hostile)
	}
	r := &requestEchoRun{
		fx: fx.requestEchoFixture, router: router, db: fx.world.DB, scanner: canary.NewScanner(), allow: allow,
		adminTok: mintSession(fx.adminID), outsiderTok: mintSession(fx.outsiderID),
		sBody: mint("s-body", canary.Secret, false), sQuery: mint("s-query", canary.Secret, true), sHeader: mint("s-header", canary.Secret, false),
		mBody: mint("m-body", canary.Metadata, false), mPath: mint("m-path", canary.Metadata, false),
		mQuery: mint("m-query", canary.Metadata, true), mHeader: mint("m-header", canary.Metadata, false),
		control: mint("control", canary.Secret, true), controlName: mint("control-name", canary.Metadata, false),
		probe: mint("probe", canary.Metadata, false),
	}
	for _, can := range []canary.Canary{r.sBody, r.sQuery, r.sHeader, r.mBody, r.mPath, r.mQuery, r.mHeader, r.control, r.controlName, r.probe} {
		r.scanner.Add(can)
	}
	return r
}

// pgShape returns a PostgreSQL-specific request, sharing shape's URL construction and
// credentials. Only the body or query differs.
func (r *requestEchoRun) pgShape(rt sweepRoute, principal string, shape uint8, mut []byte) *sweepReq {
	req := r.shape(rt, principal, 0, nil)
	req.Shape = fmt.Sprintf("pg%d", shape%echoPGShapeCount)
	req.Target = sweepParam.ReplaceAllStringFunc(rt.Pattern, func(string) string { return url.PathEscape(r.mPath.Raw) })
	switch shape % echoPGShapeCount {
	case 0: // JSON's escape produces a real NUL: 22021 if it reaches a text column
		req.Body = fmt.Appendf(nil, `{"name":%q,"value":%q,"description":%q,"type":"password","project_id":%d,"environment_id":%d}`, r.mBody.Raw+`\u0000`+r.mBody.Raw, r.sBody.Raw, r.mBody.Raw+`\u0000`, r.fx.projectID, r.fx.envID)
		req.Body = bytes.ReplaceAll(req.Body, []byte(`\\u0000`), []byte(`\u0000`))
	case 1: // a raw invalid byte inside a JSON string
		req.Body = []byte(`{"name":"` + r.mBody.Raw + "\xff\xfe" + `","value":"` + r.sBody.Raw + "\xc3\x28" + `","type":"password"}`)
	case 2: // past the index size limit
		req.Body = mustJSON(map[string]any{"name": strings.Repeat(r.mBody.Raw, 80), "value": strings.Repeat(r.sBody.Raw, 80), "description": strings.Repeat(r.mBody.Raw, 3000), "type": "password", "project_id": r.fx.projectID, "environment_id": r.fx.envID})
	case 3: // the control secret's name: a duplicate key on create
		req.Body = mustJSON(map[string]any{"name": r.controlName.Raw, "value": r.sBody.Raw, "description": r.mBody.Raw, "type": "password", "project_id": r.fx.projectID, "environment_id": r.fx.envID})
	case 4: // integers past every integer type
		req.Body = []byte(`{"name":"` + r.mBody.Raw + `","value":"` + r.sBody.Raw + `","project_id":99999999999999999999,"environment_id":-99999999999999999999}`)
	case 5: // a NUL in every query parameter and the path
		q := url.Values{}
		for _, k := range []string{"name", "q", "search", "filter", "sort", "order", "ref", "id"} {
			q.Set(k, r.mQuery.Raw+"\x00")
		}
		req.Target = sweepParam.ReplaceAllStringFunc(rt.Pattern, func(string) string { return url.PathEscape(r.mPath.Raw + "\x00") }) + "?" + q.Encode()
	case 6: // a NUL inside a JSON key
		req.Body = []byte(`{"name\u0000` + r.mBody.Raw + `":"x","value":"` + r.sBody.Raw + `"}`)
	case 7: // a NUL inside a structured value
		req.Body = []byte(`{"name":"` + r.mBody.Raw + `","value":"` + r.sBody.Raw + `","type":"password","project_id":` + fmt.Sprint(r.fx.projectID) + `,"environment_id":` + fmt.Sprint(r.fx.envID) + `,"metadata":{"k":"` + r.mBody.Raw + `\u0000"},"tags":["` + r.mBody.Raw + `\u0000"]}`)
	case 8: // a canary in the fields typed as time, number or enum
		req.Body = mustJSON(map[string]any{"name": r.mBody.Raw, "value": r.sBody.Raw, "expires_at": r.mBody.Raw, "expiration": r.mBody.Raw, "not_before": r.mBody.Raw, "state": r.mBody.Raw, "type": r.mBody.Raw, "project_id": r.fx.projectID, "environment_id": r.fx.envID})
	case 9: // the hostile quoting, valid UTF-8, on every text field
		hostile := "p\"\\<&>'%+ /é" + r.mBody.Raw + "é/ +%'>&<\\\"s"
		req.Body = mustJSON(map[string]any{"name": hostile, "value": r.sBody.Raw, "description": hostile, "username": hostile, "email": hostile, "title": hostile, "reason": hostile, "project_id": r.fx.projectID, "environment_id": r.fx.envID})
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

// finishPG is requestEchoRun.finish with a database dump in place of the raw-file
// scan, keeping every positive control.
func (r *requestEchoRun) finishPG(world *pgcanary.World, origin string, plant func(*requestEchoRun)) {
	drainAllBackgroundGoroutines()
	r.fx.control.Reset()
	if plant != nil {
		plant(r)
		drainAllBackgroundGoroutines()
	}
	log.Print(r.probe.Raw)
	fmt.Fprintln(os.Stdout, r.probe.Raw)
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
	rec := r.send(&sweepReq{Method: http.MethodGet, Target: "/metrics", Header: http.Header{}})
	if !hasEchoLabel(r.scanner.Scan(echoChanMetrics, rec.Body.Bytes()), r.probe.Label) {
		echoFail("INVALID RUN: the probe is not in /metrics (HTTP %d), so that channel is not being captured", rec.Code)
	}
	for _, h := range r.scanner.Scan(echoChanMetrics, rec.Body.Bytes()) {
		r.file(origin, h)
	}
	dump, err := world.Dump()
	if err != nil {
		echoFail("INVALID RUN: database dump: %v", err)
	}
	if !hasEchoLabel(r.scanner.ScanAll(dump), r.controlName.Label) {
		echoFail("INVALID RUN: the control secret's name is in no database column, so the database scan sees nothing")
	}
	for _, h := range r.scanner.ScanAll(dump) {
		r.file(origin, h)
	}
}

// echoPGEvidence is what the driver saw during one execution.
type echoPGEvidence struct {
	codes     map[string]int
	rawFields map[string]int
	status    int
}

func runRequestEchoPG(t testing.TB, fx *requestEchoPGFixture, in requestEchoInput, allow *canary.Allowlist, wrap func(*requestEchoRun, http.Handler) http.Handler, plant func(*requestEchoRun)) (r *requestEchoRun, ev *echoPGEvidence, invalid string) {
	t.Helper()
	if err := fx.capture.InstallOnce(fx.captureDir, os.Create); err != nil {
		t.Fatalf("capture: %v", err)
	}
	r = fx.newPGRun(t, in.seed(), allow)
	if wrap != nil {
		r.router = wrap(r, r.router)
	}
	rt := fx.routes[int(in.route)%len(fx.routes)]
	if rt.Method == http.MethodConnect || rt.Method == http.MethodTrace {
		return r, &echoPGEvidence{}, ""
	}
	ev = &echoPGEvidence{codes: map[string]int{}, rawFields: map[string]int{}}
	principals := []string{"admin", "outsider", "anon", "garbage"}
	pgcanary.RunGuarded(t.Fatalf, "request echo pg", func() {
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
		fx.world.Tracer.Drain()
		principal := principals[int(in.principal)%len(principals)]
		s := in.shape % (echoW2ShapeCount + echoPGShapeCount)
		var req *sweepReq
		if s < echoW2ShapeCount {
			req = r.shape(rt, principal, s, in.mut)
		} else {
			req = r.pgShape(rt, principal, s-echoW2ShapeCount, in.mut)
		}
		rec := r.send(req)
		r.status = rec.Code
		ev.status = rec.Code
		entries := fx.world.Tracer.Drain()
		for _, e := range entries {
			if e.SQLState != "" {
				ev.codes[e.SQLState]++
			} else {
				ev.codes["client"]++
			}
		}
		for _, o := range pgcanary.RawOutputs(entries) {
			for _, h := range r.scanner.Scan(o.Channel, o.Data) {
				ev.rawFields[strings.TrimPrefix(o.Channel, "pg-raw:")+"/"+h.Class.String()]++
			}
		}
		r.judgeResponse(req, rec)
		r.finishPG(fx.world, req.Route, plant)
	})
	return r, ev, invalid
}

// echoPGDirected picks the write routes most likely to reach PostgreSQL with each
// PG shape: the corpus that TestRequestEchoPGProvocationsReachServer drives and the
// fuzz target starts from.
func (fx *requestEchoPGFixture) echoPGDirected() []requestEchoInput {
	var routes []int
	for _, suffix := range []string{"/secrets/", "/secrets", "/projects", "/projects/", "/environments", "/users", "/groups", "/roles", "/notification-channels"} {
		for i, rt := range fx.routes {
			if rt.Method == http.MethodPost && strings.HasSuffix(rt.Pattern, suffix) && strings.HasPrefix(rt.Pattern, "/api/v1/") {
				routes = append(routes, i)
				break
			}
		}
	}
	var out []requestEchoInput
	for _, route := range routes {
		for shape := range echoPGShapeCount {
			out = append(out, requestEchoInput{route: uint16(route), principal: 0, shape: uint8(echoW2ShapeCount + shape)})
		}
	}
	// A few routes for the other principals and the W2 shapes.
	for shape := range echoW2ShapeCount {
		out = append(out, requestEchoInput{route: uint16(shape * 23), principal: uint8(shape % 4), shape: uint8(shape)})
	}
	return out
}

// FuzzHTTPPGRequestEchoCanary fails when any part of a request is echoed, or written
// anywhere, outside requestEchoRules, on PostgreSQL.
func FuzzHTTPPGRequestEchoCanary(f *testing.F) {
	fx := newRequestEchoPGFixture(f)
	for _, in := range fx.echoPGDirected() {
		f.Add(in.route, in.principal, in.shape, in.mut)
	}
	f.Fuzz(func(t *testing.T, route uint16, principal, shape uint8, mut []byte) {
		if len(mut) > 64 {
			mut = mut[:64]
		}
		r, _, invalid := runRequestEchoPG(t, fx, requestEchoInput{route, principal, shape, mut}, requestEchoRules(), nil, nil)
		if invalid != "" {
			t.Fatal(invalid)
		}
		if len(r.findings) > 0 {
			t.Fatalf("CANARY LEAK (%d):\n%s", len(r.findings), strings.Join(r.findings, "\n"))
		}
	})
}

// echoPGWantSQLStates are the server errors the directed corpus must really produce.
var echoPGWantSQLStates = []string{"23505"}

// TestRequestEchoPGProvocationsReachServer proves the directed corpus reaches the
// server and that nothing it does is a finding.
func TestRequestEchoPGProvocationsReachServer(t *testing.T) {
	fx := newRequestEchoPGFixture(t)
	codes := map[string]int{}
	raw := map[string]int{}
	statusByShape := map[string]int{}
	for _, in := range fx.echoPGDirected() {
		r, ev, invalid := runRequestEchoPG(t, fx, in, requestEchoRules(), nil, nil)
		if invalid != "" {
			t.Fatalf("input %+v: %s", in, invalid)
		}
		if len(r.findings) > 0 {
			t.Errorf("input route=%s shape=%d:\n%s", fx.routes[in.route], in.shape, strings.Join(r.findings, "\n"))
		}
		for k, n := range ev.codes {
			codes[k] += n
		}
		for k, n := range ev.rawFields {
			raw[k] += n
		}
		statusByShape[fmt.Sprintf("shape%d/%d", in.shape, ev.status)]++
	}
	t.Logf("server errors by SQLSTATE: %v", codes)
	t.Logf("canaries in raw driver fields: %v", raw)
	t.Logf("status by shape: %v", statusByShape)
	for _, code := range echoPGWantSQLStates {
		if codes[code] == 0 {
			t.Errorf("the corpus never made the server raise %s; got %v", code, codes)
		}
	}
	if raw["detail/metadata"] == 0 {
		t.Errorf("no server DETAIL quoted a canary, so the oracle's channel was never under test: %v", raw)
	}
}

// echoPGCreateRoute finds POST /api/v1/secrets/ in the route table.
func (fx *requestEchoPGFixture) echoPGCreateRoute(tb testing.TB) uint16 {
	tb.Helper()
	for i, rt := range fx.routes {
		if rt.Method == http.MethodPost && rt.Pattern == "/api/v1/secrets/" {
			return uint16(i)
		}
	}
	tb.Fatal("no POST /api/v1/secrets/ route")
	return 0
}

// TestRequestEchoPGOracleCatchesWrappingShim is the red-proof, with a real duplicate
// key failure underneath. Each shim is a middleware in this test, which copies what
// PostgreSQL said into one channel, and the unbroken control stays silent.
func TestRequestEchoPGOracleCatchesWrappingShim(t *testing.T) {
	fx := newRequestEchoPGFixture(t)
	in := requestEchoInput{route: fx.echoPGCreateRoute(t), shape: echoW2ShapeCount + 3} // duplicate of the control name
	withTracedDetail := func(use func(*requestEchoRun, http.ResponseWriter, string)) func(*requestEchoRun, http.Handler) http.Handler {
		return func(r *requestEchoRun, h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				h.ServeHTTP(w, req)
				if req.Method != http.MethodPost {
					return
				}
				var detail string
				for _, e := range fx.world.Tracer.Drain() {
					if e.SQLState == "23505" {
						detail = e.Detail
					}
				}
				if detail == "" {
					echoFail("INVALID RUN: the wrapped request produced no 23505")
				}
				use(r, w, detail)
			})
		}
	}

	t.Run("control-is-silent", func(t *testing.T) {
		r, ev, invalid := runRequestEchoPG(t, fx, in, requestEchoRules(), nil, nil)
		if invalid != "" {
			t.Fatal(invalid)
		}
		if len(r.findings) != 0 {
			t.Fatalf("clean run reported: %v", r.findings)
		}
		if ev.codes["23505"] == 0 || ev.rawFields["detail/metadata"] == 0 {
			t.Fatalf("no real duplicate-key failure with a canary in DETAIL: codes %v raw %v", ev.codes, ev.rawFields)
		}
	})
	for _, tc := range []struct {
		name, want string
		use        func(*requestEchoRun, http.ResponseWriter, string)
	}{
		{"body", echoChanBody, func(_ *requestEchoRun, w http.ResponseWriter, d string) { _, _ = w.Write([]byte("db error: " + d)) }},
		{"header", echoChanHeader, func(_ *requestEchoRun, w http.ResponseWriter, d string) { w.Header().Set("X-Db-Error", d) }},
		{"log", canary.ChannelLog, func(_ *requestEchoRun, _ http.ResponseWriter, d string) { log.Print("db error: " + d) }},
	} {
		t.Run("shim-"+tc.name, func(t *testing.T) {
			r, _, invalid := runRequestEchoPG(t, fx, in, requestEchoRules(), withTracedDetail(tc.use), nil)
			if invalid != "" {
				t.Fatal(invalid)
			}
			want := "channel=" + tc.want + " "
			if !slices.ContainsFunc(r.findings, func(s string) bool { return strings.Contains(s, want) }) {
				t.Fatalf("shim on %s was not reported; findings: %v", tc.want, r.findings)
			}
		})
	}
	t.Run("shim-secret-in-body", func(t *testing.T) {
		wrap := withTracedDetail(func(r *requestEchoRun, w http.ResponseWriter, _ string) {
			_, _ = w.Write([]byte("db error: " + r.sBody.Raw))
		})
		r, _, invalid := runRequestEchoPG(t, fx, in, requestEchoRules(), wrap, nil)
		if invalid != "" {
			t.Fatal(invalid)
		}
		if !slices.ContainsFunc(r.findings, func(s string) bool { return strings.Contains(s, "channel="+echoChanBody) }) {
			t.Fatalf("secret on the error body was not reported: %v", r.findings)
		}
	})
}
