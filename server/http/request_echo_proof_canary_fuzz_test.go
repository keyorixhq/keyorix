package http

// request_echo_proof_canary_fuzz_test.go -- the red-proof and the route sweep for
// FuzzHTTPRequestEchoCanary.

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/canary"
)

// plantedRequest reports whether r is the fuzzed request, not one of the prologue
// or /metrics requests the harness itself makes.
func plantedRequest(r *http.Request) bool {
	return r.URL.Path != "/metrics" && !strings.HasPrefix(r.URL.Path, "/api/v1/secrets/")
}

// TestRequestEchoCanaryOracleCatchesPlantedLeaks is the red-proof. Each case writes
// a canary into one channel from a test-only wrapper around the real router or
// directly into the store; no production code changes.
func TestRequestEchoCanaryOracleCatchesPlantedLeaks(t *testing.T) {
	fx := newRequestEchoFixture(t)
	in := requestEchoInput{principal: 2, shape: 8}
	isPlain := func(rt sweepRoute) bool {
		return rt.Method == http.MethodGet && !strings.Contains(rt.Pattern, "/secrets") && !strings.Contains(rt.Pattern, "metrics")
	}
	for !isPlain(fx.routes[int(in.route)%len(fx.routes)]) {
		in.route++
	}
	wrapWrite := func(write func(r *requestEchoRun, w http.ResponseWriter)) func(*requestEchoRun, http.Handler) http.Handler {
		return func(r *requestEchoRun, next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if plantedRequest(req) {
					write(r, w)
				}
				next.ServeHTTP(w, req)
			})
		}
	}
	plantRow := func(r *requestEchoRun) {
		if err := r.db.Exec("CREATE TABLE redproof (x TEXT)").Error; err != nil {
			echoFail("INVALID RUN: planting row: %v", err)
		}
		if err := r.db.Exec("INSERT INTO redproof (x) VALUES (?)", r.sBody.Raw).Error; err != nil {
			echoFail("INVALID RUN: planting row: %v", err)
		}
	}
	cases := []struct {
		name, want string
		wrap       func(*requestEchoRun, http.Handler) http.Handler
		plant      func(*requestEchoRun)
	}{
		{"response-body", echoChanBody, wrapWrite(func(r *requestEchoRun, w http.ResponseWriter) { _, _ = w.Write([]byte(r.sBody.Raw)) }), nil},
		{"response-header", echoChanHeader, wrapWrite(func(r *requestEchoRun, w http.ResponseWriter) { w.Header().Set("X-Leak", r.sBody.Core) }), nil},
		{"stdlib-log", canary.ChannelLog, wrapWrite(func(r *requestEchoRun, _ http.ResponseWriter) { log.Print(r.sBody.Raw) }), nil},
		{"stdout", canary.ChannelStdout, wrapWrite(func(r *requestEchoRun, _ http.ResponseWriter) { _, _ = fmt.Fprintln(os.Stdout, r.sBody.Raw) }), nil},
		{"stderr", canary.ChannelStderr, wrapWrite(func(r *requestEchoRun, _ http.ResponseWriter) { fmt.Fprintln(os.Stderr, r.sBody.Raw) }), nil},
		{"metric-label", echoChanMetrics, nil, func(r *requestEchoRun) { r.fx.control.WithLabelValues(r.sBody.Raw).Set(1) }},
		{"db-cell", canary.ChannelDBPrefix + "redproof.x", nil, plantRow},
		{"raw-db-file", echoChanRawDB, nil, plantRow},
		{"metadata-echoed-on-error", echoChanBody, wrapWrite(func(r *requestEchoRun, w http.ResponseWriter) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"bad name ` + r.mBody.Raw + `"}`))
		}), nil},
		{"control-value-in-unrelated-log", canary.ChannelLog, wrapWrite(func(r *requestEchoRun, _ http.ResponseWriter) { log.Print(r.control.Raw) }), nil},
		{"fragment-in-body", echoChanBody, wrapWrite(func(r *requestEchoRun, w http.ResponseWriter) {
			_, _ = w.Write([]byte("x" + r.sBody.Core[4:12] + "y"))
		}), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, invalid := runRequestEcho(t, fx, t.TempDir(), in, requestEchoRules(), tc.wrap, tc.plant)
			if invalid != "" {
				t.Fatal(invalid)
			}
			want := "channel=" + tc.want + " "
			if !slices.ContainsFunc(r.findings, func(s string) bool { return strings.Contains(s, want) }) {
				t.Fatalf("planted leak on %s was not reported; findings: %v", tc.want, r.findings)
			}
		})
	}
	t.Run("clean-request-is-clean", func(t *testing.T) {
		r, invalid := runRequestEcho(t, fx, t.TempDir(), in, requestEchoRules(), nil, nil)
		if invalid != "" {
			t.Fatal(invalid)
		}
		if len(r.findings) != 0 {
			t.Fatalf("clean request reported: %v", r.findings)
		}
	})
	t.Run("metadata-on-a-successful-response-is-allowed", func(t *testing.T) {
		r, invalid := runRequestEcho(t, fx, t.TempDir(), in, requestEchoRules(), wrapWrite(func(r *requestEchoRun, w http.ResponseWriter) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(r.mBody.Raw))
		}), nil)
		if invalid != "" {
			t.Fatal(invalid)
		}
		if len(r.findings) != 0 {
			t.Fatalf("metadata on a 200 reported: %v", r.findings)
		}
	})
}

// runChannelURLShape sends echoChannelURLShape to route as the admin.
func runChannelURLShape(t *testing.T, fx *requestEchoFixture, route string) *requestEchoRun {
	t.Helper()
	idx := slices.IndexFunc(fx.routes, func(r sweepRoute) bool { return r.String() == route })
	if idx < 0 {
		t.Fatalf("route %s is not registered", route)
	}
	in := requestEchoInput{route: uint16(idx), principal: 0, shape: echoChannelURLShape}
	r, invalid := runRequestEcho(t, fx, t.TempDir(), in, requestEchoRules(), nil, nil)
	if invalid != "" {
		t.Fatal(invalid)
	}
	return r
}

// TestRequestEchoCanaryChannelURLShapeReachesValidation proves the shape gets past
// the type check on both channel routes: the refusal it asserts comes from the URL
// validation, which runs after that check.
func TestRequestEchoCanaryChannelURLShapeReachesValidation(t *testing.T) {
	fx := newRequestEchoFixture(t)
	for _, route := range echoChannelRoutes {
		t.Run(route, func(t *testing.T) {
			r := runChannelURLShape(t, fx, route)
			if r.status != http.StatusBadRequest || !strings.Contains(r.respBody, "private/link-local") {
				t.Fatalf("did not reach the URL validation: status %d body %s", r.status, r.respBody)
			}
			if len(r.findings) != 0 {
				t.Fatalf("findings: %v", r.findings)
			}
		})
	}
}

var echoChannelDNS = flag.Bool("canary-echo-channel-dns", false, "TestRequestEchoCanaryChannelDNSCandidate: replay the DNS error path through the real resolver")

// TestRequestEchoCanaryChannelDNSCandidate pins an open candidate finding: the
// resolver's error names the URL's host and validateWebhookURL returns it in the 400,
// so a canary in the host comes back, while one in the path does not. It passes while
// that is true and fails once the host stops being quoted, so it gets removed with the
// fix. It needs -canary-echo-channel-dns because it makes real DNS queries for names
// under .invalid, which a default run must not do (#1948). It covers the resolver
// error only, not a host that resolves.
func TestRequestEchoCanaryChannelDNSCandidate(t *testing.T) {
	if !*echoChannelDNS {
		t.Skip("makes real DNS queries; run with -canary-echo-channel-dns")
	}
	fx := newRequestEchoFixture(t)
	for _, route := range echoChannelRoutes {
		t.Run(route+"/canary-in-host", func(t *testing.T) {
			fx.channelURL = func(r *requestEchoRun) string { return "https://" + r.sBody.Raw + ".invalid/" }
			r := runChannelURLShape(t, fx, route)
			if !slices.ContainsFunc(r.findings, func(s string) bool {
				return strings.Contains(s, "channel="+echoChanBody+" ") && strings.Contains(s, "label=s-body")
			}) {
				t.Fatalf("the host is no longer quoted, so remove this test: status %d body %s findings %v", r.status, r.respBody, r.findings)
			}
		})
		t.Run(route+"/canary-in-path", func(t *testing.T) {
			fx.channelURL = func(r *requestEchoRun) string { return "https://echo-target.invalid/hook/" + r.sBody.Raw }
			r := runChannelURLShape(t, fx, route)
			if !strings.Contains(r.respBody, "could not resolve URL hostname") {
				t.Fatalf("did not reach the resolver's error path: status %d body %s", r.status, r.respBody)
			}
			if len(r.findings) != 0 {
				t.Fatalf("findings: %v", r.findings)
			}
		})
	}
}

// TestRequestEchoCanaryEchoRowsAreLive proves each echo row of requestEchoRules is
// needed and sufficient: its route still echoes when the row is absent, and is clean
// when it is present. A fix to the echo fails this test, so the row gets removed.
func TestRequestEchoCanaryEchoRowsAreLive(t *testing.T) {
	fx := newRequestEchoFixture(t)
	cases := []struct {
		route     string
		principal uint8
		shape     uint8
	}{
		{"GET /auth/sso/{provider}/login", 0, 0},
		{"POST /api/v1/notification-channels", 0, 0},
		{"GET /api/v1/secrets/{id}/access-log/export", 0, 9},
	}
	for _, tc := range cases {
		t.Run(tc.route, func(t *testing.T) {
			idx := slices.IndexFunc(fx.routes, func(r sweepRoute) bool { return r.String() == tc.route })
			if idx < 0 {
				t.Fatalf("route %s is not registered", tc.route)
			}
			in := requestEchoInput{route: uint16(idx), principal: tc.principal, shape: tc.shape}
			without, invalid := runRequestEcho(t, fx, t.TempDir(), in, canary.NewAllowlist(), nil, nil)
			if invalid != "" {
				t.Fatal(invalid)
			}
			echoed := slices.ContainsFunc(without.findings, func(s string) bool { return strings.Contains(s, "channel="+echoChanBody+" ") })
			if !echoed {
				t.Fatalf("no echo without the allowlist, so the row is stale; findings: %v", without.findings)
			}
			with, invalid := runRequestEcho(t, fx, t.TempDir(), in, requestEchoRules(), nil, nil)
			if invalid != "" {
				t.Fatal(invalid)
			}
			if len(with.findings) != 0 {
				t.Fatalf("findings with the allowlist: %v", with.findings)
			}
		})
	}
}

var (
	echoSweepAll  = flag.Bool("canary-echo-sweep", false, "TestRequestEchoCanarySweep: send every shape to every route (several minutes)")
	echoSweepOut  = flag.String("canary-echo-out", "", "TestRequestEchoCanarySweep: write the deduplicated findings to this file")
	echoSweepFrom = flag.Int("canary-echo-from", 0, "TestRequestEchoCanarySweep: first route index")
	echoSweepTo   = flag.Int("canary-echo-to", 1<<30, "TestRequestEchoCanarySweep: end route index (exclusive)")
)

// TestRequestEchoCanarySweep sends every shape to every route as every principal
// with -canary-echo-sweep (several minutes), and a sample otherwise. It fails on
// any finding.
func TestRequestEchoCanarySweep(t *testing.T) {
	fx := newRequestEchoFixture(t)
	step := 97
	if *echoSweepAll {
		step = 1
	}
	seen := map[string]string{}
	statuses := map[int]int{}
	// One directory per request under a parent t.TempDir: each is removed as soon as
	// the request ends, because a full sweep would otherwise keep every database copy
	// on disk until the test finished, and the parent is removed however the test ends.
	root := t.TempDir()
	t.Logf("routes: %d", len(fx.routes))
	for ri := *echoSweepFrom; ri < min(len(fx.routes), *echoSweepTo); ri += step {
		for pi := range 4 {
			for sh := range echoShapes {
				in := requestEchoInput{route: uint16(ri), principal: uint8(pi), shape: uint8(sh)}
				dir, err := os.MkdirTemp(root, "echo-sweep-*")
				if err != nil {
					t.Fatal(err)
				}
				r, invalid := runRequestEcho(t, fx, dir, in, requestEchoRules(), nil, nil)
				if invalid != "" {
					t.Fatalf("route %d principal %d shape %d: %s", ri, pi, sh, invalid)
				}
				statuses[r.status]++
				for _, f := range r.findings {
					key := fmt.Sprintf("%s|shape=%d", dedupeEchoFinding(f), sh)
					if _, ok := seen[key]; !ok {
						seen[key] = fmt.Sprintf("route=%d principal=%d shape=%d %s", ri, pi, sh, f)
					}
				}
				closeRequestEchoDB(r)
				_ = os.RemoveAll(dir)
			}
		}
	}
	t.Logf("statuses: %v, distinct findings: %d", statuses, len(seen))
	if statuses[http.StatusBadRequest] == 0 {
		t.Errorf("no request reached a 400, so the error paths were not exercised: %v", statuses)
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var out strings.Builder
	for _, k := range keys {
		out.WriteString(seen[k] + "\n")
	}
	if *echoSweepOut != "" {
		if err := os.WriteFile(*echoSweepOut, []byte(out.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) > 0 {
		t.Errorf("%d distinct findings:\n%s", len(seen), out.String())
	}
}

// dedupeEchoFinding removes the per-execution parts of a finding.
func dedupeEchoFinding(f string) string {
	before, _, _ := strings.Cut(f, " offset=")
	return before
}

func closeRequestEchoDB(r *requestEchoRun) {
	drainAllBackgroundGoroutines()
	if sqlDB, err := r.db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}
