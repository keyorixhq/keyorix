package httpx_test

// FuzzHTTPXDecodeEdge — GE1 server-edge target for the SHARED httpx request
// decoder (httpx.MustDecodeBody) driven behind the REAL production body-size
// middleware (server/middleware.MaxBodyBytes), with a sentinel "business logic"
// handler behind the decode.
//
// Non-duplicative scope (verified against FuzzJSONDecodeBoundedWork, which
// already covers bounded-work + nesting depth on the json.NewDecoder(r.Body)
// shape across six real decode call sites): this target adds the axes that one
// does NOT check —
//   - the decode-error RESPONSE must never echo the request body (a leak guard
//     on httpx.SendError's error envelope);
//   - FAIL-CLOSED through the real body cap: a decode/size failure must stop the
//     request at the decoder — the sentinel business handler must never run on a
//     body MustDecodeBody rejected (no partial struct reaching a handler);
//   - STATUS DISCIPLINE: every response code is in the bounded fail set
//     {200, 400, 413};
//   - content-type confusion / trailing data / huge numbers / charset: the
//     decoder IGNORES Content-Type and accepts trailing bytes after the first
//     JSON value (both are intentional-but-noteworthy today; this target
//     measures them and the GE1 report raises them as HARDENING observations,
//     not failures — there is nothing to crash, so asserting a crash would be a
//     test with a wrong premise).
//   - bounded work/memory via the shared internal/fuzzutil/resguard budget.
//
// Each oracle is red/green-proven in edge_decode_redgreen_test.go against the
// same decodeEdgeViolation predicate the fuzzer uses.

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
	"github.com/keyorixhq/keyorix/server/http/handlers/httpx"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// edgeBodyCanary is planted in some fuzz bodies; the decode-error response must
// never contain it (httpx.SendError writes a fixed envelope, so this is a
// regression guard against a future `details: requestBody`).
const edgeBodyCanary = "ge1bodycanary8k2"

// edgeDecodeCap mirrors the production body cap shape (a fixed byte ceiling the
// middleware enforces via http.MaxBytesReader). 1 MiB keeps fuzz exec/s high
// while still exercising the 413 path on an oversized body.
const edgeDecodeCap = 1 << 20

// decodeTarget is a representative request struct (a few typed fields) the
// handler decodes into, matching the common MustDecodeBody call shape.
type decodeTarget struct {
	Name    string         `json:"name"`
	Count   int64          `json:"count"`
	Enabled bool           `json:"enabled"`
	Extra   map[string]any `json:"extra"`
}

type decodeObservation struct {
	status   int
	reached  bool // the sentinel business handler ran (decode succeeded)
	okDecode bool // MustDecodeBody returned true
	respBody string
	bodyLen  int
	cost     resguard.Cost
}

var decodeEdgeStatuses = map[int]bool{
	http.StatusOK:                    true, // 200
	http.StatusBadRequest:            true, // 400 (InvalidJSON)
	http.StatusRequestEntityTooLarge: true, // 413 (MaxBytesReader)
}

// decodeEdgeViolation is the GE1 httpx-decode oracle, factored out so the
// red/green tests exercise the exact predicate. "" means every oracle held.
func decodeEdgeViolation(o decodeObservation, budget resguard.Budget) string {
	// Status discipline.
	if !decodeEdgeStatuses[o.status] {
		return "GE1X[status]: unexpected HTTP status " + fmt.Sprint(o.status)
	}
	// Fail-closed: the business handler ran IFF the decode succeeded.
	if o.reached != o.okDecode {
		return fmt.Sprintf("GE1X[fail-closed]: handler-reached=%v but decode-ok=%v (partial/garbage reach)", o.reached, o.okDecode)
	}
	// A rejected decode must be a 400/413, never a 200.
	if !o.okDecode && o.status == http.StatusOK {
		return "GE1X[fail-closed]: decode failed yet response was 200"
	}
	// Leak: the (error) response must not echo the request body canary.
	if strings.Contains(o.respBody, edgeBodyCanary) {
		return "GE1X[leak]: response echoes the request body canary: " + o.respBody
	}
	// Bounded work / memory.
	var bmsg string
	budget.Check(func(f string, a ...any) { bmsg = fmt.Sprintf(f, a...) }, o.cost)
	if bmsg != "" {
		return "GE1X[bounded]: " + bmsg
	}
	return ""
}

// edgeDecodeHandler is the production shape: MustDecodeBody, then (only on
// success) the sentinel "business logic". reached tracks whether that logic ran.
func edgeDecodeHandler(reached *bool, okDecode *bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var v decodeTarget
		if !httpx.MustDecodeBody(w, r, &v) {
			*okDecode = false
			return
		}
		*okDecode = true
		*reached = true
		_, _ = w.Write([]byte(`{"success":true}`))
	}
}

// buildDecodeRequest turns fuzz inputs into an HTTP request behind the real cap
// middleware, returning the recorder and the two tracking flags' addresses.
func runDecodeInput(sel byte, ctype string, body []byte) decodeObservation {
	var reached, okDecode bool
	h := middleware.MaxBodyBytes(edgeDecodeCap)(edgeDecodeHandler(&reached, &okDecode))

	method := http.MethodPost
	req := httptest.NewRequest(method, "/x", bytes.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	// Exercise content-length-declared-oversize vs chunked (unknown length) paths.
	switch sel % 3 {
	case 1:
		req.ContentLength = int64(len(body))
	case 2:
		req.ContentLength = -1 // unknown length — forces the MaxBytesReader path
		req.Header.Set("Transfer-Encoding", "chunked")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return decodeObservation{
		status: rec.Code, reached: reached, okDecode: okDecode,
		respBody: rec.Body.String(), bodyLen: len(body),
	}
}

func FuzzHTTPXDecodeEdge(f *testing.F) {
	probe := resguard.New(f, resguard.Options{})
	calProbe := resguard.New(f, resguard.Options{SampleEvery: 1})
	budget := decodeCalibrate(f, calProbe)
	f.Logf("GE1X httpx-decode: %s (platform %s)", budget.Summary(), resguard.Platform())

	for _, s := range decodeSeeds() {
		f.Add(s.sel, s.ctype, s.body)
	}

	f.Fuzz(func(t *testing.T, sel byte, ctype string, body []byte) {
		var obs decodeObservation
		cost := probe.Measure(len(body), func() { obs = runDecodeInput(sel, ctype, body) })
		obs.cost = cost
		if v := decodeEdgeViolation(obs, budget); v != "" {
			t.Fatalf("%s sel=%d ctype=%q bodyLen=%d", v, sel, ctype, len(body))
		}
	})
}

type decodeSeed struct {
	sel   byte
	ctype string
	body  []byte
}

func decodeSeeds() []decodeSeed {
	return []decodeSeed{
		{0, "application/json", []byte(`{}`)},
		{1, "application/json", []byte(`{"name":"a","count":5,"enabled":true}`)},
		{2, "text/plain", []byte(`{"name":"b"}`)},                     // content-type confusion
		{0, "application/json; charset=utf-16", []byte(`{"x":1}`)},    // charset trick
		{1, "application/json", []byte(`{"name":"a"} trailing junk`)}, // trailing data
		{0, "application/json", []byte(`{"count":1e400}`)},            // huge number
		{1, "application/json", []byte(`{"a":1,"a":2}`)},              // duplicate key
		{0, "application/json", []byte(`{"unknown":` + `"` + edgeBodyCanary + `"}`)},
		{2, "", bytes.Repeat([]byte("["), 20000)},            // deep nesting
		{0, "application/json", []byte("\xff\xfe not json")}, // invalid utf8
	}
}

func decodeCalibrate(f *testing.F, p *resguard.Probe) resguard.Budget {
	samples := make([]resguard.Cost, 0, 64)
	seeds := decodeSeeds()
	// Add larger benign bodies so the per-byte slope sees real sizes.
	seeds = append(seeds,
		decodeSeed{1, "application/json", []byte(`{"name":"` + strings.Repeat("a", 8192) + `"}`)},
		decodeSeed{0, "application/json", []byte(`{"extra":{` + strings.Repeat(`"k":1,`, 2000) + `"z":1}}`)},
	)
	for i := 0; i < 3; i++ {
		for _, s := range seeds {
			c := p.Measure(len(s.body), func() { _ = runDecodeInput(s.sel, s.ctype, s.body) })
			samples = append(samples, c)
		}
	}
	b := resguard.Calibrate("httpx-decode-edge", samples, 10.0)
	// live_heap is whole-process after-GC (not this input's cost) — prune it, keep
	// the per-input-attributable alloc/mallocs as the bounded-memory oracle.
	b.KeepOnly("alloc_bytes", "mallocs", "wall_ns", "cpu_ns")
	return b
}
