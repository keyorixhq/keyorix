package cmd

// hostile_server_fuzz_test.go -- CL1 hostile-server target.
//
// FuzzCLIHostileServer drives the REAL CLI transport stack against a REAL httptest
// server that returns fuzzed/mutated/truncated/oversized/slow/redirecting/type-confused
// replies. The path under test is the one every authenticated command runs:
//
//     newAPIClient(url, token)            -- builds apiclient.NewHardenedHTTPClient
//       -> ClientWithResponses            -- the generated oapi-codegen client
//         -> cappingTransport (10 MiB cap), refuseRedirect, request timeout
//           -> ParseGetVersionResponse    -- io.ReadAll + json.Unmarshal of the body
//     checkVersionSkew / apiError / httpStatusError / statusExitCode / classifyError
//
// This is complementary to, NOT a duplicate of, FuzzApiError (CLI-FUZZ target 2),
// which fuzzes apiError(status, body) in isolation. FuzzApiError never exercises the
// transport (size cap, redirect refusal, content-type gating, timeout) nor the
// end-to-end decode. This target does.
//
// resguard: this test imports internal/fuzzutil/resguard (the shared resource helper)
// for its NetMeter (air-gap + dial/byte metering) and Probe (wall/alloc/goroutine
// metering). The CLI is a separate module contractually isolated from the main module
// (internal/depguard, INV-CLI-06); resguard is imported ONLY from this _test.go file,
// so it is a test-only dependency and never enters the shipped CLI binary. depguard
// walks the non-test graph and stays green. See the CL1 report for the issue-ready
// proposal to split a gorm-free resguard/meter subpackage.
//
// Oracles (each with what it does NOT verify in the CL1 report, §2):
//   O1 no-panic            -- fuzzutil.Guard around the whole command path.
//   O2 no-hang             -- cost.Wall < wallCeiling (a short ctx deadline backs it).
//   O3 air-gap/SSRF        -- cost.NonLoopbackDials == 0: a 3xx Location to a
//                             non-loopback host (cloud metadata IP) must never be dialed.
//   O4 no-redirect-forward -- the evil loopback redirect target records ZERO requests
//                             and ZERO Authorization headers (refuseRedirect fires).
//   O5 fail-closed         -- an unparsable/non-200/oversized/truncated reply is never
//                             returned as a populated success (skew.Result with data).
//   O6 size-cap            -- a reply larger than the 10 MiB cap errors (ErrResponseTooLarge).
//   O7 no-terminal-inject  -- nothing the CLI would print carries a raw control rune.
//   O8 no-secret-echo      -- the bearer token never appears in any printed/error text.
//   O9 exit-codes          -- apiError's attached exit code matches the DOCUMENTED table
//                             (401->3, 403->4, 404->5, else->1); a refused redirect ->
//                             exitUnreach (6) via classifyError.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// hostileToken is the planted bearer credential. O8 asserts it never leaks into any
// text the CLI prints; O4 asserts it is never forwarded to the redirect target. It is
// deliberately recognisable.
const hostileToken = "cli1-secret-token-DEADBEEFdonotEcho-7f3a"

// metadataSSRFHost is a non-loopback address a redirect might try to send the
// token-bearing request to (the classic cloud metadata SSRF sink). The hardened
// client must refuse the redirect; if a regression followed it, NetMeter's air-gap
// (O3) turns the input into a reproducer instead of a silent dial to 169.254.169.254.
const metadataSSRFHost = "169.254.169.254:80"

// Ceilings for the resource oracles. Generous (CLAUDE.md: timeouts detect hangs, they
// do not enforce speed) -- the point is to catch an unbounded hang/alloc, not to police
// milliseconds.
const (
	hostileWallCeiling  = 10 * time.Second
	hostileAllocCeiling = 96 << 20 // 96 MiB: the 10 MiB cap + decode overhead has huge headroom
	hostileGoroCeiling  = 2000
)

// hostileCtxDeadline bounds a single command's transport time so a "slow"/hang reply
// does not cost the full 60 s production timeout per exec. A reply slower than this is
// cut off here and must surface as a fail-closed error, not a hang.
const hostileCtxDeadline = 400 * time.Millisecond

func FuzzCLIHostileServer(f *testing.F) {
	// Seeds: a valid version reply, and the hostile shapes this target exists for.
	f.Add(200, uint8(0x00), []byte(`{"api_version":3,"minimum_cli_version":"1.0.0"}`))
	f.Add(404, uint8(0x00), []byte(``))                                                      // old-server warning path
	f.Add(500, uint8(0x40), []byte("{\"error\":\"boom\",\"message\":\"\x1b[31minjected\"}")) // escape in message
	f.Add(403, uint8(0x00), []byte(`{"error":"Forbidden","message":"no"}`))                  // exit-code 4
	f.Add(401, uint8(0x00), []byte(`{"error":"Unauthorized","message":"nope"}`))             // exit-code 3
	f.Add(302, uint8(0x01), []byte(``))                                                      // redirect -> evil loopback
	f.Add(302, uint8(0x03), []byte(``))                                                      // redirect -> metadata SSRF
	f.Add(200, uint8(0x04), []byte(`{"api_version":1}`))                                     // oversize -> cap
	f.Add(200, uint8(0x10), []byte(`<html>not json</html>`))                                 // 200 + wrong content-type
	f.Add(200, uint8(0x08), []byte(`{"api_version":1}`))                                     // truncated
	f.Add(200, uint8(0x20), []byte(`{"api_version":2}`))                                     // duplicate headers
	f.Add(200, uint8(0x00), []byte(`{"api_version":`))                                       // invalid JSON
	f.Add(200, uint8(0x80), []byte(`{"api_version":1}`))                                     // slow

	// A single shared "evil" redirect target on loopback. It records every request and
	// the Authorization header it saw. O4: refuseRedirect must keep this at zero forever.
	var evilHits atomic.Int64
	var evilAuthSeen atomic.Int64
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHits.Add(1)
		if r.Header.Get("Authorization") != "" {
			evilAuthSeen.Add(1)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"api_version":99}`))
	}))
	f.Cleanup(evil.Close)
	evilHost := evil.Listener.Addr().String()

	// NetMeter air-gapped: any non-loopback dial FAILS and is counted. Installed as the
	// process default transport so the hardened client (Transport: cappingTransport{base:
	// http.DefaultTransport}) dials through it. BlockDefaultResolver catches a bare DNS
	// lookup that would leave the host.
	nm := resguard.NewNetMeter()
	restoreT := nm.InstallDefault()
	f.Cleanup(restoreT)
	restoreR := nm.BlockDefaultResolver()
	f.Cleanup(restoreR)

	probe := resguard.New(f, resguard.Options{SampleEvery: 64, Net: nm})

	f.Fuzz(func(t *testing.T, status int, ctrl uint8, body []byte) {
		code := clampHostileStatus(status)
		sp := hostileSpec{code: code, ctrl: ctrl, body: body, evilHost: evilHost}

		srv := httptest.NewServer(http.HandlerFunc(sp.serve))
		defer srv.Close()

		client, err := newAPIClient(srv.URL, hostileToken)
		if err != nil {
			// A client-build failure is not a server-reply defect; skip.
			return
		}

		var skewRes any
		var skewErr error
		var verResp *struct {
			status  int
			body    []byte
			nilJSON bool
		}

		cost := probe.Measure(len(body), func() {
			fuzzutil.Guard(t.Fatalf, "CLI hostile-server command path", func() {
				ctx, cancel := context.WithTimeout(context.Background(), hostileCtxDeadline)
				defer cancel()

				// The real preamble every authenticated command runs.
				r, e := client.GetVersionWithResponse(ctx)
				if e != nil {
					skewErr = fmt.Errorf("contact server: %w", e)
					return
				}
				verResp = &struct {
					status  int
					body    []byte
					nilJSON bool
				}{status: r.StatusCode(), body: r.Body, nilJSON: r.JSON200 == nil}

				res, se := checkVersionSkew(ctx, client)
				skewRes, skewErr = res, se
				_ = skewRes
			})
		})
		resguard.FeedCoverage(cost)

		// ---- O2 no-hang -------------------------------------------------------
		if cost.Wall > hostileWallCeiling {
			t.Fatalf("HANG: command path took %v (> %v) for status=%d ctrl=%#x len=%d",
				cost.Wall, hostileWallCeiling, code, ctrl, len(body))
		}

		// ---- O3 air-gap / SSRF ------------------------------------------------
		if cost.NonLoopbackDials > 0 {
			t.Fatalf("SSRF/AIR-GAP: command path made %d non-loopback dial(s) for status=%d ctrl=%#x -- a redirect was followed off-host",
				cost.NonLoopbackDials, code, ctrl)
		}

		// ---- O4 no credential forwarding after redirect -----------------------
		if h := evilHits.Load(); h > 0 {
			t.Fatalf("REDIRECT-FORWARD: the evil redirect target received %d request(s); refuseRedirect did not fire", h)
		}
		if a := evilAuthSeen.Load(); a > 0 {
			t.Fatalf("CREDENTIAL-LEAK: the bearer token was forwarded to the redirect target %d time(s)", a)
		}

		// ---- O5/O6 fail-closed + size-cap -------------------------------------
		// Was this reply one that MUST parse cleanly? Only a 200 with a json
		// content-type, a valid version body, and no transport mutation.
		parseable := sp.isCleanParseable()
		if skewErr == nil {
			// skewErr==nil is only legitimate for (a) the clean-200 path, or
			// (b) the documented 404 "old server" warning path.
			if code != http.StatusNotFound && !parseable {
				t.Fatalf("FAIL-OPEN: an unparsable/non-200 reply (status=%d ctrl=%#x len=%d) was accepted as success (skewErr==nil); verResp=%+v",
					code, ctrl, len(body), verResp)
			}
		}
		if sp.isOversize() && skewErr == nil {
			t.Fatalf("SIZE-CAP BYPASS: an oversized reply (> cap) was accepted as success")
		}

		// ---- O7 no terminal injection + O8 no secret echo ---------------------
		// Every string the CLI would actually print on these paths.
		printed := hostilePrintedStrings(code, body, skewErr)
		for _, s := range printed {
			for _, r := range s {
				if unicode.IsControl(r) {
					t.Fatalf("TERMINAL-INJECT: printed text %q carries raw control rune %U (status=%d ctrl=%#x)", s, r, code, ctrl)
				}
			}
			if strings.Contains(s, hostileToken) {
				t.Fatalf("SECRET-ECHO: bearer token leaked into printed text %q (status=%d ctrl=%#x)", s, code, ctrl)
			}
		}

		// ---- O9 exit codes match the documented table -------------------------
		assertHostileExitCodes(t, code, body, skewErr, sp)

		// ---- resource ceilings (sampled) --------------------------------------
		if cost.Sampled && cost.AllocBytes > hostileAllocCeiling {
			t.Fatalf("MEMORY: %d alloc bytes (> %d) for status=%d ctrl=%#x len=%d",
				cost.AllocBytes, hostileAllocCeiling, code, ctrl, len(body))
		}
		if n := runtime.NumGoroutine(); n > hostileGoroCeiling {
			t.Fatalf("GOROUTINE LEAK: %d goroutines after status=%d ctrl=%#x", n, code, ctrl)
		}
	})
}

// hostileSpec captures how the fuzzed server should answer one request.
type hostileSpec struct {
	code     int
	ctrl     uint8
	body     []byte
	evilHost string
}

const (
	hcRedirect  = 0x01 // 3xx with Location
	hcMetadata  = 0x02 // redirect target = non-loopback metadata host (else evil loopback)
	hcOversize  = 0x04 // write a body larger than the 10 MiB cap
	hcTruncate  = 0x08 // hijack and write a truncated/malformed HTTP response
	hcWrongCT   = 0x10 // non-json content-type even on 200
	hcDupHeader = 0x20 // repeated headers
	hcEscapeMsg = 0x40 // JSON error envelope whose message carries escapes + the token
	hcSlow      = 0x80 // sleep before responding (bounded, honours ctx)
)

func (s hostileSpec) isRedirect() bool { return s.ctrl&hcRedirect != 0 }
func (s hostileSpec) isOversize() bool {
	return s.ctrl&hcOversize != 0 && !s.isRedirect() && s.ctrl&hcTruncate == 0
}

// isCleanParseable reports whether this reply is a well-formed 200 that
// checkVersionSkew is allowed to accept as a successful version read.
func (s hostileSpec) isCleanParseable() bool {
	if s.isRedirect() || s.ctrl&hcTruncate != 0 || s.isOversize() || s.ctrl&hcWrongCT != 0 {
		return false
	}
	if s.code != http.StatusOK {
		return false
	}
	// Must decode as the version struct (json.Unmarshal into a struct of pointers
	// tolerates missing fields but not malformed JSON).
	var dest struct {
		ApiVersion        *int    `json:"api_version,omitempty"`
		MinimumCliVersion *string `json:"minimum_cli_version,omitempty"`
	}
	return jsonValid(s.effectiveBody(), &dest)
}

// effectiveBody is the body bytes actually written for a normal (non-redirect,
// non-truncate) response, after the hcEscapeMsg transform.
func (s hostileSpec) effectiveBody() []byte {
	if s.ctrl&hcEscapeMsg != 0 {
		return escapeEnvelope(s.body)
	}
	return s.body
}

func (s hostileSpec) serve(w http.ResponseWriter, r *http.Request) {
	if s.ctrl&hcSlow != 0 {
		select {
		case <-time.After(hostileCtxDeadline + 100*time.Millisecond):
		case <-r.Context().Done():
			return // client gave up; do not pile up goroutines
		}
	}

	if s.isRedirect() {
		target := "http://" + s.evilHost + "/stolen"
		if s.ctrl&hcMetadata != 0 {
			target = "http://" + metadataSSRFHost + "/latest/meta-data/"
		}
		w.Header().Set("Location", target)
		w.WriteHeader(clampRedirectCode(s.code))
		return
	}

	if s.ctrl&hcTruncate != 0 {
		// Hijack and write a deliberately malformed/truncated HTTP response: a
		// Content-Length that over-promises, then an early close.
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1048576\r\n\r\n")
		_, _ = buf.Write(truncateBytes(s.body, 16))
		_ = buf.Flush()
		return
	}

	ct := "application/json"
	if s.ctrl&hcWrongCT != 0 {
		ct = "text/html; charset=utf-8"
	}
	w.Header().Set("Content-Type", ct)
	if s.ctrl&hcDupHeader != 0 {
		w.Header().Add("Content-Type", "application/xml")
		w.Header().Add("X-Keyorix-Dup", "a")
		w.Header().Add("X-Keyorix-Dup", "b")
		w.Header().Add("Set-Cookie", "s=1")
		w.Header().Add("Set-Cookie", "s=2")
	}

	if s.isOversize() {
		w.WriteHeader(s.code)
		// Write just over the 10 MiB cap in chunks; stop as soon as the client
		// disconnects (the cap trips and closes the body).
		chunk := make([]byte, 64<<10)
		for i := range chunk {
			chunk[i] = 'A'
		}
		const target = (10 << 20) + (256 << 10)
		written := 0
		for written < target {
			n, err := w.Write(chunk)
			written += n
			if err != nil {
				return
			}
		}
		return
	}

	w.WriteHeader(s.code)
	_, _ = w.Write(s.effectiveBody())
}

// escapeEnvelope builds a server {"error","message"} envelope whose message embeds
// terminal escape sequences, the raw fuzz bytes, and the planted token -- the exact
// shape a compromised server would use to try to inject the operator's terminal or
// bait the CLI into echoing its own credential. json.Marshal escapes control runes,
// so this is what a real server's JSON encoder would emit on the wire; the CLI's
// decode + SanitizeForTerminal is what must neutralise it.
func escapeEnvelope(raw []byte) []byte {
	msg := "\x1b[31m" + string(raw) + "\x1b]0;evil\a" + hostileToken
	return jsonMarshalEnvelope("HostileError", msg)
}

// hostilePrintedStrings returns every string the CLI would actually write to a
// terminal for this reply: the classified error message, and (for a non-2xx) the
// apiError/httpStatusError text. These are the terminal-injection + secret-echo surface.
func hostilePrintedStrings(code int, body []byte, skewErr error) []string {
	out := []string{}
	if skewErr != nil {
		_, msg := classifyError(skewErr, true)
		out = append(out, msg, skewErr.Error())
	}
	if code < 200 || code >= 300 {
		out = append(out,
			apiError("fuzz action", code, body).Error(),
			httpStatusError("fuzz what", code, body).Error(),
		)
	}
	return out
}

// assertHostileExitCodes checks O9: the exit code apiError attaches matches the
// DOCUMENTED table (not statusExitCode's own output -- a hardcoded expectation so a
// regression in statusExitCode is caught), and a refused redirect classifies as
// exitUnreach.
func assertHostileExitCodes(t *testing.T, code int, body []byte, skewErr error, sp hostileSpec) {
	t.Helper()
	if code < 200 || code >= 300 {
		want := documentedExitCode(code)
		err := apiError("fuzz action", code, body)
		got, _ := classifyError(err, true)
		if got != want {
			t.Fatalf("EXIT-CODE: apiError for HTTP %d classified as exit %d, documented table says %d", code, got, want)
		}
	}
	// A refused redirect (or a transport failure) must be exitUnreach (6).
	if sp.isRedirect() && skewErr != nil {
		got, _ := classifyError(skewErr, true)
		if got != exitUnreach {
			t.Fatalf("EXIT-CODE: a refused redirect classified as exit %d, documented table says %d (exitUnreach)", got, exitUnreach)
		}
	}
}

// documentedExitCode is the exit-code table as DOCUMENTED in exitcodes.go's
// exitCodesHelp, written out independently of statusExitCode so a drift between the
// two is a test failure.
func documentedExitCode(status int) int {
	switch status {
	case http.StatusUnauthorized:
		return exitAuth // 3
	case http.StatusForbidden:
		return exitPermission // 4
	case http.StatusNotFound:
		return exitNotFound // 5
	}
	return exitFailure // 1
}

// --- small helpers -----------------------------------------------------------

func clampHostileStatus(status int) int {
	// Map an arbitrary int into a FINAL HTTP status (200..599). 1xx codes are
	// excluded on purpose: net/http's WriteHeader treats a 1xx as an INTERIM
	// informational response and then sends 200 as the real status, so a 1xx here
	// would model a reply the harness cannot actually drive (the client sees 200,
	// not the 1xx) -- an artifact, not a CLI behaviour. Interim 1xx handling is a
	// separate surface noted in the CL1 report LEFTOVERS.
	if status < 0 {
		status = -status
	}
	return 200 + (status % 400)
}

func clampRedirectCode(code int) int {
	switch code {
	case 301, 302, 303, 307, 308:
		return code
	}
	return 302
}

func truncateBytes(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// jsonValid reports whether b unmarshals cleanly into dest.
func jsonValid(b []byte, dest any) bool {
	return json.Unmarshal(b, dest) == nil
}

// jsonMarshalEnvelope builds the {"error","message"} body a server sends on a
// non-2xx, with message properly JSON-escaped (what a real server's encoder emits).
func jsonMarshalEnvelope(errCode, message string) []byte {
	b, err := json.Marshal(map[string]string{"error": errCode, "message": message})
	if err != nil {
		return []byte(`{"error":"marshal-failed"}`)
	}
	return b
}
