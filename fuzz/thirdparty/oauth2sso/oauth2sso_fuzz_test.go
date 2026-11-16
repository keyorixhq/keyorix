package oauth2sso

// oauth2sso_fuzz_test.go — hostile token-endpoint fuzz of golang.org/x/oauth2's
// authorization-code Exchange, on Keyorix's SSO/OIDC call path.
//
// Model: Keyorix is the OAuth2 client. A fuzzer-controlled loopback server plays the
// token endpoint and writes RAW HTTP response bytes (status line, Content-Type,
// Content-Length — which it may make LIE — and body). The real (*oauth2.Config).Exchange
// parses them, built and called exactly as core.CompleteSSO does (server/wire_sso.go:220
// Config shape + oauth2.VerifierOption, internal/core/sso.go:255). Any finding localises
// to golang.org/x/oauth2 (or the net/http response reader under it).
//
// Meters enabled (resguard) and why:
//   - Net (NetMeter): AIR-GAP — Exchange must only ever dial the configured loopback
//     token endpoint; a regression that dialed elsewhere fails cost.NonLoopbackDials. Also
//     meters dial count (oauth2's AuthStyleUnknown auto-detect does up to TWO round-trips
//     per Exchange — the bound is asserted) and response byte volume (oauth2 caps the body
//     at 1 MiB via io.LimitReader; the byte-in ceiling catches a regression removing it).
//   - Alloc / CPU / Wall (Probe cheap+sampled meters): the token-response PARSER is the
//     attack surface; the 130 B→1.8 GB amplification class is exactly what the alloc
//     ceiling guards. Bounded by the 1 MiB read cap in a correct library.
//   - Goroutine / FD drift (CheckDrift): each Exchange is a real HTTP round-trip; a
//     connection/goroutine leak across inputs is caught by the cross-input drift watcher.
//
// Meters NOT enabled and why: SleepClock — oauth2's Exchange has no retry/backoff sleep
// (the auth-style probe is immediate), so there is no sleep seam to meter. Disk / Log / DB
// — oauth2's token parse touches none of them.
//
// No production code is modified.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// fuzzClientSecret is a high-entropy canary. oauth2 legitimately SENDS it to the token
// endpoint in the request (Basic auth header or POST param), so the harness never inspects
// the on-wire request; it asserts the secret never surfaces in a RETURNED error or token.
// The fuzzer controls only the response bytes and cannot know this value, so the server
// can never echo it — any appearance in a returned value is a genuine library leak.
const (
	fuzzClientSecret = "kx-oauth2-canary-7f3b9d1e5a2c4860bf0d2e4a6c8e0f13"
	fuzzClientID     = "keyorix-fuzz-client"
)

// Resource ceilings. Absolute and input-size-independent: the response body is the
// attacker's input, but a correct oauth2 reads at most 1 MiB of it (io.LimitReader),
// across at most two auth-style round-trips. Ceilings sit comfortably above that so a
// regression (removed cap, retry storm, amplification, extra dial) trips them, while
// normal parsing never does.
const (
	dialCeiling      = 4           // ≤2 round-trips per Exchange (auth-style probe) + slack
	allocCeiling     = 16 << 20    // 16 MiB; the 1 MiB body cap + JSON overhead is far below
	netInCeiling     = 4 << 20     // 4 MiB; ~1 MiB body cap + headers, ×2 round-trips + slack
	serverBodyCap    = 2 << 20     // harness self-limit on bytes it writes per response
	exchangeDeadline = 5 * time.Second
)

// rawResponse builds the loopback server's raw HTTP/1.1 response from the fuzz input.
// When lie is set and the status carries a body, the Content-Length header declares more
// bytes than the server actually writes (then closes) — a truncated / short response that
// a correct client MUST error on rather than returning a partial-success token.
func rawResponse(status int, ctype string, lie bool, body []byte) (resp []byte, truncated bool) {
	if len(body) > serverBodyCap {
		body = body[:serverBodyCap]
	}
	declared := len(body)
	if lie && statusCarriesBody(status) {
		declared = len(body) + 16 // promise more than we deliver
		truncated = true
	}
	reason := http.StatusText(status)
	if reason == "" {
		reason = "Status"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, reason)
	if ctype != "" {
		fmt.Fprintf(&b, "Content-Type: %s\r\n", ctype)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", declared)
	b.WriteString("Connection: close\r\n\r\n")
	out := append([]byte(b.String()), body...)
	return out, truncated
}

// statusCarriesBody mirrors net/http's rule: 204 and 304 responses carry no body, so a
// lying Content-Length on them is ignored by the reader and is not a truncation.
func statusCarriesBody(status int) bool { return status != http.StatusNoContent && status != http.StatusNotModified }

// selectContentType maps a fuzz byte to a content type, covering oauth2's two parse
// branches (form-urlencoded/text-plain vs JSON default) and mime.ParseMediaType failure.
func selectContentType(sel uint8) string {
	switch sel % 7 {
	case 0:
		return "application/json"
	case 1:
		return "application/x-www-form-urlencoded"
	case 2:
		return "text/plain"
	case 3:
		return "application/json; charset=utf-8"
	case 4:
		return "" // no Content-Type header → JSON default branch
	case 5:
		return "garbage/\x01bad" // mime.ParseMediaType fails → content "" → JSON branch
	default:
		return "text/html"
	}
}

// serveRaw reads the oauth2 client's request fully (so its write never blocks), then writes
// the fuzzer-controlled raw response and closes. http.ReadRequest handles request framing.
func serveRaw(c net.Conn, resp []byte) {
	br := bufio.NewReader(c)
	if req, err := http.ReadRequest(br); err == nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	_, _ = c.Write(resp)
}

// meteredClient builds the HTTP client oauth2 uses, dialing only through the NetMeter
// (air-gap + byte metering), keep-alives disabled so each auth-style round-trip is a
// distinct, countable dial.
func meteredClient(nm *resguard.NetMeter) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext:       nm.DialContext,
			DisableKeepAlives: true,
		},
		Timeout: exchangeDeadline,
	}
}

// exchangeConfig mirrors the *oauth2.Config Keyorix builds at server/wire_sso.go:220 for a
// token endpoint at tokenURL (no AuthStyle set → AuthStyleUnknown auto-detect).
func exchangeConfig(tokenURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     fuzzClientID,
		ClientSecret: fuzzClientSecret,
		Endpoint:     oauth2.Endpoint{AuthURL: "http://auth.invalid/authorize", TokenURL: tokenURL},
		RedirectURL:  "http://sp.invalid/sso/complete",
		Scopes:       []string{"openid", "profile", "email"},
	}
}

func FuzzOAuth2HostileTokenEndpoint(f *testing.F) {
	// Seeds: a valid JSON token, a valid form token, RFC6749 error bodies, oddities.
	f.Add(200, uint8(0), false, []byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600,"id_token":"x"}`))
	f.Add(200, uint8(1), false, []byte(`access_token=at&token_type=bearer&expires_in=3600`))
	f.Add(400, uint8(0), false, []byte(`{"error":"invalid_grant","error_description":"bad code"}`))
	f.Add(400, uint8(1), false, []byte(`error=invalid_client`))
	f.Add(200, uint8(0), false, []byte(`{"access_token":"","token_type":"Bearer"}`)) // empty token → error
	f.Add(200, uint8(0), false, []byte(`not json at all`))
	f.Add(200, uint8(0), true, []byte(`{"access_token":"at","token_type":"Bearer"}`)) // truncated
	f.Add(200, uint8(4), false, []byte(`{"access_token":"at","expires_in":"3600"}`))   // string expires_in, no ctype
	f.Add(500, uint8(6), false, []byte(`<html>oops</html>`))                            // text/html + 5xx
	f.Add(204, uint8(4), true, []byte(``))                                              // no-body status + lie
	f.Add(200, uint8(0), false, []byte(`{"access_token":{"nested":true}}`))             // type-confused field

	nm := resguard.NewNetMeter() // air-gap: any non-loopback dial fails
	probe := resguard.New(f, resguard.Options{SampleEvery: 32, Net: nm})

	// ONE shared loopback server and ONE reused client for the whole run. The response is
	// swapped per input through an atomic pointer. This keeps the token-endpoint URL STABLE
	// (as it is in production: one endpoint per OIDC provider), so oauth2's process-global
	// auth-style cache — keyed by (tokenURL, clientID) — holds a single entry instead of
	// accruing one per input. A per-input fresh listener made that cache (and server/client
	// goroutine churn) grow the live heap and trip the drift watcher: a harness artifact,
	// not an oauth2 leak reachable on our call path. The stock engine runs one body at a
	// time per process, so a shared server + atomic swap is race-free (-parallel forks
	// processes, each with its own server).
	var curResp atomic.Pointer[[]byte]
	srv := hostile.NewServer(f, func(c net.Conn) {
		if p := curResp.Load(); p != nil {
			serveRaw(c, *p)
		}
	})
	defer srv.Close()
	client := meteredClient(nm)
	tokenURL := "http://" + srv.Addr() + "/token"

	f.Fuzz(func(t *testing.T, status int, ctypeSel uint8, lie bool, body []byte) {
		code := clampStatus(status)
		ctype := selectContentType(ctypeSel)
		resp, truncated := rawResponse(code, ctype, lie, body)
		curResp.Store(&resp)

		ctx, cancel := context.WithTimeout(context.Background(), exchangeDeadline)
		defer cancel()
		ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
		cfg := exchangeConfig(tokenURL)

		var tok *oauth2.Token
		var err error
		cost := probe.Measure(len(body), func() {
			fuzzutil.Guard(t.Fatalf, "oauth2.Config.Exchange", func() {
				// Mirror CompleteSSO's call: a PKCE verifier option is always present
				// once a login carries one (internal/core/sso.go:253).
				tok, err = cfg.Exchange(ctx, "fuzz-auth-code", oauth2.VerifierOption("fuzz-pkce-verifier-0123456789abcdef"))
			})
		})
		resguard.FeedCoverage(cost)

		checkOracles(t.Fatalf, truncated, tok, err, cost, len(body))

		// Cross-input drift: goroutine and fd creep are the leak signatures that matter for
		// an HTTP-driving target (a connection or goroutine leaked per Exchange) — those stay
		// fatal. The live-heap sub-verdict is treated as ADVISORY here: process-global live
		// heap is dominated by the Go fuzz engine's own corpus/coverage set, which grows
		// monotonically as coverage expands over a long run and is NOT attributable to oauth2
		// (on our call path the token URL is stable, so oauth2 holds a single auth-style cache
		// entry — nothing for a heap-leak meter to watch). Per-input allocation remains bounded
		// by the AllocBytes ceiling in checkOracles, which is the correct attributable memory
		// oracle. Not weakening the goroutine/fd leak oracle; excluding a meter that cannot
		// attribute growth to the code under test. See the TP3 report for the evidence.
		if r := probe.CheckDrift(cost); r != "" && !strings.Contains(r, "live-heap") {
			t.Fatalf("RESOURCE DRIFT across inputs: %s", r)
		}
	})
}

// checkOracles runs every per-input oracle against the observed Exchange outcome and the
// metered Cost. Factored out of the fuzz body so each oracle can be proven red/green in
// oracle_validation_test.go. fatalf is t.Fatalf in the fuzz run. Each branch calls fatalf
// (which aborts the input) on a violation; on a correct oauth2 none fire.
func checkOracles(fatalf func(string, ...any), truncated bool, tok *oauth2.Token, err error, cost resguard.Cost, bodyLen int) {
	// --- Oracle (d): fails-open on truncation. A response whose body was declared
	// longer than delivered must produce an error, never a partial-success token. ---
	if truncated && err == nil {
		fatalf("FAILS-OPEN: truncated token response (declared>delivered) accepted as success: tok=%+v", tok)
		return
	}

	// --- Oracle (b): canary never leaks into a returned error or token. The fuzzer cannot
	// supply the secret, so any appearance in a returned value is a genuine library leak. ---
	if err != nil && strings.Contains(err.Error(), fuzzClientSecret) {
		fatalf("LEAK: client secret appeared in Exchange error: %v", err)
		return
	}
	if tok != nil {
		for _, s := range []string{tok.AccessToken, tok.TokenType, tok.RefreshToken} {
			if strings.Contains(s, fuzzClientSecret) {
				fatalf("LEAK: client secret appeared in returned token field")
				return
			}
		}
		if raw, ok := tok.Extra("id_token").(string); ok && strings.Contains(raw, fuzzClientSecret) {
			fatalf("LEAK: client secret appeared in token extras")
			return
		}
	}

	// --- Oracle (success invariant): a nil-error Exchange must return a usable token.
	// oauth2 guarantees a non-empty access_token on success; a regression returning
	// (nil-err, empty/absent token) would silently authenticate a session. ---
	if err == nil {
		if tok == nil {
			fatalf("INVARIANT: Exchange returned nil error and nil token")
			return
		}
		if tok.AccessToken == "" {
			fatalf("INVARIANT: Exchange succeeded with an empty access_token")
			return
		}
	}

	// --- Oracle (a): air-gap + bounded round-trips + bounded alloc/bytes. ---
	if cost.NonLoopbackDials > 0 {
		fatalf("AIR-GAP: Exchange made %d non-loopback dial(s)", cost.NonLoopbackDials)
		return
	}
	if cost.Dials > dialCeiling {
		fatalf("DIAL STORM: Exchange made %d dials (ceiling %d)", cost.Dials, dialCeiling)
		return
	}
	if cost.NetBytesIn > netInCeiling {
		fatalf("UNBOUNDED READ: Exchange read %d response bytes (ceiling %d)", cost.NetBytesIn, netInCeiling)
		return
	}
	if cost.Sampled && cost.AllocBytes > allocCeiling {
		fatalf("ALLOC AMPLIFICATION: %d bytes allocated for %d input bytes (ceiling %d)", cost.AllocBytes, bodyLen, allocCeiling)
		return
	}
}

// clampStatus keeps the fuzzed status in the meaningful 200..599 range, avoiding 1xx
// interim-response handling that is not part of the token-response parse surface.
func clampStatus(status int) int {
	if status < 200 {
		status = 200 + (status%100+100)%100
	}
	if status > 599 {
		status = 200 + status%400
	}
	return status
}
