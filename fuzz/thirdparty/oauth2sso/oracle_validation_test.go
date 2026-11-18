package oauth2sso

// oracle_validation_test.go — red/green proof that every oracle in
// FuzzOAuth2HostileTokenEndpoint is LIVE (fires on a planted violation) and QUIET (does
// not fire on correct behaviour). A guard nobody has watched fail is not a guard.
//
// For a third-party library we cannot edit oauth2 to plant a bug, so each oracle is proven
// two ways: (1) the detector (checkOracles) is driven with a synthetic violating tuple and
// must fatal, and with a correct tuple and must not; (2) where feasible the REAL Exchange
// is driven end to end to confirm the oracle's premise about the real library holds
// (e.g. oauth2 really does fail closed on truncation), so the green side is not vacuous.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// fatalPanic is raised by the recording fatalf so control unwinds at the first violation,
// mirroring t.Fatalf's runtime.Goexit stop semantics.
type fatalPanic struct{ msg string }

func recordingFatalf(msgs *[]string) func(string, ...any) {
	return func(format string, args ...any) {
		m := fmt.Sprintf(format, args...)
		*msgs = append(*msgs, m)
		panic(fatalPanic{m})
	}
}

// expectFatal runs fn and asserts it fataled with a message containing want.
func expectFatal(t *testing.T, want string, fn func(fatalf func(string, ...any))) {
	t.Helper()
	var msgs []string
	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatalf("expected a fatal containing %q, but none fired", want)
			}
			if _, ok := r.(fatalPanic); !ok {
				panic(r)
			}
		}()
		fn(recordingFatalf(&msgs))
	}()
	if len(msgs) == 0 || !strings.Contains(msgs[len(msgs)-1], want) {
		t.Fatalf("fatal fired but message %q does not contain %q", msgs, want)
	}
}

// expectNoFatal runs fn and asserts it did NOT fatal.
func expectNoFatal(t *testing.T, fn func(fatalf func(string, ...any))) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			if fp, ok := r.(fatalPanic); ok {
				t.Fatalf("unexpected fatal: %s", fp.msg)
			}
			panic(r)
		}
	}()
	fn(recordingFatalf(&[]string{}))
}

func validToken() *oauth2.Token { return &oauth2.Token{AccessToken: "at", TokenType: "Bearer"} }

func TestOracle_Truncation_RedGreen(t *testing.T) {
	// RED: truncated response accepted as success.
	expectFatal(t, "FAILS-OPEN", func(f func(string, ...any)) {
		checkOracles(f, true, validToken(), nil, resguard.Cost{Dials: 2}, 10)
	})
	// GREEN: truncated but errored (what a correct oauth2 does) → no fire.
	expectNoFatal(t, func(f func(string, ...any)) {
		checkOracles(f, true, nil, errors.New("oauth2: cannot fetch token: unexpected EOF"), resguard.Cost{Dials: 2}, 10)
	})
	// GREEN premise, end to end: the REAL Exchange must fail closed on a truncated body.
	nm := resguard.NewNetMeter()
	resp, truncated := rawResponse(200, "application/json", true, []byte(`{"access_token":"at","token_type":"Bearer"}`))
	if !truncated {
		t.Fatal("setup: expected truncated=true for a 200 with lie")
	}
	tok, err := driveExchange(t, nm, resp)
	if err == nil {
		t.Fatalf("PREMISE BROKEN: real oauth2 accepted a truncated response as success: %+v", tok)
	}
}

func TestOracle_CanaryLeak_RedGreen(t *testing.T) {
	// RED: secret in the error string.
	expectFatal(t, "LEAK", func(f func(string, ...any)) {
		checkOracles(f, false, nil, errors.New("boom "+fuzzClientSecret), resguard.Cost{}, 10)
	})
	// RED: secret in a token field.
	expectFatal(t, "LEAK", func(f func(string, ...any)) {
		checkOracles(f, false, &oauth2.Token{AccessToken: "x" + fuzzClientSecret}, nil, resguard.Cost{}, 10)
	})
	// GREEN: no secret anywhere.
	expectNoFatal(t, func(f func(string, ...any)) {
		checkOracles(f, false, validToken(), nil, resguard.Cost{Dials: 2}, 10)
	})
	// Liveness end to end: a (hypothetically leaky) server that echoes the secret in its
	// error body makes RetrieveError.Error() contain it, and the leak oracle fires. This is
	// the echo-class caveat made explicit: in the fuzz run the fuzzer never knows the
	// secret, so a real fire is a genuine leak — here we plant it only to prove the detector
	// is wired to the real returned error.
	// A text/plain 4xx with no "error=" key leaves RetrieveError.ErrorCode empty, so
	// Error() falls to the branch that echoes the raw Body — surfacing the planted secret.
	nm := resguard.NewNetMeter()
	resp, _ := rawResponse(400, "text/plain", false, []byte("upstream said: "+fuzzClientSecret))
	_, err := driveExchange(t, nm, resp)
	if err == nil || !strings.Contains(err.Error(), fuzzClientSecret) {
		t.Fatalf("setup: expected the planted secret to surface in the error body echo; got %v", err)
	}
	expectFatal(t, "LEAK", func(f func(string, ...any)) {
		checkOracles(f, false, nil, err, resguard.Cost{}, 10)
	})
}

func TestOracle_SuccessInvariant_RedGreen(t *testing.T) {
	expectFatal(t, "nil token", func(f func(string, ...any)) {
		checkOracles(f, false, nil, nil, resguard.Cost{}, 10)
	})
	expectFatal(t, "empty access_token", func(f func(string, ...any)) {
		checkOracles(f, false, &oauth2.Token{AccessToken: ""}, nil, resguard.Cost{}, 10)
	})
	expectNoFatal(t, func(f func(string, ...any)) {
		checkOracles(f, false, validToken(), nil, resguard.Cost{Dials: 2}, 10)
	})
}

func TestOracle_AirGapAndBounds_RedGreen(t *testing.T) {
	expectFatal(t, "AIR-GAP", func(f func(string, ...any)) {
		checkOracles(f, false, validToken(), nil, resguard.Cost{NonLoopbackDials: 1}, 10)
	})
	expectFatal(t, "DIAL STORM", func(f func(string, ...any)) {
		checkOracles(f, false, validToken(), nil, resguard.Cost{Dials: dialCeiling + 1}, 10)
	})
	expectFatal(t, "UNBOUNDED READ", func(f func(string, ...any)) {
		checkOracles(f, false, validToken(), nil, resguard.Cost{NetBytesIn: netInCeiling + 1}, 10)
	})
	expectFatal(t, "ALLOC AMPLIFICATION", func(f func(string, ...any)) {
		checkOracles(f, false, validToken(), nil, resguard.Cost{Sampled: true, AllocBytes: allocCeiling + 1}, 10)
	})
	// GREEN: within every bound.
	expectNoFatal(t, func(f func(string, ...any)) {
		checkOracles(f, false, validToken(), nil, resguard.Cost{Dials: 2, NetBytesIn: 2048, Sampled: true, AllocBytes: 1 << 16}, 10)
	})
}

// Note on the no-panic / no-hang oracles: a panic in oauth2 during Exchange is recorded
// natively by the Go fuzz engine (which fails the run and saves the input), and a hang is
// caught by the shared, independently-tested fuzzutil.Guard timeout (fires above
// fuzzutil.GuardTimeout, default 3s). Neither is re-proven here; the detectors proven
// red/green above are the harness-specific oracles in checkOracles.

// TestExchange_ValidToken_Green drives the real oauth2.Exchange against a well-formed JSON
// token response and asserts a usable token with no oracle firing — the integration green.
func TestExchange_ValidToken_Green(t *testing.T) {
	nm := resguard.NewNetMeter()
	resp, _ := rawResponse(200, "application/json", false, []byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600,"id_token":"idt"}`))
	tok, err := driveExchange(t, nm, resp)
	if err != nil {
		t.Fatalf("valid token response errored: %v", err)
	}
	if tok == nil || tok.AccessToken != "at" {
		t.Fatalf("expected access_token=at, got %+v", tok)
	}
	if raw, _ := tok.Extra("id_token").(string); raw != "idt" {
		t.Fatalf("expected id_token=idt in extras, got %q", raw)
	}
	dials, nonLoop, _, _ := netMeterRead(nm)
	expectNoFatal(t, func(f func(string, ...any)) {
		checkOracles(f, false, tok, err, resguard.Cost{Dials: dials, NonLoopbackDials: nonLoop}, 10)
	})
}

// driveExchange runs the real oauth2.Config.Exchange against a one-shot loopback server
// that serves resp, mirroring the fuzz target's wiring.
func driveExchange(t *testing.T, nm *resguard.NetMeter, resp []byte) (*oauth2.Token, error) {
	t.Helper()
	srv := hostile.NewServer(t, func(c net.Conn) { serveRaw(c, resp) })
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), exchangeDeadline)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, meteredClient(nm))
	cfg := exchangeConfig("http://" + srv.Addr() + "/token")
	return cfg.Exchange(ctx, "code", oauth2.VerifierOption("verifier-0123456789abcdef"))
}

func netMeterRead(nm *resguard.NetMeter) (dials, nonLoop int, _ int64, _ int64) {
	return nm.Count(), nm.NonLoopback(), 0, 0
}
