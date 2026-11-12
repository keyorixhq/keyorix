package hostile

// known_selftest_test.go: validity of the Known-findings filter and of the
// no-response replay rule in Delivery/Intact. Each property is checked in both
// directions: the filter suppresses the hit it names AND still reports a hit
// it does not name; the replay rule accepts a transport replay AND still fails
// a success that rests on no response at all.

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// faultAcceptClose is the 1-based Fault index of "accept-close".
var faultAcceptClose = 1 + slices.Index(faults, "accept-close")

// runFinish runs toy c under cfg and returns what Finish would fail with.
func runFinish(t *testing.T, c toy, p Program, cfg Config) []string {
	t.Helper()
	cfg.Routes, cfg.Program, cfg.RecoverPanics = toyRoutes(), p, true
	if cfg.CallTimeout == 0 {
		cfg.CallTimeout = 150 * time.Millisecond
	}
	h := New(cfg)
	var val string
	err := h.Run("toy", func(ctx context.Context) error {
		var e error
		val, e = c(ctx, h.URL())
		return e
	})
	check(h, val, err)
	var failed []string
	h.Finish(func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) })
	return failed
}

var p5Prog = Program{Ops: []Op{{12, 1, 0}}}

func TestKnownSuppressesOnlyWhatItNames(t *testing.T) {
	echo := Known{ID: "SELFTEST-O7", Prefix: "O7 LEAK: toy:"}
	t.Setenv("KX_HOSTILE_ALLOW", "")

	if f := runFinish(t, p5EchoSecret, p5Prog, Config{}); len(f) == 0 {
		t.Fatal("without a Known entry the planted O7 must fail Finish")
	}
	if f := runFinish(t, p5EchoSecret, p5Prog, Config{Known: []Known{echo}}); len(f) != 0 {
		t.Fatalf("the Known entry must suppress the hit it names: %v", f)
	}
	// Novel findings are still reported: a different oracle class (P1, O5)
	// under the same Known entry.
	if f := runFinish(t, p1EmptyOK, Program{Ops: []Op{{1, 1, 0}}}, Config{Known: []Known{echo}}); len(f) == 0 || !strings.Contains(f[0], "O5") {
		t.Fatalf("an O7 Known entry must not hide an O5 finding: %v", f)
	}
	// Narrowing: ErrContains and When must both hold.
	narrowErr := echo
	narrowErr.ErrContains = "text-that-the-toy-never-returns"
	if f := runFinish(t, p5EchoSecret, p5Prog, Config{Known: []Known{narrowErr}}); len(f) == 0 {
		t.Fatal("a Known entry whose ErrContains does not match must not suppress")
	}
	narrowWhen := echo
	narrowWhen.When = func(*Harness) bool { return false }
	if f := runFinish(t, p5EchoSecret, p5Prog, Config{Known: []Known{narrowWhen}}); len(f) == 0 {
		t.Fatal("a Known entry whose When is false must not suppress")
	}
	narrowOK := echo
	narrowOK.ErrContains = "unexpected secret format"
	narrowOK.When = func(h *Harness) bool { return len(h.Served("secret")) == 1 }
	if f := runFinish(t, p5EchoSecret, p5Prog, Config{Known: []Known{narrowOK}}); len(f) != 0 {
		t.Fatalf("a Known entry whose ErrContains and When both hold must suppress: %v", f)
	}
}

type fakeTB struct{ failed []string }

func (*fakeTB) Helper() {}
func (f *fakeTB) Fatalf(format string, args ...any) {
	f.failed = append(f.failed, fmt.Sprintf(format, args...))
}

func toyHarness(c toy, p Program) *Harness {
	h := New(Config{Routes: toyRoutes(), Program: p, RecoverPanics: true, CallTimeout: 150 * time.Millisecond})
	var val string
	err := h.Run("toy", func(ctx context.Context) error {
		var e error
		val, e = c(ctx, h.URL())
		return e
	})
	check(h, val, err)
	return h
}

func TestRequireKnownReproducesGoesRedWhenFixed(t *testing.T) {
	k := Known{ID: "SELFTEST-O7", Prefix: "O7 LEAK: toy:", Repro: p5Prog}
	var defect fakeTB
	RequireKnownReproduces(&defect, k, toyHarness(p5EchoSecret, p5Prog))
	if len(defect.failed) != 0 {
		t.Fatalf("reproducer must pass while the defect is present: %v", defect.failed)
	}
	var fixed fakeTB
	RequireKnownReproduces(&fixed, k, toyHarness(control, p5Prog))
	if len(fixed.failed) == 0 {
		t.Fatal("reproducer must fail once the defect is fixed (control client)")
	}
	// Evaluate reports a hit even when the harness was configured to suppress it.
	h := New(Config{Routes: toyRoutes(), Program: p5Prog, CallTimeout: 150 * time.Millisecond, Known: []Known{k}})
	_ = h.Run("toy", func(ctx context.Context) error { _, e := p5EchoSecret(ctx, h.URL()); return e })
	if vs := h.Evaluate(); len(vs) == 0 {
		t.Fatal("Evaluate must return suppressed violations too")
	}
}

// p10InventsOnNoResponse returns a cached value when the backend closes the
// connection without answering: success that rests on no response at all.
func p10InventsOnNoResponse(ctx context.Context, base string) (string, error) {
	cl := &http.Client{CheckRedirect: refuse}
	if _, _, err := fetch(ctx, cl, base+"/secret", 1<<20); err != nil {
		return toyValue, nil // BUG: stale/invented value on a transport failure
	}
	return toyValue, nil
}

func TestNoResponseLastExchangeStillFails(t *testing.T) {
	p := Program{Fault: faultAcceptClose}
	v := run(t, p10InventsOnNoResponse, p, Config{})
	if !slices.ContainsFunc(v, func(m string) bool { return strings.HasPrefix(m, "O5") }) {
		t.Fatalf("a success with no consumed response must be O5; got %v", v)
	}
	if v := run(t, control, p, Config{}); len(v) != 0 {
		t.Fatalf("control must be silent on accept-close: %v", v)
	}
}

// TestNoResponseReplayIsNotConsumed: net/http replays an idempotent GET when a
// REUSED connection is closed before any response byte. The replayed exchange
// is the one the client consumed; the closed one must not fail the judgement.
func TestNoResponseReplayIsNotConsumed(t *testing.T) {
	routes := []Route{
		{Name: "warm", Method: "GET", Prefix: "/warm", Valid: func(int, *http.Request) Resp {
			return Resp{Status: 200, CT: "application/json", Body: []byte(`{}`)}
		}},
		toyRoutes()[0],
	}
	// Ceiling 2: the client makes two requests; the replay is net/http's (O8).
	h := New(Config{Routes: routes, Program: Program{Route: 1, Fault: faultAcceptClose}, CallTimeout: time.Second, RequestCeiling: 2})
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, CheckRedirect: refuse}
	var val string
	err := h.Run("toy", func(ctx context.Context) error {
		if _, _, err := fetch(ctx, cl, h.URL()+"/warm", 1<<20); err != nil {
			return err
		}
		b, code, err := fetch(ctx, cl, h.URL()+"/secret", 1<<20)
		if err != nil || code != 200 {
			return fmt.Errorf("status %d: %v", code, err)
		}
		v, _, ok := strict(b)
		if !ok {
			return fmt.Errorf("no value")
		}
		val = v
		return nil
	})
	recs := h.Served("secret")
	if err != nil || len(recs) != 2 || !recs[0].NoResponse {
		t.Fatalf("premise: expected a transport replay (2 exchanges, first with no response); err=%v served=%+v", err, recs)
	}
	check(h, val, err)
	if _, kind := h.Delivery("secret", func(b []byte) bool { _, _, ok := strict(b); return ok }); kind != "" {
		t.Fatalf("Delivery judged the replay as %q", kind)
	}
	if vs := h.Evaluate(); len(vs) != 0 {
		t.Fatalf("a transport replay after a no-response close must not be a violation: %v", vs)
	}
}

// pRetriesForever retries a failed fetch far past any ceiling.
func pRetriesForever(ctx context.Context, base string) (string, error) {
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, CheckRedirect: refuse}
	for range 10 {
		if b, code, err := fetch(ctx, cl, base+"/secret", 1<<20); err == nil && code == 200 {
			if v, _, ok := strict(b); ok {
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("gave up")
}

// TestNoResponseDiscountIsBounded: the O8 discount for a replay must not let a
// retry loop against an always-closing backend through.
func TestNoResponseDiscountIsBounded(t *testing.T) {
	v := run(t, pRetriesForever, Program{Occ: 1, Fault: faultAcceptClose}, Config{RequestCeiling: 3})
	if !slices.ContainsFunc(v, func(m string) bool { return strings.HasPrefix(m, "O8 ") }) {
		t.Fatalf("10 retries against an always-closing backend must be O8 (ceiling 3); got %v", v)
	}
}
