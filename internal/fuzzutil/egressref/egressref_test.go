package egressref_test

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/egressref"
	"github.com/keyorixhq/keyorix/internal/netutil"
)

// recorder is a TB that records a Fatalf instead of aborting, so a planted bypass can be
// shown to turn an oracle red (and the real guard shown to keep it green).
type recorder struct{ failures []string }

func (r *recorder) Helper() {}
func (r *recorder) Fatalf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

func (r *recorder) red() bool { return len(r.failures) > 0 }

// sweep probes every encoding of a spread of octets through dial under policy.
func sweep(dial egressref.DialFunc, refuse func(egressref.Addr) bool) *recorder {
	r := &recorder{}
	octets := [][4]byte{{169, 254, 169, 254}, {169, 254, 0, 1}, {10, 0, 0, 5}, {127, 0, 0, 1}, {100, 100, 100, 200}, {192, 0, 0, 192}, {8, 8, 8, 8}, {0, 0, 0, 0}, {172, 16, 1, 1}, {192, 168, 1, 1}}
	for kind := range byte(egressref.Kinds) {
		for _, o := range octets {
			egressref.Probe(r, "plant", dial, egressref.Decode(kind, o[0], o[1], o[2], o[3]), "443", "", refuse(egressref.Decode(kind, o[0], o[1], o[2], o[3])))
		}
	}
	return r
}

// stdlibOnly is the encoding-gap plant: the check hand-rolled sites used before #1937,
// stdlib classification with no embedded-IPv4 decode.
func stdlibOnly(ip net.IP) bool { return ip.IsLinkLocalUnicast() }

func TestOracleLinkLocalTier(t *testing.T) {
	green := netutil.Dialer{Disallow: netutil.IsLinkLocal}
	if r := sweep(green.DialContext, egressref.LinkLocalTier); r.red() {
		t.Fatalf("real netutil.IsLinkLocal guard must be green against the reference: %v", r.failures)
	}
	for name, d := range map[string]netutil.Dialer{
		"no guard":                  {},
		"stdlib-only (no decode)":   {Disallow: stdlibOnly},
		"over-block (private tier)": {Disallow: netutil.IsPrivateOrLinkLocal},
		"refuse everything":         {Disallow: func(net.IP) bool { return true }},
	} {
		if r := sweep(d.DialContext, egressref.LinkLocalTier); !r.red() {
			t.Errorf("planted %q: oracle stayed green", name)
		}
	}
}

func TestOraclePrivateTier(t *testing.T) {
	green := netutil.Dialer{Disallow: netutil.IsPrivateOrLinkLocal}
	if r := sweep(green.DialContext, egressref.PrivateTier); r.red() {
		t.Fatalf("real netutil.IsPrivateOrLinkLocal guard must be green against the reference: %v", r.failures)
	}
	for name, d := range map[string]netutil.Dialer{
		"no guard":                {},
		"link-local only":         {Disallow: netutil.IsLinkLocal},
		"stdlib-only (no decode)": {Disallow: func(ip net.IP) bool { return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() }},
		"refuse everything":       {Disallow: func(net.IP) bool { return true }},
	} {
		if r := sweep(d.DialContext, egressref.PrivateTier); !r.red() {
			t.Errorf("planted %q: oracle stayed green", name)
		}
	}
}

func TestOracleResolved(t *testing.T) {
	answers := []egressref.Addr{egressref.Decode(0, 8, 8, 8, 8), egressref.Decode(2, 169, 254, 169, 254)}
	run := func(resolve func(calls *int) netutil.Resolver, d netutil.Dialer) *recorder {
		calls := 0
		d.Resolve = resolve(&calls)
		r := &recorder{}
		egressref.CheckResolved(r, d.DialContext, "vault.example.test", func() int { return calls }, answers, egressref.PrivateTier)
		return r
	}
	stub := func(calls *int) netutil.Resolver {
		return func(context.Context, string) ([]net.IPAddr, error) {
			*calls++
			return []net.IPAddr{{IP: answers[0].IP}, {IP: answers[1].IP}}, nil
		}
	}
	if r := run(stub, netutil.Dialer{Disallow: netutil.IsPrivateOrLinkLocal}); r.red() {
		t.Fatalf("real guard must be green on a mixed answer set: %v", r.failures)
	}
	// Plant 1: no guard, a mixed answer set passes.
	if r := run(stub, netutil.Dialer{}); !r.red() {
		t.Error("planted no-guard: oracle stayed green")
	}
	// Plant 2: validates only the first answer (a mixed answer set slips through).
	first := func(calls *int) netutil.Resolver {
		return func(context.Context, string) ([]net.IPAddr, error) {
			*calls++
			return []net.IPAddr{{IP: answers[0].IP}}, nil
		}
	}
	if r := run(first, netutil.Dialer{Disallow: netutil.IsPrivateOrLinkLocal}); !r.red() {
		t.Error("planted first-answer-only validation: oracle stayed green")
	}
	// Plant 3: a second lookup between validation and connect (the rebinding window).
	double := func(calls *int) netutil.Resolver {
		inner := stub(calls)
		return func(ctx context.Context, h string) ([]net.IPAddr, error) {
			_, _ = inner(ctx, h)
			return inner(ctx, h)
		}
	}
	if r := run(double, netutil.Dialer{Disallow: netutil.IsPrivateOrLinkLocal}); !r.red() {
		t.Error("planted double resolution: oracle stayed green")
	}
}
