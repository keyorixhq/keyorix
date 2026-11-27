package egressref

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
)

// TB is the part of testing.TB the probes use, so the self-tests can hand them a
// recorder and prove each oracle goes red on a planted bypass.
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// DialFunc is the shape of http.Transport.DialContext.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// refusalMarker is the text netutil.Dialer puts in the error when its Disallow policy
// refuses a literal address ("netutil: refusing to dial disallowed address <ip>") or a
// resolved one ("... resolves to disallowed address <ip>; refusing to dial").
const refusalMarker = "disallowed address"

// Probe dials addr (as a literal, optionally with a zone suffix on an IPv6 link-local) through
// dial with an ALREADY-CANCELLED context and checks the guard's decision against want.
//
// The cancelled context is what keeps the fuzz target off the network: a guard that
// lets the address through hands it to net.Dialer, which sees the cancelled context and
// returns before it issues a socket call, and a guard that refuses returns its own error
// first. So "refused" is read from the guard's error text, never from a connection
// attempt, and a connection that succeeds anyway is closed and reported as a bypass.
//
//   - wantRefuse and not refused: BYPASS (an address the site policy must refuse was let through).
//   - not wantRefuse and refused: OVER-BLOCK (a legitimate destination, or an encoding of
//     a public one, was refused: the regression #1937 nearly caused for NAT64).
func Probe(t TB, site string, dial DialFunc, a Addr, port string, zone string, wantRefuse bool) {
	t.Helper()
	host := a.IP.String()
	if zone != "" && strings.Contains(host, ":") {
		host += "%" + zone
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := dial(ctx, "tcp", net.JoinHostPort(host, port))
	if conn != nil {
		_ = conn.Close()
		t.Fatalf("%s: connected to %s despite a cancelled context", site, a)
	}
	refused := err != nil && strings.Contains(err.Error(), refusalMarker)
	switch {
	case wantRefuse && !refused:
		t.Fatalf("%s: BYPASS: %s must be refused by this site's policy, dial returned %v", site, a, err)
	case !wantRefuse && refused:
		t.Fatalf("%s: OVER-BLOCK: %s must be permitted by this site's policy, dial returned %v", site, a, err)
	}
}

// Run registers the shared seeds and the fuzz body for one site: every fuzz input is a
// destination encoding (Decode), a port and an optional IPv6 zone suffix, driven through
// the site's real dial hook. refuse is the site's documented policy over the reference
// verdicts (LinkLocal tier or Private tier). dial is called per input so a site whose
// transport is built on demand is exercised through its real constructor.
func Run(f *testing.F, site string, dial func() DialFunc, refuse func(Addr) bool) {
	f.Helper()
	f.Add(byte(0), byte(169), byte(254), byte(169), byte(254), uint16(80), false)  // IMDS, raw
	f.Add(byte(1), byte(169), byte(254), byte(169), byte(254), uint16(80), false)  // IMDS, IPv4-mapped
	f.Add(byte(2), byte(169), byte(254), byte(169), byte(254), uint16(443), false) // IMDS, NAT64 well-known
	f.Add(byte(3), byte(169), byte(254), byte(169), byte(254), uint16(443), false) // IMDS, NAT64 local-use
	f.Add(byte(4), byte(169), byte(254), byte(169), byte(254), uint16(443), false) // IMDS, IPv4-compatible
	f.Add(byte(5), byte(169), byte(254), byte(169), byte(254), uint16(443), false) // IMDS, 6to4
	f.Add(byte(6), byte(169), byte(254), byte(169), byte(254), uint16(443), false) // IMDS, Teredo
	f.Add(byte(7), byte(0), byte(0), byte(0), byte(1), uint16(443), true)          // fe80:: with a zone suffix
	f.Add(byte(8), byte(0), byte(0), byte(0), byte(0), uint16(80), false)          // fd00:ec2::254 (AWS IPv6 IMDS)
	f.Add(byte(0), byte(100), byte(100), byte(100), byte(200), uint16(80), false)  // Alibaba metadata, in CGNAT
	f.Add(byte(0), byte(192), byte(0), byte(0), byte(192), uint16(80), false)      // Oracle metadata, 192.0.0.192
	f.Add(byte(0), byte(10), byte(0), byte(0), byte(5), uint16(443), false)        // RFC-1918
	f.Add(byte(0), byte(127), byte(0), byte(0), byte(1), uint16(443), false)       // loopback
	f.Add(byte(2), byte(8), byte(8), byte(8), byte(8), uint16(443), false)         // public via NAT64 (#1937)
	f.Add(byte(9), byte(1), byte(2), byte(3), byte(4), uint16(443), false)         // public IPv6

	f.Fuzz(func(t *testing.T, kind, a, b, c, d byte, port uint16, zone bool) {
		addr := Decode(kind, a, b, c, d)
		z := ""
		if zone {
			z = "lo"
		}
		Probe(t, site, dial(), addr, strconvPort(port), z, refuse(addr))
	})
}

func strconvPort(p uint16) string { return strconv.Itoa(int(p)) }

// LinkLocalTier is the policy of netutil.IsLinkLocal: link-local only, in every encoding.
func LinkLocalTier(a Addr) bool { return a.LinkLocal }

// PrivateTier is the policy of netutil.IsPrivateOrLinkLocal: private, loopback, CGNAT,
// link-local and ULA, in every encoding.
func PrivateTier(a Addr) bool { return a.Private }

// CheckResolved dials host through dial (a hostname, so the guard must resolve it) with a
// cancelled context, where the caller has installed a resolver stub that returns answers on
// its first call and something else afterwards and counts its calls through resolveCalls.
// It asserts the DNS-rebinding properties:
//
//   - the decision is made from the first answer set alone, and refuses the whole set when ANY
//     answer in it is refused by the site policy (a mixed public/private answer);
//   - the guard resolves exactly once per dial, so no second, unvalidated lookup exists
//     between validation and connect.
func CheckResolved(t TB, dial DialFunc, host string, resolveCalls func() int, answers []Addr, refuse func(Addr) bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := dial(ctx, "tcp", net.JoinHostPort(host, "443"))
	if conn != nil {
		_ = conn.Close()
		t.Fatalf("connected despite a cancelled context")
	}
	wantRefuse := false
	for _, a := range answers {
		wantRefuse = wantRefuse || refuse(a)
	}
	refused := err != nil && strings.Contains(err.Error(), refusalMarker)
	if wantRefuse && !refused {
		t.Fatalf("BYPASS: answer set %v contains an address the site policy refuses, dial returned %v", answers, err)
	}
	if !wantRefuse && refused {
		t.Fatalf("OVER-BLOCK: answer set %v is allowed by the site policy, dial returned %v", answers, err)
	}
	if n := resolveCalls(); n != 1 {
		t.Fatalf("resolver called %d times for one dial; the guard must validate and pin a single resolution", n)
	}
}
