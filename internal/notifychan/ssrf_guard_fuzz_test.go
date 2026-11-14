package notifychan

import (
	"net"
	"net/url"
	"testing"

	"github.com/keyorixhq/keyorix/internal/netutil"
)

// FuzzWebhookSSRFGuard is a sink-guided harness for the outbound-HTTP sink in
// WebhookSink.send / ChatSink.send (http.NewRequestWithContext + client.Do with
// an operator/event-derived URL). The sink itself is defended, before any dial,
// by validateEndpoint -> refuseDisallowedHost -> isDisallowedIP. This harness
// pins the net-out invariant for that defense:
//
//	INVARIANT: with allowPrivateNetwork=false, an endpoint whose host is — or
//	resolves to — an SSRF-class address (RFC1918 private, link-local incl. the
//	169.254.169.254 cloud-IMDS literal, unspecified/0.0.0.0/8, or an IPv6
//	encoding carrying such an IPv4) is ALWAYS refused. Loopback is deliberately
//	permitted as a dev target and is therefore NOT asserted as refused.
//
// The oracle is DIFFERENTIAL: refIsSSRF below is an independent reimplementation
// of the classification, written against the stdlib primitives rather than
// calling the production isDisallowedIP, so weakening the production classifier
// makes the two diverge and the harness fail (see the sinkmap REPORT for the
// red-proof run).
//
// What this oracle does NOT verify:
//   - It does not prove a dial is actually prevented at the socket layer; it
//     asserts validateEndpoint returns an error, which is the pre-dial gate the
//     real DialContext resolver (lookupIPAddr) also enforces. The redirect-time
//     guard (refuseRedirectDowngrade) is a separate path, not covered here.
//   - It only asserts the SSRF⇒refused direction. It does NOT assert
//     public⇒allowed (a URL may be refused for unrelated reasons, e.g. a parse
//     error), so a guard that refused everything would pass this harness; that
//     direction is covered by the package's existing allow-path table tests.
//   - refIsSSRF mirrors the production ruleset by construction; it catches a
//     weakened production classifier, not a shared blind spot in the ruleset
//     itself (e.g. a brand-new reserved range both forget).
func FuzzWebhookSSRFGuard(f *testing.F) {
	f.Add([]byte{169, 254, 169, 254}, "")
	f.Add([]byte{10, 0, 0, 1}, "")
	f.Add([]byte{192, 168, 1, 1}, "metadata.internal")
	f.Add([]byte{0, 0, 0, 0}, "")
	f.Add([]byte{127, 0, 0, 1}, "") // loopback — permitted, must NOT be flagged
	f.Add([]byte{8, 8, 8, 8}, "")   // public — not asserted either way

	f.Fuzz(func(t *testing.T, ipBytes []byte, host string) {
		ip := ipFromBytes(ipBytes)
		if ip == nil {
			return
		}
		ssrf := refIsSSRF(ip)

		// Path 1: literal-IP host — refuseDisallowedHost checks it directly.
		if raw := "https://" + hostLiteral(ip) + "/x"; parseable(raw) {
			err := validateEndpoint(raw, false /*allowPrivateNetwork*/, false)
			if ssrf && err == nil {
				t.Fatalf("SSRF literal IP %s accepted by validateEndpoint (%q); guard let an internal address through", ip, raw)
			}
		}

		// Path 2: a hostname that RESOLVES to ip — exercises the lookup branch.
		// Only assert when the URL's effective host is itself NOT a literal IP,
		// so validateEndpoint actually consults the (stubbed) resolver and thus
		// evaluates `ip` — otherwise it would check the literal host directly
		// and our `ssrf` (computed from `ip`) would be the wrong oracle.
		if host != "" {
			raw := "https://" + host + "/x"
			if u, err := url.Parse(raw); err == nil && u.Scheme == "https" {
				if eff := u.Hostname(); eff != "" && net.ParseIP(eff) == nil {
					restore := lookupIPAddr
					lookupIPAddr = func(string) ([]net.IPAddr, error) { return []net.IPAddr{{IP: ip}}, nil }
					verr := validateEndpoint(raw, false, false)
					lookupIPAddr = restore
					if ssrf && verr == nil {
						t.Fatalf("SSRF via hostname %q resolving to %s accepted by validateEndpoint; resolve-time guard bypassed", eff, ip)
					}
				}
			}
		}
	})
}

// refIsSSRF is the independent reference classifier (see the harness doc).
func refIsSSRF(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 0 { // 0.0.0.0/8 reaches localhost
		return true
	}
	if privOrLinkLocal(ip) {
		return true
	}
	if v4 := netutil.EmbeddedIPv4(ip); v4 != nil {
		return privOrLinkLocal(v4)
	}
	return false
}

func privOrLinkLocal(ip net.IP) bool {
	return !ip.IsLoopback() && (ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast())
}

// ipFromBytes maps a fuzz byte slice to an IPv4 (4 bytes) or IPv6 (16 bytes)
// address; anything else yields nil (skipped).
func ipFromBytes(b []byte) net.IP {
	switch len(b) {
	case 4:
		return net.IPv4(b[0], b[1], b[2], b[3])
	case 16:
		ip := make(net.IP, 16)
		copy(ip, b)
		return ip
	default:
		return nil
	}
}

// hostLiteral renders ip as a URL host, bracketing IPv6.
func hostLiteral(ip net.IP) string {
	if ip.To4() == nil {
		return "[" + ip.String() + "]"
	}
	return ip.String()
}

func parseable(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Hostname() != ""
}
