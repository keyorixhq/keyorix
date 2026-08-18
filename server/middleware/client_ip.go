package middleware

import (
	"net"
	"net/http"
	"strings"
)

// The forwarding headers a trusted proxy may set, in order of preference, are
// X-Forwarded-For (a comma-separated client→proxy chain; leftmost is the originating
// client) and X-Real-IP (a single address) — both read directly in clientIPFromRequest.

// ClientIP returns a middleware that derives the real client IP and rewrites
// r.RemoteAddr, but ONLY honors forwarding headers when the immediate TCP peer is a
// configured trusted proxy. This replaces chi's middleware.RealIP, which trusts the
// header unconditionally — letting any client spoof its source IP and so defeat the
// per-IP login/MFA brute-force rate limiter that keys on r.RemoteAddr.
//
// trustedProxies is a list of CIDRs or bare IPs (the ingress/load-balancer addresses).
// When it is empty, forwarding headers are ignored entirely and the real TCP peer is
// always used — the safe default for a directly-exposed server. When the peer is NOT a
// trusted proxy, headers are likewise ignored. Only when the peer IS trusted do we walk
// the X-Forwarded-For chain from the right and take the first hop that is not itself a
// trusted proxy (the address the trusted edge actually saw), so an attacker cannot
// prepend a spoofed entry to claim an arbitrary client IP.
func ClientIP(trustedProxies []string) func(http.Handler) http.Handler {
	nets := parseCIDRs(trustedProxies)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ip := clientIPFromRequest(r, nets); ip != "" {
				r.RemoteAddr = ip
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIPFromRequest returns the IP to attribute the request to, or "" to leave
// r.RemoteAddr unchanged. It trusts forwarding headers only when the peer is trusted.
func clientIPFromRequest(r *http.Request, trusted []*net.IPNet) string {
	peer := hostOnly(r.RemoteAddr)
	if len(trusted) == 0 || !ipInAny(peer, trusted) {
		return "" // no trusted proxy in front (or none configured) → keep the TCP peer
	}
	// Prefer X-Forwarded-For: walk it right→left and return the first address that is NOT
	// a trusted proxy — the client as seen by the trusted edge. Stopping at the first
	// untrusted hop from the right means a spoofed leftmost (client-prepended) entry is
	// ignored, so the client cannot claim an arbitrary source IP.
	//
	// r.Header.Get returns only the FIRST occurrence of a header name; net/http does not
	// fold duplicate header lines for arbitrary headers the way RFC 7230 §3.2.2 requires
	// recipients to. Most proxies comma-fold X-Forwarded-For into a single header line, but
	// one that instead appends its own hop via Header.Add (a second, separate line) would
	// have its trusted hop silently dropped by Get, leaving only the attacker-controlled
	// line. Use Header.Values and join every occurrence with "," first, so the walk below
	// always sees the full chain regardless of how the proxy emitted it.
	if xff := strings.TrimSpace(strings.Join(r.Header.Values("X-Forwarded-For"), ",")); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			hop := strings.TrimSpace(parts[i])
			if hop == "" || net.ParseIP(hop) == nil {
				continue
			}
			if !ipInAny(hop, trusted) {
				return hop
			}
		}
		return "" // XFF present but only trusted hops — nothing client-attributable
	}
	// Only when X-Forwarded-For is absent do we fall back to X-Real-IP. X-Real-IP carries
	// no chain, so its anti-spoof guarantee depends entirely on the trusted proxy
	// OVERWRITING it (not passing a client-supplied value through). Preferring the XFF
	// walk above avoids trusting a possibly-passed-through X-Real-IP whenever XFF exists.
	//
	// X-Real-IP is a single-address header, not a comma-separated list, so unlike XFF we
	// can't join multiple occurrences and parse the result as one IP. But it's subject to
	// the same Header.Get first-occurrence pitfall: a trusted proxy that appends its own
	// X-Real-IP via Header.Add (rather than overwriting a client-supplied one) leaves its
	// trusted value as the LAST header line, with the client's own value first. Walk the
	// occurrences from the last back to the first and take the first one that parses as a
	// valid IP, so the proxy-appended hop wins over anything the client sent.
	xriValues := r.Header.Values("X-Real-IP")
	for i := len(xriValues) - 1; i >= 0; i-- {
		if xri := strings.TrimSpace(xriValues[i]); xri != "" && net.ParseIP(xri) != nil {
			return xri
		}
	}
	return ""
}

func parseCIDRs(entries []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			// A bare IP — treat as a /32 (v4) or /128 (v6).
			if ip := net.ParseIP(e); ip != nil {
				if ip.To4() != nil {
					e += "/32"
				} else {
					e += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

func ipInAny(ipStr string, nets []*net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// hostOnly strips the :port from a host:port (or returns the input if there's no port).
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
