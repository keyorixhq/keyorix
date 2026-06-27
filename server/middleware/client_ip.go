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
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
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
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" && net.ParseIP(xri) != nil {
		return xri
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
