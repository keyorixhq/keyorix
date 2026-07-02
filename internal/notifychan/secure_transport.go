package notifychan

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
)

// validateEndpoint rejects a non-https notification endpoint — which would send the
// bearer token and payload in cleartext — allowing http only for an explicit insecure
// opt-in or a loopback target (local testing). It also refuses a literal private /
// link-local destination IP (e.g. cloud metadata 169.254.169.254 or an internal host).
//
// allowInsecure ONLY relaxes the transport-security requirement (permits http, and —
// at the call site — lets the HTTP client skip TLS certificate verification for a
// trusted self-signed endpoint). It must NOT also relax the SSRF/destination-IP guard:
// those are independent concerns — an operator who has a legitimate reason to disable
// TLS certificate verification (e.g. an internal service with a self-signed cert) has
// said nothing about wanting the notification webhook to be allowed to reach internal/
// metadata IPs. Coupling them previously meant setting insecure_skip_verify for a
// mundane self-signed-cert reason silently ALSO disabled SSRF protection. So the
// private/link-local IP check below is unconditional, independent of allowInsecure.
func validateEndpoint(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("notifychan: invalid endpoint %q: %w", raw, err)
	}
	switch u.Scheme {
	case "https":
		// scheme OK; fall through to the destination-IP check
	case "http":
		if !allowInsecure && !isLoopbackHost(u.Hostname()) {
			return fmt.Errorf("notifychan: endpoint %q must use https (set insecure_skip_verify only for a trusted self-signed or loopback target)", raw)
		}
	default:
		return fmt.Errorf("notifychan: endpoint %q must use https", raw)
	}
	// SSRF guard: always enforced, regardless of allowInsecure (see the doc comment
	// above) — a private/link-local target is refused whether or not TLS
	// verification is disabled.
	if isDisallowedIPHost(u.Hostname()) {
		return fmt.Errorf("notifychan: endpoint %q targets a private/link-local address; refusing to send to an internal host", raw)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// isDisallowedIPHost reports whether host is a literal private or link-local IP (loopback
// is permitted as a dev target). Hostnames are not resolved here (no DNS at config time),
// so this catches the literal-IP SSRF cases without a resolution side effect.
func isDisallowedIPHost(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() {
		return false
	}
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// refuseRedirectDowngrade blocks a redirect to a different host or a downgrade from
// https to http, so a compromised/misbehaving endpoint cannot bounce the signed,
// token-bearing request to an internal or cleartext target (SSRF/exfil hardening).
func refuseRedirectDowngrade(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1]
	if req.URL.Host != prev.URL.Host {
		return fmt.Errorf("notifychan: refusing cross-host redirect to %q", req.URL.Host)
	}
	if prev.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("notifychan: refusing https->%s redirect", req.URL.Scheme)
	}
	return nil
}
