package notifychan

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
)

// validateEndpoint rejects a non-https notification endpoint — which would send the
// bearer token and payload in cleartext — allowing http only for an explicit insecure
// opt-in or a loopback target (local testing).
func validateEndpoint(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("notifychan: invalid endpoint %q: %w", raw, err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowInsecure || isLoopbackHost(u.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("notifychan: endpoint %q must use https (set insecure_skip_verify only for a trusted self-signed or loopback target)", raw)
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
