package k8ssync

import (
	"net/url"
	"testing"
)

// FuzzValidateKeyorixURL drives validateKeyorixURL, the sync agent's gate that stops
// the machine-identity bearer token (KEYORIX_TOKEN, sent on every request) from
// travelling in cleartext. Unlike the operator's validateClientBaseURL, this one is
// deliberately STRICTER (K8SSYNC-007): http is allowed only for the literal hostname
// "localhost", never for a loopback IP, because an attacker who controls DNS could map
// a loopback IP string to a routable address. The security property:
//
//	ACCEPTED(raw) ⟹ u.Host != "" AND ( u.Scheme == "https"
//	                                   OR (u.Scheme == "http" AND u.Hostname() == "localhost") )
//
// The oracle is computed independently from net/url, so any disagreement between what
// validateKeyorixURL reads and what the HTTP client would dial is a finding. What this
// does NOT verify: reachability, nor that KEYORIX_TOKEN itself is well-formed — only the
// cleartext-transport gate.
func FuzzValidateKeyorixURL(f *testing.F) {
	seeds := []string{
		"https://keyorix.internal",
		"http://localhost",
		"http://localhost:8080",
		"http://127.0.0.1", // loopback IP over http — must be REJECTED (K8SSYNC-007)
		"http://[::1]",     // loopback IP over http — must be REJECTED
		"http://localhost.evil.com",
		"https://",
		"ftp://keyorix.internal",
		"http://keyorix.internal",
		"HTTP://LOCALHOST",
		"http://user@localhost",
		"https://user:pass@keyorix.internal",
		"//keyorix.internal",
		"http://localhost@evil.com",
		"",
		"https://keyorix.internal:8443/api?x=1",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		err := validateKeyorixURL(raw)
		if err != nil {
			return
		}
		u, perr := url.Parse(raw)
		if perr != nil {
			t.Fatalf("validateKeyorixURL ACCEPTED %q but net/url cannot parse it: %v", raw, perr)
		}
		if u.Host == "" {
			t.Fatalf("validateKeyorixURL ACCEPTED %q with empty Host", raw)
		}
		switch u.Scheme {
		case "https":
			return
		case "http":
			if u.Hostname() != "localhost" {
				t.Fatalf("validateKeyorixURL ACCEPTED http://%s (%q) — K8SSYNC-007 allows http only for "+
					"the literal host \"localhost\"; the bearer token would be sent in cleartext",
					u.Hostname(), raw)
			}
		default:
			t.Fatalf("validateKeyorixURL ACCEPTED %q with scheme %q — token transport is not TLS", raw, u.Scheme)
		}
	})
}
