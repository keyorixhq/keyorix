package rules

import (
	"net/url"
	"testing"
)

// FuzzReturnToOpenRedirectDifferential is an open-redirect differential over SanitizeReturnTo
// (sso.go), the post-login return-to path validator. The security contract is: any value
// SanitizeReturnTo ACCEPTS must, when a browser resolves it as a redirect target against the app
// origin, stay on that origin. We assert ONLY the accept direction (a reject is always safe), and
// we use Go's own url.ResolveReference — the same RFC-3986 resolution a browser applies to a
// Location: / <a href> — as the oracle for "how the value is really interpreted". The oracle
// therefore cannot false-positive: an accepted value that reference-resolves to another host or
// scheme is an open redirect by definition. This surface (return-to redirect) was previously
// unfuzzed; the bug class (accept-vs-resolve parser differential) is the classic open-redirect.
func FuzzReturnToOpenRedirectDifferential(f *testing.F) {
	// Known evasion shapes + one benign accept.
	for _, s := range []string{
		"/app/home",       // benign — accepted, resolves on-origin
		"//evil.com",      // protocol-relative
		"/\\evil.com",     // backslash → normalised to // by some browsers
		"/%2f%2fevil.com", // percent-encoded slashes
		"/ok/\\/evil.com", // backslash deeper in the path
		"https:/evil.com", // single-slash scheme smuggle
		"/\t//evil.com",   // embedded tab
		"/ /evil.com",     // embedded space
		"/app/../../evil", // dot-segment climb
		"/\r/evil.com",    // embedded CR
		"/\n//evil.com",   // embedded LF
		"/@evil.com",      // userinfo-looking
		"/path?x=1#frag",  // query + fragment
		"",                // empty
	} {
		f.Add(s)
	}

	// Fixed canonical app origin the post-login redirect resolves the return-to against.
	base, err := url.Parse("https://keyorix.example.test/app/")
	if err != nil {
		f.Fatalf("seed base parse: %v", err)
	}

	f.Fuzz(func(t *testing.T, s string) {
		got := SanitizeReturnTo(s)
		if got == "" {
			return // rejected — always safe, nothing to assert (we never assert "must accept")
		}
		// SanitizeReturnTo only returns its input unchanged, so got == s here; re-parse it the
		// way the redirect layer would. An accepted value that no longer parses is itself a defect.
		ref, err := url.Parse(got)
		if err != nil {
			t.Fatalf("OPEN-REDIRECT (unparseable accept): SanitizeReturnTo accepted %q which url.Parse rejects: %v", s, err)
		}
		// How a browser really interprets the returned Location against the app origin.
		resolved := base.ResolveReference(ref)
		if resolved.Scheme != base.Scheme || resolved.Hostname() != base.Hostname() {
			t.Fatalf("OPEN-REDIRECT: SanitizeReturnTo accepted %q; resolves off-origin to scheme=%q host=%q (want scheme=%q host=%q)",
				s, resolved.Scheme, resolved.Hostname(), base.Scheme, base.Hostname())
		}
	})
}
