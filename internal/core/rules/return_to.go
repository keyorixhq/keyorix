package rules

// Post-login redirect target sanitizer (SSO returnTo). Moved from core/sso.go
// (leaf package, see doc.go).

import (
	"net/url"
	"strings"
)

// SanitizeReturnTo allows only a same-origin in-app path (leading single slash), so
// the post-login redirect can't be turned into an open redirect.
func SanitizeReturnTo(s string) string {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
		return ""
	}
	// A backslash right after the leading slash — e.g. "/\evil.com" — is rejected
	// outright: several browsers normalize a leading "\" to "/", turning this into
	// "//evil.com", the exact protocol-relative open-redirect the "//" check above
	// is meant to block, just spelled with a backslash to slip past a naive
	// HasPrefix(s, "//") check. Reject a backslash anywhere in the value, not just
	// right after the leading slash — a normalized-later backslash deeper in the
	// string (e.g. "/ok/\/evil.com") could still be re-interpreted as a host
	// boundary by a permissive parser downstream.
	if strings.ContainsRune(s, '\\') {
		return ""
	}
	// Belt-and-suspenders: confirm this really parses as a schemeless, hostless
	// relative reference. Guards against any other scheme/host-smuggling trick
	// (e.g. an embedded "://") that the prefix checks above don't anticipate.
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return ""
	}
	return s
}
