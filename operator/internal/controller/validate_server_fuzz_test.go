package controller

import (
	"net/url"
	"strings"
	"testing"
)

// FuzzValidateServer drives the confused-deputy / token-exfiltration gate
// (KeyorixSecretReconciler.validateServer) with fuzzer-chosen allow-list entries and a
// fuzzer-chosen CR-supplied spec.server. validateServer is THE control that stops a
// namespace-scoped tenant — who can only create a KeyorixSecret CR — from pointing
// spec.server at an attacker-controlled destination and having the operator ship a
// Secret's bytes (the "token") to it. The security property it must uphold:
//
//	ACCEPTED(server) ⟹ the destination net/http will actually dial — URL.Scheme and
//	URL.Host as parsed by net/url, i.e. where the bearer token really goes — uses
//	scheme "https" AND URL.Host is byte-equal to the Host of at least one allow-list
//	entry.
//
// The oracle recomputes the accept-set INDEPENDENTLY from the destination net/http
// would use (u.Host), not by mirroring validateServer's own string math, so a
// url.Parse quirk where the textual server and the dialled host disagree
// (userinfo@host, backslashes, embedded credentials, %-encoding, control bytes) is a
// real finding, not a self-fulfilling tautology.
//
// What this does NOT verify: that the allow-list itself is configured correctly (that
// is the operator's deploy responsibility), nor anything about the token Secret gate
// (tokenSecretLabel) — only that an accepted server is https and its dialled host is
// allow-listed.
func FuzzValidateServer(f *testing.F) {
	seeds := []struct {
		allowed string // newline-separated allow-list entries
		server  string
	}{
		{"https://keyorix.internal", "https://keyorix.internal"},
		{"https://keyorix.internal/", "https://keyorix.internal/api"},
		{"https://keyorix.internal", "http://keyorix.internal"},
		{"https://keyorix.internal", "https://evil.example"},
		{"", "https://keyorix.internal"},
		{"https://keyorix.internal", "https://keyorix.internal@evil.example"},
		{"https://keyorix.internal", "https://evil.example#@keyorix.internal"},
		{"https://keyorix.internal", "https://keyorix.internal:443"},
		{"https://a\nhttps://b", "https://b"},
		{"https://keyorix.internal", "https://keyorix.internal\\@evil.example"},
		{"https://keyorix.internal", "HTTPS://keyorix.internal"},
		{"https://keyorix.internal", "javascript:alert(1)"},
		{"https://keyorix.internal", "//keyorix.internal"},
		{"https://keyorix.internal", ""},
	}
	for _, s := range seeds {
		f.Add(s.allowed, s.server)
	}

	f.Fuzz(func(t *testing.T, allowedBlob, server string) {
		// A fuzzer-controlled allow-list: split on newline, drop blank lines.
		var allowed []string
		for _, line := range strings.Split(allowedBlob, "\n") {
			if strings.TrimSpace(line) != "" {
				allowed = append(allowed, line)
			}
		}
		r := &KeyorixSecretReconciler{AllowedServers: allowed}

		err := r.validateServer(server)
		if err != nil {
			return // rejected: nothing to prove — a reject is always safe.
		}

		// ACCEPTED. Independently establish where net/http will dial, from the same
		// URL fields http.Client uses (Scheme + Host). The token travels there.
		u, perr := url.Parse(server)
		if perr != nil {
			t.Fatalf("validateServer ACCEPTED %q but net/url cannot parse it: %v — "+
				"an accepted server must be a parseable URL", server, perr)
		}
		if u.Host == "" {
			t.Fatalf("validateServer ACCEPTED %q but its parsed Host is empty — "+
				"net/http would have no allow-listed destination to dial", server)
		}
		if u.Scheme != "https" {
			t.Fatalf("validateServer ACCEPTED %q but its scheme is %q, not https — "+
				"the bearer token would travel in cleartext", server, u.Scheme)
		}

		// The dialled host must match the Host of some allow-list entry. Parse each
		// entry exactly as a client would read a base URL (scheme://host), trimming a
		// trailing slash as validateServer's own loop does for normalisation.
		dialHost := u.Host
		matched := false
		for _, a := range allowed {
			au, aerr := url.Parse(strings.TrimRight(strings.TrimSpace(a), "/"))
			if aerr != nil {
				continue
			}
			if au.Host == dialHost && au.Host != "" {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("validateServer ACCEPTED %q (dialled host %q) but NO allow-list "+
				"entry has that host: %q — confused-deputy exfiltration gate bypassed",
				server, dialHost, allowed)
		}
	})
}
