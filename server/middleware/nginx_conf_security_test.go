package middleware

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNginxConfSecurityHeadersMatchGoMiddleware guards against web/nginx.conf
// (the Docker+nginx serving mode's config) silently drifting back to the
// pre-hardening headers this package already enforces for the embedded
// single-binary serving mode (see SecurityHeaders above).
//
// Root cause this guards against (r140): web/nginx.conf arrived wholesale via
// the web/ subtree merge (18a661b6, ADR-070) AFTER bbc14d97 had already
// hardened both other serving modes (this package + deploy/helm/keyorix/
// templates/web-config.yaml) — a sibling site the merge reintroduced with the
// stale SAMEORIGIN/strict-origin-when-cross-origin/bare-ws-wss policy. DAST
// never catches this because DAST only exercises the embedded single-binary
// mode, never web/Dockerfile's nginx.
//
// nginx's add_header does not inherit into a location block once that block
// sets any add_header of its own (see the comment atop web/nginx.conf's http
// block), so the header set is repeated across all of that file's location
// blocks — this test checks every occurrence, not just the first, so a
// partial revert (fixing one block but not another) still fails.
//
// Deliberately narrow: this is not a full CSP-string equality check (nginx.conf
// legitimately differs from the Go middleware's CSP in ways that don't matter
// here, e.g. img-src's data: scheme), just the handful of properties that have
// each already caused a real, named vulnerability class in this codebase.
func TestNginxConfSecurityHeadersMatchGoMiddleware(t *testing.T) {
	const nginxConfPath = "../../web/nginx.conf"
	data, err := os.ReadFile(nginxConfPath) // #nosec G304 -- fixed relative path to a repo file, not user input
	require.NoError(t, err, "web/nginx.conf must exist and be readable")
	conf := string(data)

	xfoRe := regexp.MustCompile(`add_header X-Frame-Options "([^"]*)"`)
	xfoMatches := xfoRe.FindAllStringSubmatch(conf, -1)
	require.NotEmpty(t, xfoMatches, "expected at least one X-Frame-Options add_header in web/nginx.conf")
	for _, m := range xfoMatches {
		// Clickjacking (matches server/middleware/security_headers.go and
		// deploy/helm/keyorix/templates/web-config.yaml): the dashboard must
		// never be framed by ANY origin, including its own — SAMEORIGIN is not
		// strict enough.
		assert.Equal(t, "DENY", m[1], "every X-Frame-Options in web/nginx.conf must be DENY, not %q", m[1])
	}

	cspRe := regexp.MustCompile(`add_header Content-Security-Policy "([^"]*)"`)
	cspMatches := cspRe.FindAllStringSubmatch(conf, -1)
	require.NotEmpty(t, cspMatches, "expected at least one Content-Security-Policy add_header in web/nginx.conf")

	connectSrcRe := regexp.MustCompile(`connect-src ([^;]*);`)
	for _, m := range cspMatches {
		csp := m[1]

		// #1214/#1215-class CSP bypass: a bare ws:/wss: scheme in connect-src
		// permits a WebSocket connection to ANY host, which is a data-
		// exfiltration channel. 'self' already covers same-origin WebSocket
		// connections in all modern browsers, so the wildcard is never needed.
		connectSrcMatch := connectSrcRe.FindStringSubmatch(csp)
		require.NotEmpty(t, connectSrcMatch, "expected a connect-src directive in CSP %q", csp)
		assert.NotContains(t, connectSrcMatch[1], "ws:", "connect-src must not allow a bare ws:/wss: scheme (CSP bypass): %q", csp)

		// frame-ancestors does NOT inherit from default-src and must be
		// explicit, or embedding is left ungoverned by CSP entirely
		// (X-Frame-Options above is the fallback, but browsers that only
		// honor CSP would be unprotected).
		assert.Contains(t, csp, "frame-ancestors 'none'", "CSP must explicitly set frame-ancestors 'none': %q", csp)
	}
}
