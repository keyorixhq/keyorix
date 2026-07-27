package middleware

import "net/http"


// contentSecurityPolicy mirrors the policy the Helm chart's nginx frontend already sends
// (deploy/helm/keyorix/templates/web-config.yaml) — the two serving modes (embedded
// single-binary SPA vs. the separate nginx+API-proxy deployment) should present the same
// policy to the browser. style-src allows 'unsafe-inline' for the SPA's runtime style
// injection (a common CSS-in-JS/Tailwind requirement); script-src does not, so an
// attacker-injected inline <script> — the primary XSS vector — is blocked regardless of
// where the malicious markup came from.
//
// connect-src uses 'self' only — this already covers same-origin WebSocket connections
// (ws:/wss: to the same host) in all modern browsers. The bare ws: and wss: scheme
// values that were here previously allowed WebSocket connections to ANY host, which
// is a CSP bypass for data exfiltration via WebSocket.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self';"

// SecurityHeaders sets standard hardening response headers on every response. For a
// secrets manager these matter beyond the usual:
//   - X-Content-Type-Options: nosniff — never let a browser MIME-sniff a response into
//     something executable.
//   - X-Frame-Options: DENY — the dashboard must never be framed (clickjacking).
//   - Referrer-Policy: no-referrer — never leak the request URL via the Referer header;
//     Keyorix URLs can carry tokens (e.g. the SSO completion fragment), so stripping the
//     referrer closes a token-leak channel to third-party pages.
//   - Content-Security-Policy — #112: the single-binary/air-gap serving mode (the
//     embedded SPA, server/webui) previously sent NO CSP at all (only the separate Helm
//     nginx frontend did), so the strongest practical mitigation against an XSS reading
//     the SSO/SAML session-token URL fragment or localStorage was entirely absent in
//     that mode. Now sent unconditionally, matching the nginx config's policy.
//
// HSTS is sent only when this process terminates TLS (tlsEnabled); deployments that
// terminate TLS at a proxy add HSTS there, and sending it over plain HTTP is wrong.
//
// Headers are set before the handler runs, so they apply to every response — including
// errors, panics (the recovery middleware runs after this), and static assets — not just
// the handlers that set nosniff themselves today.
func SecurityHeaders(tlsEnabled bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", contentSecurityPolicy)
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
			if tlsEnabled {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
			}
			next.ServeHTTP(w, r)
		})
	}
}
