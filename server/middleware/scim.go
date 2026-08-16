// scim.go — static-bearer-token auth for the SCIM 2.0 endpoints (RFC 7644). Unlike
// the session/PAT Authentication middleware, SCIM is authenticated by a single
// provisioning token an IdP presents (KEYORIX_SCIM_TOKEN). The token is compared in
// constant time, and failures return a SCIM-format error (not the API envelope).
package middleware

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// SCIMToken gates the SCIM routes on a static bearer token. An empty configured
// token denies every request (a misconfiguration fails closed).
//
// Every failed comparison is recorded against the caller's source IP via the
// same recordTokenAuthFailure limiter the session/PAT/machine-token path uses
// (see handleAuthRequest in auth.go) — SCIM is otherwise the only credential
// guard in this middleware stack with no brute-force throttling at all, since
// its static bearer token can be retried indefinitely without penalty.
func SCIMToken(token string) func(http.Handler) http.Handler {
	want := []byte(token)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			presented := []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if len(want) == 0 || subtle.ConstantTimeCompare(presented, want) != 1 {
				if !recordTokenAuthFailure(clientIP(r)) {
					scimError(w, http.StatusTooManyRequests, "too many invalid SCIM token attempts")
					return
				}
				scimError(w, http.StatusUnauthorized, "invalid or missing SCIM bearer token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// scimError writes a SCIM-format (RFC 7644 §3.12) error response. Both current
// callers pass a fixed string literal, but detail is encoded via encoding/json
// (matching the sibling scimError in server/http/handlers/scim.go) rather than
// spliced into a hand-built JSON string with %s -- a future caller passing
// anything containing a `"` or control character would otherwise corrupt the
// response's JSON structure (semgrep: no-fprintf-to-responsewriter, #G798).
func scimError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":  strconv.Itoa(status),
		"detail":  detail,
	})
}
