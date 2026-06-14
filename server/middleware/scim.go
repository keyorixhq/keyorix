// scim.go — static-bearer-token auth for the SCIM 2.0 endpoints (RFC 7644). Unlike
// the session/PAT Authentication middleware, SCIM is authenticated by a single
// provisioning token an IdP presents (KEYORIX_SCIM_TOKEN). The token is compared in
// constant time, and failures return a SCIM-format error (not the API envelope).
package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// SCIMToken gates the SCIM routes on a static bearer token. An empty configured
// token denies every request (a misconfiguration fails closed).
func SCIMToken(token string) func(http.Handler) http.Handler {
	want := []byte(token)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			presented := []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if len(want) == 0 || subtle.ConstantTimeCompare(presented, want) != 1 {
				w.Header().Set("Content-Type", "application/scim+json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"401","detail":"invalid or missing SCIM bearer token"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
