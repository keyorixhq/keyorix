package config

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/cors"
)

// FuzzAllowedOriginsCORSGrant checks the claim server/http/router.go makes about its
// go-chi/cors middleware ("Credentials are only sent to origins in AllowedOrigins
// (never \"*\")") for every server.http.allowed_origins list validateAllowedOrigins
// lets through: a credentialed CORS grant (Access-Control-Allow-Origin plus
// Access-Control-Allow-Credentials) goes only to a browser-shaped Origin that equals,
// ignoring ASCII case, one configured entry; every configured origin is granted; the
// response always varies on Origin; and "*" is never sent with credentials.
//
// go-chi/cors treats a '*' anywhere in an entry as a wildcard; validateAllowedOrigins
// refuses such entries (#4382, TestValidateAllowedOrigins_RejectsWildcardInsideEntry),
// so every list reaching the oracle is exact-match only.
//
// What this does NOT verify: that corsTestOptions still equals router.go's inline
// cors.Options (it is a copy; the router's options are not exported); preflight
// method and header lists; non-browser Origin values (a browser sends ASCII
// scheme://host[:port], so only that shape is asked; CORS does not constrain other
// clients); the "development" environment's fixed localhost list; the default
// https://<domain> origin when the list is empty.
func FuzzAllowedOriginsCORSGrant(f *testing.F) {
	for _, s := range [][2]string{
		{"https://app.example.com", "https://app.example.com"},
		{"https://app.example.com", "https://APP.example.com"},
		{"https://app.example.com\nhttp://localhost:3000", "https://evil.example"},
		{"https://*", "https://evil.example"},
		{"https://*.example.com", "https://evil.example.com.attacker.net"},
		{"https://app.example.com:8443", "https://app.example.com"},
		{"https://app.example.com", "https://app.example.com.attacker.net"},
		{"https://app.example.com", "https://app.example.com:444"},
		{"http://[::1]:5173", "http://[::1]:5173"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, entries, origin string) {
		if len(entries) > 1024 || len(origin) > 256 {
			return
		}
		list := strings.Split(entries, "\n")
		if len(list) > 4 || validateAllowedOrigins(list) != nil {
			return
		}
		if !browserOrigin.MatchString(origin) {
			return
		}
		checkCORSGrant(t, list, origin)
	})
}

// browserOrigin is the serialisation a browser puts in the Origin header for an http(s)
// page: lower-case scheme, ASCII host (IDNs arrive as punycode), optional port.
var browserOrigin = regexp.MustCompile(`^https?://([a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*|\[[0-9a-fA-F:.]+\])(:[0-9]{1,5})?$`)

// corsTestOptions mirrors the cors.Options server/http/router.go installs.
func corsTestOptions(origins []string) cors.Options {
	return cors.Options{
		AllowedOrigins:   origins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Requested-With"},
		ExposedHeaders:   []string{"Link", "X-Total-Count", "X-Page-Count"},
		MaxAge:           300,
		AllowCredentials: true,
	}
}

func checkCORSGrant(t *testing.T, list []string, origin string) {
	t.Helper()
	h := cors.Handler(corsTestOptions(list))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	req.Header.Set("Origin", origin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	acao := rec.Header().Get("Access-Control-Allow-Origin")
	creds := rec.Header().Get("Access-Control-Allow-Credentials") == "true"

	if !slices.Contains(rec.Header().Values("Vary"), "Origin") {
		t.Fatalf("CORS VARY: response to Origin %q does not vary on Origin (list %q)", origin, list)
	}
	if acao == "*" && creds {
		t.Fatalf("CORS WILDCARD: \"*\" sent with credentials (list %q, origin %q)", list, origin)
	}
	exact := slices.ContainsFunc(list, func(e string) bool { return strings.EqualFold(e, origin) })
	switch {
	case acao != "" && acao != origin:
		t.Fatalf("CORS GRANT: Access-Control-Allow-Origin %q for Origin %q (list %q)", acao, origin, list)
	case acao != "" && !exact:
		t.Fatalf("CORS GRANT: credentialed grant to %q, which no allowed_origins entry names (list %q)", origin, list)
	case acao == "" && exact:
		t.Fatalf("CORS LIVENESS: configured origin %q not granted (list %q)", origin, list)
	case acao != "" && !creds:
		t.Fatalf("CORS GRANT: grant to %q without Access-Control-Allow-Credentials", origin)
	}
}
