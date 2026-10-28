package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOpenAPISpec verifies the spec handler returns YAML with the correct content-type.
func TestOpenAPISpec(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	rr := httptest.NewRecorder()
	OpenAPISpec(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/yaml", rr.Header().Get("Content-Type"))
	// The embedded spec is non-empty and starts with the OpenAPI document.
	body := rr.Body.String()
	assert.NotEmpty(t, body, "embedded OpenAPI spec must not be empty")
}

// TestSwaggerHandler_IndexRoute verifies the Swagger UI HTML is served at "/" and "/index.html".
func TestSwaggerHandler_IndexRoute(t *testing.T) {
	for _, path := range []string{"/swagger/", "/swagger/index.html"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()
			SwaggerHandler().ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, "text/html", rr.Header().Get("Content-Type"))
			body := rr.Body.String()
			assert.Contains(t, body, "swagger-ui", "HTML must include the Swagger UI div")
			// The spec URL lives in the init script (no inline <script> under the CSP).
			assert.Contains(t, body, "/swagger/ui/swagger-init.js", "Swagger UI must load its init script")
			initRec := httptest.NewRecorder()
			SwaggerHandler().ServeHTTP(initRec, httptest.NewRequest(http.MethodGet, "/swagger/ui/swagger-init.js", nil))
			assert.Contains(t, initRec.Body.String(), "/openapi.yaml", "Swagger UI must reference the embedded spec")
			// Must not carry the version in the page so an unauthenticated visitor can't
			// fingerprint the exact Keyorix build via the swagger UI page title.
			assert.True(t, strings.Contains(body, "Keyorix API Documentation"), "page title must be present")
		})
	}
}

// TestSwaggerHandler_UnknownRouteIs404 verifies that arbitrary sub-paths return 404.
func TestSwaggerHandler_UnknownRouteIs404(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/swagger/nonexistent.js", nil)
	rr := httptest.NewRecorder()
	SwaggerHandler().ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// pinnedSwaggerUI is the SHA-256 of the vendored swagger-ui-dist@4.15.5 files
// (swaggerui/README.md). A change to any of them must be a deliberate upgrade that
// updates this table, not an accidental edit of a third-party bundle.
var pinnedSwaggerUI = map[string]string{
	"swagger-ui.css":                  "e883f234c6ef0b7dbb6d473fb45a00b85e98d58282f9dd1cc70bcc57ef12ef6a",
	"swagger-ui-bundle.js":            "fd76294e33356ab3fd111ddaeeb10d3f79de8ae1a4d34dbf777f5eef224648d9",
	"swagger-ui-standalone-preset.js": "8e910e1d42309b49aec560301a5d32930c698848df752ced0490691918ce9a5b",
}

func TestSwaggerUIVendoredFilesArePinned(t *testing.T) {
	total := 0
	for name, want := range pinnedSwaggerUI {
		data, err := swaggerUIFS.ReadFile("swaggerui/" + name)
		require.NoError(t, err, name)
		total += len(data)
		sum := sha256.Sum256(data)
		assert.Equal(t, want, hex.EncodeToString(sum[:]), "%s differs from swagger-ui-dist@4.15.5", name)
	}
	// The vendoring decision was made at ~1.5 MB; past 2 MB it should be revisited.
	assert.Less(t, total, 2<<20, "vendored swagger-ui grew past 2 MB: revisit vendor-vs-drop")
}

var (
	externalURLRe = regexp.MustCompile(`(?i)(https?:)?//[a-z0-9][a-z0-9.-]*\.[a-z]{2,}`)
	scriptTagRe   = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)
	refRe         = regexp.MustCompile(`(?i)(?:src|href)="([^"]+)"`)
)

// The served page makes no external request: no external host anywhere in it, every
// subresource is same-origin and actually served, and nothing needs 'unsafe-inline'
// for scripts (the CSP is script-src 'self').
//
// Not covered: what the vendored bundle does at runtime. It is pinned byte-for-byte
// (TestSwaggerUIVendoredFilesArePinned); its one default external call, the online
// validator, is switched off in swagger-init.js and checked below.
func TestSwaggerPage_NoExternalHost(t *testing.T) {
	h := SwaggerHandler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/swagger/", nil))
	require.Equal(t, http.StatusOK, rr.Code)
	page := rr.Body.String()

	assert.Empty(t, externalURLRe.FindAllString(page, -1), "swagger page references an external host")
	assert.NotContains(t, strings.ToLower(page), "unpkg.com")

	for _, m := range scriptTagRe.FindAllStringSubmatch(page, -1) {
		assert.Contains(t, m[1], "src=", "inline <script> would be blocked by script-src 'self'")
		assert.Empty(t, strings.TrimSpace(m[2]), "inline script body")
	}
	assert.NotContains(t, strings.ToLower(page), "<style", "inline <style> relies on 'unsafe-inline'")
	assert.NotRegexp(t, `(?i)\son[a-z]+=`, page, "inline event handler attribute")

	refs := refRe.FindAllStringSubmatch(page, -1)
	require.NotEmpty(t, refs)
	for _, m := range refs {
		ref := m[1]
		require.True(t, strings.HasPrefix(ref, swaggerUIPath), "%s is not under the fixed same-origin path", ref)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ref, nil))
		require.Equal(t, http.StatusOK, rec.Code, ref)
		assert.NotEmpty(t, rec.Body.Bytes(), ref)
		assert.NotContains(t, rec.Header().Get("Content-Type"), "text/html", ref)
	}

	init, err := swaggerUIFS.ReadFile("swaggerui/swagger-init.js")
	require.NoError(t, err)
	assert.Contains(t, string(init), "validatorUrl: null", "the online validator must stay off")
	assert.Contains(t, string(init), "url: '/openapi.yaml'")
}

func TestSwaggerUIAssets_Routing(t *testing.T) {
	h := SwaggerHandler()
	get := func(method, target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
		return rec
	}

	rec := get(http.MethodGet, "/swagger/ui/swagger-ui-bundle.js")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/javascript; charset=utf-8", rec.Header().Get("Content-Type"))

	rec = get(http.MethodGet, "/swagger/ui/swagger-ui.css")
	assert.Equal(t, "text/css; charset=utf-8", rec.Header().Get("Content-Type"))

	rec = get(http.MethodHead, "/swagger/ui/swagger-ui-bundle.js")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Body.Bytes(), "HEAD must not send a body")

	for _, target := range []string{
		"/swagger/ui/README.md",   // embedded but not allowlisted
		"/swagger/ui/",            // no directory listing
		"/swagger/ui",             // ditto
		"/swagger/ui/nope.js",     // unknown
		"/swagger/ui/../index.js", // traversal
		"/swagger/ui/swaggerui/README.md",
	} {
		assert.Equal(t, http.StatusNotFound, get(http.MethodGet, target).Code, target)
	}

	assert.Equal(t, http.StatusMethodNotAllowed, get(http.MethodPost, "/swagger/ui/swagger-ui.css").Code)
}
