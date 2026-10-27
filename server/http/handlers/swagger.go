package handlers

import (
	"embed"
	"net/http"
	"strings"
)

// openapiSpecYAML is the canonical OpenAPI 3.0 spec, embedded at build time and
// served verbatim at /openapi.yaml. Editing openapi.yaml is the single source of
// truth — the Swagger UI and the published spec both read it.
//
//go:embed openapi.yaml
var openapiSpecYAML string

// swaggerUIFS holds the Swagger UI the /swagger/ page runs: swagger-ui-dist 4.15.5
// vendored byte-for-byte (see swaggerui/README.md) plus Keyorix's own init script and
// page stylesheet. Embedded so the page makes no request to a third-party host: an
// air-gapped install has none to reach, and an authenticated API host should not
// send the operator's browser to one.
//
//go:embed swaggerui
var swaggerUIFS embed.FS

// swaggerUIPath is the fixed path prefix the page loads its assets from.
const swaggerUIPath = "/swagger/ui/"

// swaggerUIAssets is the allowlist of files served under swaggerUIPath, with the
// Content-Type each is sent as (set explicitly: nosniff is on). Anything else in
// the embedded directory (its README) is not reachable.
var swaggerUIAssets = map[string]string{
	"swagger-ui.css":                  "text/css; charset=utf-8",
	"swagger-ui-bundle.js":            "text/javascript; charset=utf-8",
	"swagger-ui-standalone-preset.js": "text/javascript; charset=utf-8",
	"swagger-init.js":                 "text/javascript; charset=utf-8",
	"swagger-page.css":                "text/css; charset=utf-8",
	"LICENSE":                         "text/plain; charset=utf-8",
	"NOTICE":                          "text/plain; charset=utf-8",
}

// SwaggerHandler returns a handler for serving Swagger UI. The UI loads the spec
// from /openapi.yaml (the embedded file), so there is no second spec to drift.
func SwaggerHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/swagger/")
		switch path {
		case "", "index.html":
			serveSwaggerIndex(w, r)
		default:
			name, ok := strings.CutPrefix(r.URL.Path, swaggerUIPath)
			if ctype, known := swaggerUIAssets[name]; ok && known {
				serveSwaggerAsset(w, r, name, ctype)
				return
			}
			http.NotFound(w, r)
		}
	})
}

func serveSwaggerAsset(w http.ResponseWriter, r *http.Request, name, ctype string) {
	data, err := swaggerUIFS.ReadFile("swaggerui/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	// The files are pinned to one swagger-ui version and change only with a release.
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

// swaggerIndexHTML is the Swagger UI page. No inline <script> and no inline
// <style>: the CSP is script-src 'self' without 'unsafe-inline', and every asset
// is same-origin. TestSwaggerPage_NoExternalHost keeps it that way.
const swaggerIndexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Keyorix API Documentation</title>
    <link rel="stylesheet" type="text/css" href="/swagger/ui/swagger-ui.css" />
    <link rel="stylesheet" type="text/css" href="/swagger/ui/swagger-page.css" />
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="/swagger/ui/swagger-ui-bundle.js"></script>
    <script src="/swagger/ui/swagger-ui-standalone-preset.js"></script>
    <script src="/swagger/ui/swagger-init.js"></script>
</body>
</html>`

// serveSwaggerIndex serves the Swagger UI HTML (its init script fetches /openapi.yaml).
func serveSwaggerIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(swaggerIndexHTML))
	}
}

// OpenAPISpec serves the embedded OpenAPI specification (YAML).
func OpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(openapiSpecYAML))
}
