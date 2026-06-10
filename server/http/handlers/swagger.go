package handlers

import (
	_ "embed"
	"net/http"
	"strings"
)

// openapiSpecYAML is the canonical OpenAPI 3.0 spec, embedded at build time and
// served verbatim at /openapi.yaml. Editing openapi.yaml is the single source of
// truth — the Swagger UI and the published spec both read it.
//
//go:embed openapi.yaml
var openapiSpecYAML string

// SwaggerHandler returns a handler for serving Swagger UI. The UI loads the spec
// from /openapi.yaml (the embedded file), so there is no second spec to drift.
func SwaggerHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/swagger/")
		switch path {
		case "", "index.html":
			serveSwaggerIndex(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// serveSwaggerIndex serves the Swagger UI HTML (it fetches /openapi.yaml).
func serveSwaggerIndex(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Keyorix API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
    <style>
        html {
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }
        *, *:before, *:after {
            box-sizing: inherit;
        }
        body {
            margin:0;
            background: #fafafa;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/openapi.yaml',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
        };
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

// OpenAPISpec serves the embedded OpenAPI specification (YAML).
func OpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(openapiSpecYAML))
}
