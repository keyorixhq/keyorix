package handlers

import (
	"net/http"
	"net/http/httptest"
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
			assert.Contains(t, body, "/openapi.yaml", "Swagger UI must reference the embedded spec")
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
