// Package contracttest verifies that server/http/handlers responses match
// what server/http/handlers/openapi.yaml declares for them, using
// getkin/kin-openapi against the real spec file.
//
// See docs/adr-074-openapi-contract-test-harness.md for the design record:
// why the spec stays hand-written, why kin-openapi, and the fail-closed
// requirements this package implements.
//
// Usage from a handler test, after the normal httptest.ResponseRecorder call:
//
//	w := httptest.NewRecorder()
//	handler.SomeHandler(w, req)
//	contracttest.AssertOpenAPIResponse(t, req, w)
//
// This package is test-only infrastructure. Nothing in server/http/handlers'
// production code imports it, so kin-openapi is never linked into the
// keyorix-server binary.
package contracttest
