package contracttest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

// dualContentSpec declares DIFFERENT schemas per content type on purpose:
// application/json requires an object with an integer "count" field,
// text/csv requires a plain string. If AssertOpenAPIResponse's underlying
// validation call picked the wrong schema (e.g. always checked JSON, or the
// first content type in map iteration order) these two cases would tell
// apart -- a JSON-shaped body would wrongly fail the csv case, or a
// plain-string body would wrongly fail the json case. The real
// openapi.yaml's only dual-content operation (exportSecretAccessLog)
// declares an identical `{type: string, format: binary}` for both content
// types, which can't distinguish correct content-type selection from a
// library that ignores it entirely -- this synthetic spec exists because
// that distinction matters (ADR-074, requirement 2) and the real spec can't
// prove it either way.
const dualContentSpec = `
openapi: 3.0.3
info:
  title: dual-content-type test
  version: "1.0"
paths:
  /dual:
    get:
      operationId: getDual
      responses:
        '200':
          description: dual content type response
          content:
            application/json:
              schema:
                type: object
                required: [count]
                properties:
                  count: {type: integer}
            text/csv:
              schema:
                type: string
`

func TestContentTypeSelection_NotJSONAssumption(t *testing.T) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(dualContentSpec))
	if err != nil {
		t.Fatalf("loading synthetic spec: %v", err)
	}
	if err := doc.Validate(loader.Context); err != nil {
		t.Fatalf("validating synthetic spec: %v", err)
	}
	r, err := gorillamux.NewRouter(doc)
	if err != nil {
		t.Fatalf("building router: %v", err)
	}

	validate := func(t *testing.T, contentType, body string) error {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/dual", nil)
		route, pathParams, err := r.FindRoute(req)
		if err != nil {
			t.Fatalf("FindRoute: %v", err)
		}
		respInput := &openapi3filter.ResponseValidationInput{
			RequestValidationInput: &openapi3filter.RequestValidationInput{
				Request:    req,
				PathParams: pathParams,
				Route:      route,
			},
			Status: http.StatusOK,
			Header: http.Header{"Content-Type": []string{contentType}},
		}
		respInput.SetBodyBytes([]byte(body))
		return openapi3filter.ValidateResponse(req.Context(), respInput)
	}

	t.Run("csv body validates against the csv (string) schema", func(t *testing.T) {
		if err := validate(t, "text/csv", "id,event\n1,login\n"); err != nil {
			t.Errorf("expected csv body to validate against the string schema, got: %v", err)
		}
	})

	t.Run("json body matching the json schema validates", func(t *testing.T) {
		if err := validate(t, "application/json", `{"count": 3}`); err != nil {
			t.Errorf("expected valid json body to pass, got: %v", err)
		}
	})

	t.Run("json body violating the json schema fails", func(t *testing.T) {
		err := validate(t, "application/json", `{"count": "not-an-integer"}`)
		if err == nil {
			t.Fatal("expected a schema violation for count as a string, got nil error")
		}
		t.Logf("observed failure (expected): %v", err)
	})

	t.Run("a csv-shaped body sent as application/json is rejected by the json schema", func(t *testing.T) {
		// The decisive case: this body satisfies the CSV schema (any
		// string) but NOT the JSON schema (an object with integer count).
		// Declaring it as application/json must fail -- if the library
		// were secretly validating against the csv schema regardless of
		// the declared content type, this would incorrectly pass.
		err := validate(t, "application/json", "id,event\n1,login\n")
		if err == nil {
			t.Fatal("expected the json-declared response to be validated against the JSON " +
				"schema (and fail, since the body is a raw CSV string, not a JSON object) -- " +
				"got nil error, which would mean content type is not actually driving schema selection")
		}
		t.Logf("observed failure (expected, proves content-type selection): %v", err)
	})
}

func TestAssertOpenAPIResponse_UnmatchedRequestFailsLoudly(t *testing.T) {
	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}

	fakeT := &testing.T{}
	req := httptest.NewRequest(http.MethodGet, "/this/path/does/not/exist/in/the/spec", nil)
	w := httptest.NewRecorder()
	w.Code = http.StatusOK
	w.Body = bytes.NewBufferString(`{}`)

	// AssertOpenAPIResponse calls t.Fatalf on a match failure, which for a
	// real *testing.T stops that test's goroutine via runtime.Goexit --
	// running it against a throwaway *testing.T in a subgoroutine lets us
	// observe that it actually failed, instead of silently skipping.
	done := make(chan bool, 1)
	go func() {
		defer func() { done <- fakeT.Failed() }()
		AssertOpenAPIResponse(fakeT, req, w)
	}()
	failed := <-done

	if !failed {
		t.Fatal("expected AssertOpenAPIResponse to fail loudly on an unmatched request path, " +
			"but the test did not fail -- an unmatched request must never be silently skipped")
	}
}
