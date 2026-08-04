package contracttest

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3filter"
)

var (
	exercisedMu sync.Mutex
	exercised   = map[string]bool{}
)

// AssertOpenAPIResponse verifies that w's response matches what openapi.yaml
// declares for the operation req resolves to. Call it after the handler has
// already written to w via its normal httptest.ResponseRecorder call.
//
// It fails the test (t.Fatalf, not a warning) if:
//   - req does not resolve to any operation in the spec (a request the
//     harness can't match can't be verified -- see ADR-074, "unmatched
//     requests fail loudly")
//   - the response does not validate against the schema declared for its
//     actual status code and Content-Type (never assumed to be JSON --
//     openapi3filter.ValidateResponse selects by the response's own
//     Content-Type header, matching ADR-074's dual-content-type requirement)
//
// On success, the matched operationId is recorded as exercised for the
// coverage assertion (see checks.go, CheckAllEnforcedExercised).
func AssertOpenAPIResponse(t *testing.T, req *http.Request, w *httptest.ResponseRecorder) {
	t.Helper()
	loadSpec()
	if specErr != nil {
		t.Fatalf("contracttest: %v", specErr)
	}

	route, pathParams, err := router.FindRoute(req)
	if err != nil {
		t.Fatalf(
			"contracttest: %s %s did not resolve to any operation in openapi.yaml (%v) -- "+
				"a request the harness can't match to a spec operation can't be verified against "+
				"it; fix the request's path to match a real route, or fix the spec",
			req.Method, req.URL.Path, err,
		)
	}
	opID := route.Operation.OperationID

	respInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request:    req,
			PathParams: pathParams,
			Route:      route,
		},
		Status: w.Code,
		Header: w.Header().Clone(),
	}
	respInput.SetBodyBytes(w.Body.Bytes())

	if err := openapi3filter.ValidateResponse(req.Context(), respInput); err != nil {
		t.Fatalf(
			"contracttest: %s %s (operationId=%s, status=%d) response does not match "+
				"openapi.yaml: %v",
			req.Method, req.URL.Path, opID, w.Code, err,
		)
	}

	exercisedMu.Lock()
	exercised[opID] = true
	exercisedMu.Unlock()
}
