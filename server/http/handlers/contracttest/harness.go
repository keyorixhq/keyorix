package contracttest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
)

func init() {
	// Several enforced operations return live secrets in their body
	// (authLogin/authRefresh's tokens, authGetSetupToken's setup token, and
	// -- as pending operations like createPAT/issueMachineToken graduate to
	// enforced -- PATs and machine tokens too). Without this,
	// *openapi3.SchemaError's Error() method (kin-openapi's default) embeds
	// the actual offending value into its message, which AssertOpenAPIResponse
	// below then hands to t.Fatalf -- so a schema mismatch on one of those
	// operations would leak a real, live token verbatim into `go test`
	// output and, from there, CI logs. Disabling schema error details drops
	// the value dump but keeps the field path and reason, which is still
	// enough to debug the mismatch.
	openapi3.SchemaErrorDetailsDisabled = true
}

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

	opID, err := validateAgainstRouter(router, req, w)
	if err != nil {
		t.Fatalf("contracttest: %v", err)
	}

	exercisedMu.Lock()
	exercised[opID] = true
	exercisedMu.Unlock()
}

// validateAgainstRouter is AssertOpenAPIResponse's actual route-matching and
// schema-validation logic, taking the router explicitly rather than reading
// the package-global one loadSpec() populates. This lets it be exercised
// against a synthetic spec in tests (see harness_test.go's dual-content-type
// test, which needs a spec the real openapi.yaml can't express) using the
// exact same code path production tests run, instead of a hand-rolled copy
// that could silently drift from it. Returns the matched operationId even on
// a validation failure (not a route-match failure), matching
// AssertOpenAPIResponse's error message, which names the operation.
func validateAgainstRouter(router routers.Router, req *http.Request, w *httptest.ResponseRecorder) (string, error) {
	route, pathParams, err := router.FindRoute(req)
	if err != nil {
		return "", fmt.Errorf(
			"%s %s did not resolve to any operation in openapi.yaml (%v) -- "+
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
		return opID, fmt.Errorf(
			"%s %s (operationId=%s, status=%d) response does not match openapi.yaml: %v",
			req.Method, req.URL.Path, opID, w.Code, err,
		)
	}
	return opID, nil
}
