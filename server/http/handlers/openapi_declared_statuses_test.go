// openapi_declared_statuses_test.go — pins the response statuses openapi.yaml
// declares for operations whose handlers answer a status the spec once left out.
//
// contracttest.AssertOpenAPIResponse validates a body against the declared
// schema but does not fail on a status the operation never declared, so these
// checks read the declared statuses straight from the spec. FuzzOpenAPIStateful
// (server/http) is the oracle that finds such gaps; each case here is the
// deterministic twin of one of its findings.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// declaredStatuses returns the response status keys openapi.yaml declares for one operation.
func declaredStatuses(t *testing.T, method, path string) map[string]bool {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromFile("openapi.yaml")
	require.NoError(t, err)
	item := doc.Paths.Find(path)
	require.NotNil(t, item, "openapi.yaml has no path %s", path)
	op := item.GetOperation(method)
	require.NotNil(t, op, "openapi.yaml has no %s %s", method, path)
	out := map[string]bool{}
	for k := range op.Responses.Map() {
		out[k] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// #4244: the handler answers 204 (no body); the spec declared only 200.
func TestOpenAPIDeclaredStatuses_DeleteRejectionReasonTemplate(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	cw := httptest.NewRecorder()
	h.CreateRejectionReasonTemplate(cw, withUserCtx(httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"name":"decl","reason":"declared"}`))))
	require.Equal(t, http.StatusCreated, cw.Code)

	answered := map[int]*httptest.ResponseRecorder{}
	for _, id := range []string{"1", "999", "abc"} {
		w := httptest.NewRecorder()
		h.DeleteRejectionReasonTemplate(w, withChiParam(withUserCtx(
			httptest.NewRequest(http.MethodDelete, "/", nil)), "id", id))
		answered[w.Code] = w
	}
	require.Contains(t, answered, http.StatusNoContent)
	require.Contains(t, answered, http.StatusNotFound)
	require.Contains(t, answered, http.StatusBadRequest)
	assert.Empty(t, answered[http.StatusNoContent].Body.String(), "204 carries no body")

	declared := declaredStatuses(t, http.MethodDelete, "/api/v1/rejection-reason-templates/{id}")
	for code := range answered {
		assert.True(t, declared[strconv.Itoa(code)], "handler answers %d but the spec declares only %v", code, sortedKeys(declared))
	}
	assert.False(t, declared["200"], "the handler never answers 200; a client waiting for it would misread the 204")
}
