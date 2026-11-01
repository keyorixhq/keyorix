// secret_ref_read_fault_test.go — STORAGE-ERR-CLASS-4 item 1.
//
// core.ResolveSecretRef turned ANY GetSecretByName error into ErrSecretRefNotFound, so a
// storage fault on the by-reference value read answered a global holder 404 and everyone
// else 403. A fault is a retry (503 + Retry-After + storage_unavailable); a ref that
// really names nothing keeps the 404 / 403 split.
package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/core"
)

func srfServeRef(t *testing.T, w *srfWorld, user uint, ref string) *httptest.ResponseRecorder {
	t.Helper()
	called := false
	rec := httptest.NewRecorder()
	req := makeRequest(t, http.MethodGet, "/secrets/value?ref="+url.QueryEscape(ref), nil,
		&UserContext{UserID: user, ActorType: core.ActorTypeUser}, w.cs)
	RequireScopedSecretRefPermission("secrets.read")(okNext(&called)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		assert.False(t, called, "the handler behind the gate ran on a %d", rec.Code)
	}
	return rec
}

func TestSecretRefReadFault_GlobalHolderGets503(t *testing.T) {
	w := newSRFWorld(t)
	w.armOnce(t, "GetSecretByName", errScanFault)
	rec := srfServeRef(t, w, a503UserAdmin, "proj/dev/s")
	w.disarm(t)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "a read fault is not \"not found\": %s", rec.Body.String())
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	assert.Contains(t, rec.Body.String(), `"storage_unavailable"`)
	assert.NotContains(t, rec.Body.String(), "project_id", "the driver cause must not reach the client")

	// Nothing cached: the same request is served once the fault clears.
	assert.Equal(t, http.StatusOK, srfServeRef(t, w, a503UserAdmin, "proj/dev/s").Code)
}

func TestSecretRefReadFault_NonHolderKeepsAbsentRef403(t *testing.T) {
	w := newSRFWorld(t)
	w.armOnce(t, "GetSecretByName", errScanFault)
	fault := srfServeRef(t, w, a503UserNobody, "proj/dev/s")
	w.disarm(t)
	absent := srfServeRef(t, w, a503UserNobody, "proj/dev/missing")
	assert.Equal(t, http.StatusForbidden, absent.Code, absent.Body.String())
	assert.Equal(t, absent.Code, fault.Code)
	assert.Equal(t, absent.Body.String(), fault.Body.String(), "a fault and an absent ref are one answer for a non-holder")
	assert.Empty(t, fault.Header().Get("Retry-After"))
}

func TestSecretRefReadFault_RealNotFoundStays404(t *testing.T) {
	w := newSRFWorld(t)
	rec := srfServeRef(t, w, a503UserAdmin, "proj/dev/missing")
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Empty(t, rec.Header().Get("Retry-After"))
}
