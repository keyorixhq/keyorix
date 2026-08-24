// break_glass_s13_test.go — S13 coverage sweep for break_glass.go and
// break_glass_proxy.go. Targets uncovered branches: bad-param paths, missing
// user context, bad JSON, validation errors, and proxy 400 paths.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// newCatalogHandlerBreakGlassS13 returns a CatalogHandler backed by a fresh isolated DB.
func newCatalogHandlerBreakGlassS13(t *testing.T) *CatalogHandler {
	t.Helper()
	cs := freshCoreS12(t)
	return NewCatalogHandler(cs)
}

// ── break_glass.go: ActivateBreakGlass ────────────────────────────────────────

func TestActivateBreakGlass_BadProjectID_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "notanumber")
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestActivateBreakGlass_NoUserCtx_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"justification":"test","ttl":""}`)), "id", "1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestActivateBreakGlass_BadJSON_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad json")), "id", "1"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestActivateBreakGlass_MissingJustification_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"justification":""}`)), "id", "1"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestActivateBreakGlass_CoreError_InternalError_S13 — with a valid param, user ctx,
// and a justification, the core call fails because break-glass is not enabled.
// "ErrorPermissionDenied" is in en.json → i18n returns "permission denied" →
// the handler matches the permission-denied branch → 403.
func TestActivateBreakGlass_CoreError_InternalError_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	body := strings.NewReader(`{"justification":"emergency access needed","ttl":"1h"}`)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", body), "id", "1"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	// break-glass not enabled → core returns "permission denied" → 403
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── break_glass.go: ListBreakGlassActivations ─────────────────────────────────

func TestListBreakGlassActivations_BadProjectID_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "xyz")
	w := httptest.NewRecorder()
	h.ListBreakGlassActivations(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListBreakGlassActivations_EmptyProject_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.ListBreakGlassActivations(w, req)
	// no project with id=9999, but ListBreakGlassActivations returns empty list not error
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── break_glass.go: RevokeBreakGlass ─────────────────────────────────────────

func TestRevokeBreakGlass_BadProjectID_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "notanumber", "activationId": "1"})
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeBreakGlass_BadActivationID_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "1", "activationId": "notanumber"})
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeBreakGlass_NoUserCtx_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "1", "activationId": "1"})
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeBreakGlass_NotFound_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "1", "activationId": "999999"}))
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── break_glass_proxy.go: GetBreakGlassActivationProxy ───────────────────────

func TestGetBreakGlassActivationProxy_BadID_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notanumber")
	w := httptest.NewRecorder()
	h.GetBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetBreakGlassActivationProxy_NotFound_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999999")
	w := httptest.NewRecorder()
	h.GetBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── break_glass_proxy.go: ListBreakGlassActivationsProxy ─────────────────────

func TestListBreakGlassActivationsProxy_MissingProjectID_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil) // no project_id query param
	w := httptest.NewRecorder()
	h.ListBreakGlassActivationsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListBreakGlassActivationsProxy_BadProjectID_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=notanumber", nil)
	w := httptest.NewRecorder()
	h.ListBreakGlassActivationsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListBreakGlassActivationsProxy_HappyPath_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListBreakGlassActivationsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── break_glass_proxy.go: RevokeBreakGlassActivationProxy ────────────────────

func TestRevokeBreakGlassActivationProxy_BadID_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"revoked_by":1}`)), "id", "notanumber")
	w := httptest.NewRecorder()
	h.RevokeBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeBreakGlassActivationProxy_BadJSON_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeBreakGlassActivationProxy_MissingRevokedBy_S13(t *testing.T) {
	h := newCatalogHandlerBreakGlassS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"revoked_by":0}`)), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
