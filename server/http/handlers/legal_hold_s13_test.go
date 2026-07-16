// legal_hold_s13_test.go — S13 coverage sweep for legal_hold.go and
// legal_hold_proxy.go. Targets uncovered branches: bad params, missing user
// context, bad JSON, and validation errors.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// newDashboardHandlerS13 returns a DashboardHandler backed by a fresh DB.
func newDashboardHandlerS13(t *testing.T) *DashboardHandler {
	t.Helper()
	cs := freshCoreS12(t)
	return NewDashboardHandler(cs)
}

// ── legal_hold.go: PlaceLegalHold ────────────────────────────────────────────

func TestPlaceLegalHold_NoUserCtx_S13(t *testing.T) {
	h := newDashboardHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/legal-hold", strings.NewReader(`{"reason":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.PlaceLegalHold(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPlaceLegalHold_BadJSON_S13(t *testing.T) {
	h := newDashboardHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/legal-hold", strings.NewReader("{bad json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.PlaceLegalHold(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestPlaceLegalHold_CoreError_Required_S13 — core.PlaceLegalHold enforces that
// reason is non-empty. Sending an empty reason triggers a 400 via the handler's
// "required" branch.
func TestPlaceLegalHold_CoreError_Required_S13(t *testing.T) {
	h := newDashboardHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/legal-hold", strings.NewReader(`{"reason":""}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.PlaceLegalHold(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── legal_hold.go: LiftLegalHold ─────────────────────────────────────────────

func TestLiftLegalHold_NoUserCtx_S13(t *testing.T) {
	h := newDashboardHandlerS13(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/legal-hold", nil)
	w := httptest.NewRecorder()
	h.LiftLegalHold(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestLiftLegalHold_NoHold_S13 — when there is no active hold, core.LiftLegalHold
// returns "no legal hold" which maps to 400.
func TestLiftLegalHold_NoHold_S13(t *testing.T) {
	h := newDashboardHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodDelete, "/api/v1/legal-hold",
		strings.NewReader(`{"reason":"removing hold"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.LiftLegalHold(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── legal_hold_proxy.go: CreateLegalHoldProxy ────────────────────────────────

func TestCreateLegalHoldProxy_BadJSON_S13(t *testing.T) {
	h := newDashboardHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/legal-hold", strings.NewReader("{bad json"))
	w := httptest.NewRecorder()
	h.CreateLegalHoldProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateLegalHoldProxy_MissingReason_S13(t *testing.T) {
	h := newDashboardHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/legal-hold", strings.NewReader(`{"placed_by":1}`))
	w := httptest.NewRecorder()
	h.CreateLegalHoldProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── legal_hold_proxy.go: UpdateLegalHoldProxy ────────────────────────────────

func TestUpdateLegalHoldProxy_BadID_S13(t *testing.T) {
	h := newDashboardHandlerS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "notanumber")
	w := httptest.NewRecorder()
	h.UpdateLegalHoldProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateLegalHoldProxy_BadJSON_S13(t *testing.T) {
	h := newDashboardHandlerS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateLegalHoldProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
