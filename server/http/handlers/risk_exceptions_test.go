// risk_exceptions_test.go — coverage for risk_exceptions.go's live (non-proxy)
// error paths. Extracted from handlers_s13_proxy_test.go (ADR-108 Phase 6):
// that file's remaining 82 tests covered risk_exceptions_proxy.go and other
// deleted /system proxy handlers; these 9 covered the live RiskException*
// handlers and were the only non-proxy tests in that file.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func freshDashboardHandlerS13(t *testing.T) *DashboardHandler {
	t.Helper()
	cs := freshCoreS12(t)
	return NewDashboardHandler(cs)
}

func TestListRiskExceptions_HappyPath_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/risk-exceptions", nil))
	w := httptest.NewRecorder()
	h.ListRiskExceptions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListRiskExceptions_AllParam_S13 — ?all=true → 200.
func TestListRiskExceptions_AllParam_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/risk-exceptions?all=true", nil))
	w := httptest.NewRecorder()
	h.ListRiskExceptions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestCreateRiskException_NoUserCtx_S13 — missing user context → 401.
func TestCreateRiskException_NoUserCtx_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/risk-exceptions", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	h.CreateRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestCreateRiskException_BadJSON_S13 — malformed JSON → 400.
func TestCreateRiskException_BadJSON_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/risk-exceptions", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreateRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateRiskException_BadExpiresAt_S13 — non-RFC3339 expires_at → 400.
func TestCreateRiskException_BadExpiresAt_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	body := `{"title":"T","category":"op","justification":"J","expires_at":"not-a-date"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/risk-exceptions", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreateRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestApproveRiskException_NoUserCtx_S13 — missing user context → 401.
func TestApproveRiskException_NoUserCtx_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/risk-exceptions/1/approve", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ApproveRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestApproveRiskException_BadID_S13 — non-numeric id → 400.
func TestApproveRiskException_BadID_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/risk-exceptions/bad/approve", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.ApproveRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRevokeRiskException_NoUserCtx_S13 — missing user context → 401.
func TestRevokeRiskException_NoUserCtx_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/risk-exceptions/1", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.RevokeRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRevokeRiskException_BadID_S13 — non-numeric id → 400.
func TestRevokeRiskException_BadID_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/risk-exceptions/bad", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.RevokeRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
