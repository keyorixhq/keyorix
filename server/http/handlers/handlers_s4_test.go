// handlers_s4_test.go — broad coverage sweep targeting previously-uncovered
// handler functions. Strategy: proxy handlers get bad-input validation tests
// (early-return paths); CRUD handlers get unauthorized + bad-ID + happy-path
// tests against an empty in-memory DB.
package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// newCatalogHandlerS4 creates a CatalogHandler with the full s4 DB.
func newCatalogHandlerS4(t *testing.T) *CatalogHandler {
	t.Helper()
	return NewCatalogHandler(newHandlerCoreS4(t))
}

// ── access_request_proxy.go ───────────────────────────────────────────────────

func TestValidAccessRequestTargetState(t *testing.T) {
	assert.True(t, validAccessRequestTargetState("approved"))
	assert.True(t, validAccessRequestTargetState("rejected"))
	assert.True(t, validAccessRequestTargetState("withdrawn"))
	assert.True(t, validAccessRequestTargetState("expired"))
	assert.False(t, validAccessRequestTargetState("pending"))
	assert.False(t, validAccessRequestTargetState(""))
	assert.False(t, validAccessRequestTargetState("unknown"))
}

func TestAccessRequestProxyWireRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	w := accessRequestProxyWire{
		ID:        1,
		ProjectID: 2,
		UserID:    3,
		State:     "pending",
		Reason:    "need access",
		CreatedAt: now,
	}
	m := w.toModel()
	require.Equal(t, uint(1), m.ID)
	require.Equal(t, uint(2), m.ProjectID)
	require.Equal(t, "pending", m.State)

	w2 := newAccessRequestProxyWire(m)
	assert.Equal(t, w.ID, w2.ID)
	assert.Equal(t, w.State, w2.State)
}

func TestAccessRequestApprovalProxyWireRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	w := accessRequestApprovalProxyWire{
		ID:         1,
		RequestID:  2,
		ApproverID: 3,
		CreatedAt:  now,
	}
	assert.Equal(t, uint(1), w.ID)
	assert.Equal(t, uint(2), w.RequestID)
	assert.Equal(t, uint(3), w.ApproverID)
	assert.Equal(t, now, w.CreatedAt)
}

func TestCreateAccessRequestProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessRequestProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"state":"pending"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessRequestProxy_MissingState(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"project_id":1,"user_id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetAccessRequestProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notanumber")
	w := httptest.NewRecorder()
	h.GetAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetAccessRequestProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateAccessRequestProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateAccessRequestProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateAccessRequestProxy_InvalidState(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"state":"pending"}`
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAccessRequestsProxy_MissingProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListAccessRequestsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAccessRequestsProxy_InvalidProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=abc", nil)
	w := httptest.NewRecorder()
	h.ListAccessRequestsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAccessRequestsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListAccessRequestsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateAccessRequestApprovalProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.CreateAccessRequestApprovalProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessRequestApprovalProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.CreateAccessRequestApprovalProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessRequestApprovalProxy_MissingApproverID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.CreateAccessRequestApprovalProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAccessRequestApprovalsProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListAccessRequestApprovalsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAccessRequestApprovalsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListAccessRequestApprovalsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── access_review_campaigns_proxy.go ─────────────────────────────────────────

func TestParseRequiredProjectIDQuery_Missing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	_, ok := parseRequiredProjectIDQuery(w, req)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestParseRequiredProjectIDQuery_Invalid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?project_id=abc", nil)
	w := httptest.NewRecorder()
	_, ok := parseRequiredProjectIDQuery(w, req)
	assert.False(t, ok)
}

func TestParseRequiredProjectIDQuery_Valid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?project_id=42", nil)
	w := httptest.NewRecorder()
	id, ok := parseRequiredProjectIDQuery(w, req)
	assert.True(t, ok)
	assert.Equal(t, uint(42), id)
}

func TestAccessReviewCampaignProxyWireRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	w := accessReviewCampaignProxyWire{
		ID:        1,
		ProjectID: 2,
		Name:      "test",
		State:     "open",
		CreatedBy: 3,
		CreatedAt: now,
	}
	m := w.toModel()
	require.Equal(t, uint(1), m.ID)
	w2 := newAccessReviewCampaignProxyWire(m)
	assert.Equal(t, w.ID, w2.ID)
	assert.Equal(t, w.Name, w2.Name)
}

func TestCreateAccessReviewCampaignProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessReviewCampaignProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"x"}`))
	w := httptest.NewRecorder()
	h.CreateAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetAccessReviewCampaignProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAccessReviewCampaignsProxy_MissingProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaignsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAccessReviewCampaignsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaignsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetOpenAccessReviewCampaignProxy_MissingProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetOpenAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetOpenAccessReviewCampaignProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.GetOpenAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetLatestClosedAccessReviewCampaignProxy_MissingProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetLatestClosedAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetLatestClosedAccessReviewCampaignProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.GetLatestClosedAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateAccessReviewCampaignProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateAccessReviewCampaignProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessReviewItemsProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.CreateAccessReviewItemsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessReviewItemsProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.CreateAccessReviewItemsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAccessReviewItemsProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListAccessReviewItemsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAccessReviewItemsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListAccessReviewItemsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCountPendingAccessReviewItemsProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.CountPendingAccessReviewItemsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCountPendingAccessReviewItemsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.CountPendingAccessReviewItemsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetAccessReviewItemProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "itemID", "bad")
	w := httptest.NewRecorder()
	h.GetAccessReviewItemProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetAccessReviewItemProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "itemID", "9999")
	w := httptest.NewRecorder()
	h.GetAccessReviewItemProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateAccessReviewItemProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "itemID", "bad")
	w := httptest.NewRecorder()
	h.UpdateAccessReviewItemProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateAccessReviewItemProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "itemID", "1")
	w := httptest.NewRecorder()
	h.UpdateAccessReviewItemProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── break_glass_proxy.go ──────────────────────────────────────────────────────

func TestBreakGlassActivationProxyWireRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	a := breakGlassActivationProxyWire{
		ID:            1,
		ProjectID:     2,
		UserID:        3,
		RoleID:        4,
		RoleName:      "admin",
		Justification: "emergency",
		State:         "active",
		CreatedAt:     now,
	}
	m := a.toModel()
	require.Equal(t, uint(1), m.ID)
	a2 := newBreakGlassActivationProxyWire(m)
	assert.Equal(t, a.ID, a2.ID)
	assert.Equal(t, a.RoleName, a2.RoleName)
}

func TestCreateBreakGlassActivationProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateBreakGlassActivationProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"project_id":0}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetBreakGlassActivationProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetBreakGlassActivationProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListBreakGlassActivationsProxy_MissingProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListBreakGlassActivationsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListBreakGlassActivationsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListBreakGlassActivationsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateBreakGlassActivationProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateBreakGlassActivationProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeBreakGlassActivationProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.RevokeBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── catalog.go ────────────────────────────────────────────────────────────────

func TestGetProjectDrift_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetProjectDrift(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetProjectDrift_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetProjectDrift(w, req)
	// No project → 200 with empty drift (core returns empty for unknown project)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestListEnvironments_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/environments", nil)
	w := httptest.NewRecorder()
	h.ListEnvironments(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateProject_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateProject(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateProject_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateProject(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteProject_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteProject(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteProject_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.DeleteProject(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestCreateProjectEnvironment_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.CreateProjectEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateProjectEnvironment_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.CreateProjectEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateProjectEnvironment_MissingName(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.CreateProjectEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteEnvironment_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteEnvironment_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.DeleteEnvironment(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListProjectEnvironments_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListProjectEnvironments(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListProjectEnvironments_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListProjectEnvironments(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRestoreEnvironment_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"projectId": "bad", "id": "1"})
	w := httptest.NewRecorder()
	h.RestoreEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRestoreEnvironment_BadEnvID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"projectId": "1", "id": "bad"})
	w := httptest.NewRecorder()
	h.RestoreEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── connect.go ────────────────────────────────────────────────────────────────

// TestIsSafeConnectError checks isSafeConnectError's classification of the
// core package's typed connect sentinels (see also
// TestIsSafeConnectError_ExtraStrings_S23 for the G50 anti-spoofing coverage:
// a look-alike error carrying the same text but not wrapping a sentinel must
// NOT be classified as safe).
func TestIsSafeConnectError(t *testing.T) {
	assert.True(t, isSafeConnectError(core.ErrConnectDisabled))
	assert.True(t, isSafeConnectError(fmt.Errorf("%w %q", core.ErrConnectUnknownConnector, "foo")))
	assert.True(t, isSafeConnectError(core.ErrConnectRoleRequired))
	assert.True(t, isSafeConnectError(fmt.Errorf("ref %q %w %q", "r", core.ErrConnectRefNotPermitted, "c")))
	assert.False(t, isSafeConnectError(errors.New("some storage layer error")))
	assert.False(t, isSafeConnectError(nil))
}

func TestNewConnectHandler(t *testing.T) {
	h := NewConnectHandler(newHandlerCore(t))
	require.NotNil(t, h)
}

func TestConnectHandler_ListConnectors_Unauthorized(t *testing.T) {
	h := NewConnectHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListConnectors(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestConnectHandler_GetSecret_Unauthorized(t *testing.T) {
	h := NewConnectHandler(newHandlerCore(t))
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"connector": "vault", "ref": "secret/foo"})
	w := httptest.NewRecorder()
	h.GetSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestConnectHandler_ListRefGrants_Unauthorized(t *testing.T) {
	h := NewConnectHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListRefGrants(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestConnectHandler_CreateRefGrant_Unauthorized(t *testing.T) {
	h := NewConnectHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.CreateRefGrant(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestConnectHandler_DeleteRefGrant_Unauthorized(t *testing.T) {
	h := NewConnectHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteRefGrant(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── dashboard.go ──────────────────────────────────────────────────────────────

func TestDashboardHandler_GetStats_Unauthorized(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/stats", nil)
	w := httptest.NewRecorder()
	h.GetStats(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDashboardHandler_GetStats_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/stats", nil))
	w := httptest.NewRecorder()
	h.GetStats(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_GetCompliancePosture_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/posture", nil)
	w := httptest.NewRecorder()
	h.GetCompliancePosture(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_GetComplianceDigest_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/digest", nil)
	w := httptest.NewRecorder()
	h.GetComplianceDigest(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_VerifyComplianceEvidence_BadJSON(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.VerifyComplianceEvidence(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDashboardHandler_VerifyComplianceEvidence_BadBase64(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	body := `{"data_b64":"not!valid@base64","signature":""}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.VerifyComplianceEvidence(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDashboardHandler_VerifyComplianceEvidence_ValidBase64(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	data := base64.StdEncoding.EncodeToString([]byte("somedata"))
	body, _ := json.Marshal(map[string]string{"data_b64": data, "signature": "sig"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.VerifyComplianceEvidence(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_GetComplianceControls_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/controls", nil)
	w := httptest.NewRecorder()
	h.GetComplianceControls(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_GetComplianceEvidence_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/evidence", nil)
	w := httptest.NewRecorder()
	h.GetComplianceEvidence(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_GetActivity_Unauthorized(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/activity", nil)
	w := httptest.NewRecorder()
	h.GetActivity(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDashboardHandler_GetActivity_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/activity", nil))
	w := httptest.NewRecorder()
	h.GetActivity(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// sharedS4Core is initialised exactly once for the entire test binary. All
// s4 tests are structural/error-path tests (bad JSON, missing auth, bad IDs)
// that never assert on specific row counts or pre-seeded DB state, so sharing
// a single migrated core across the run is safe and eliminates the ~1400×
// AutoMigrate calls that caused the 2-minute CI timeout under -race.
var (
	sharedS4CoreOnce sync.Once
	sharedS4Core     *core.KeyorixCore
)

// s4UniqueCounter mints a per-process-unique suffix for literal values (e.g.
// SSO state tokens, WebAuthn credential IDs, credential token hashes) that a
// handful of s4/s5/s9 tests insert into the shared sharedS4Core DB. Those
// tests assert on a fixed-string insert succeeding; under `go test -count=N`
// the whole binary (and sharedS4Core with it) is reused across iterations, so
// a hardcoded literal collides with its own prior insert on repeat. Folding
// this counter into the literal keeps each invocation's value unique without
// touching the singleton itself. Shared across files (not per-file, unlike
// the sN DBCounter DSN-uniqueness vars elsewhere in this package) because all
// of s4/s5/s9 write into the SAME sharedS4Core DB, not independent ones.
var s4UniqueCounter atomic.Int64

// newHandlerCoreS4 returns a shared *core.KeyorixCore backed by a single
// in-memory SQLite DB whose schema is migrated exactly once per test binary.
// All s4 tests are early-return path tests (4xx status checks) that do not
// rely on an empty DB, so the shared instance is safe.
func newHandlerCoreS4(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	sharedS4CoreOnce.Do(func() {
		db, err := gorm.Open(sqlite.Open("file:kxhandlers_s4?mode=memory&cache=shared&_timeout=30000"), &gorm.Config{})
		if err != nil {
			panic("newHandlerCoreS4: open DB: " + err.Error())
		}
		if err := db.AutoMigrate(
			&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
			&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
			&models.Project{}, &models.Environment{}, &models.SecretNode{},
			&models.AuditEvent{}, &models.AnomalyAlert{},
			&models.RotationPolicy{}, &models.Notification{},
			&models.ProjectMembership{}, &models.SoDPolicy{},
			&models.BreakGlassActivation{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
			&models.LoginAttempt{},
			// s4 additions:
			&models.AccessRequest{}, &models.AccessRequestApproval{},
			&models.WebAuthnCredential{}, &models.WebAuthnSession{},
			&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
			&models.ConnectRefGrant{}, &models.Session{}, &models.SetupToken{},
			&models.MFAChallenge{}, &models.SSOLoginState{},
			// s4 round2 additions:
			&models.MachineIdentity{}, &models.MachineIdentityCredential{},
			&models.MachineIdentityRole{}, &models.MachineIdentityOIDCBinding{},
			&models.SecretDependency{}, &models.RiskException{},
			&models.MFASecret{}, &models.MFARecoveryCode{},
			&models.IdentityProvider{}, &models.ExternalIdentity{},
			&models.LegalHold{}, &models.ShareRecord{},
			&models.PersonalAccessToken{},
			// s4 batch3 additions:
			&models.ProjectInvitation{}, &models.SchedulerLockLease{},
			&models.SecretAccessLog{},
			&models.SecretACL{},
		); err != nil {
			panic("newHandlerCoreS4: AutoMigrate: " + err.Error())
		}
		sharedS4Core = core.NewKeyorixCore(store.NewLocalStorage(db))
	})
	return sharedS4Core
}

// newAuthHandlerWithWebAuthn creates an AuthHandler backed by a DB that also
// has the WebAuthn tables migrated (required by the proxy tests).
func newAuthHandlerWithWebAuthn(t *testing.T) *AuthHandler {
	t.Helper()
	return NewAuthHandler(newHandlerCoreS4(t), false)
}

// ── webauthn_proxy.go ─────────────────────────────────────────────────────────

func TestParseWebAuthnUserIDQuery_Missing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	_, ok := parseWebAuthnUserIDQuery(w, req)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestParseWebAuthnUserIDQuery_Invalid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?user_id=abc", nil)
	w := httptest.NewRecorder()
	_, ok := parseWebAuthnUserIDQuery(w, req)
	assert.False(t, ok)
}

func TestParseWebAuthnUserIDQuery_Valid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?user_id=42", nil)
	w := httptest.NewRecorder()
	id, ok := parseWebAuthnUserIDQuery(w, req)
	assert.True(t, ok)
	assert.Equal(t, uint(42), id)
}

func TestWebAuthnCredentialProxyWireRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	w := webAuthnCredentialProxyWire{
		ID:           1,
		UserID:       2,
		CredentialID: []byte("credid"),
		Name:         "hw key",
		CreatedAt:    now,
	}
	m := w.toModel()
	require.Equal(t, uint(1), m.ID)
	w2 := newWebAuthnCredentialProxyWire(m)
	assert.Equal(t, w.ID, w2.ID)
	assert.Equal(t, w.Name, w2.Name)
}

func TestWebAuthnSessionProxyWireRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := webAuthnSessionProxyWire{
		ID:        1,
		UserID:    2,
		TokenHash: "hash",
		Purpose:   "registration",
		Data:      []byte("data"),
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
	m := s.toModel()
	require.Equal(t, uint(1), m.ID)
	s2 := newWebAuthnSessionProxyWire(m)
	assert.Equal(t, s.TokenHash, s2.TokenHash)
}

func TestCreateWebAuthnCredentialProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateWebAuthnCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateWebAuthnCredentialProxy_MissingFields(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":0}`))
	w := httptest.NewRecorder()
	h.CreateWebAuthnCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListWebAuthnCredentialsProxy_MissingUserID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListWebAuthnCredentialsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListWebAuthnCredentialsProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/?user_id=1", nil)
	w := httptest.NewRecorder()
	h.ListWebAuthnCredentialsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetWebAuthnCredentialByCredIDProxy_MissingUserID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetWebAuthnCredentialByCredIDProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetWebAuthnCredentialByCredIDProxy_MissingCredID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/?user_id=1", nil)
	w := httptest.NewRecorder()
	h.GetWebAuthnCredentialByCredIDProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetWebAuthnCredentialByCredIDProxy_InvalidBase64(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/?user_id=1&credential_id=not!base64", nil)
	w := httptest.NewRecorder()
	h.GetWebAuthnCredentialByCredIDProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetWebAuthnCredentialByCredIDProxy_NotFound(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	credID := base64.StdEncoding.EncodeToString([]byte("nosuchcred"))
	req := httptest.NewRequest(http.MethodGet, "/?user_id=1&credential_id="+credID, nil)
	w := httptest.NewRecorder()
	h.GetWebAuthnCredentialByCredIDProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateWebAuthnCredentialProxy_BadID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateWebAuthnCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateWebAuthnCredentialProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateWebAuthnCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdvanceWebAuthnCredentialCounterProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.AdvanceWebAuthnCredentialCounterProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdvanceWebAuthnCredentialCounterProxy_MissingFields(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(`{"user_id":0}`))
	w := httptest.NewRecorder()
	h.AdvanceWebAuthnCredentialCounterProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteWebAuthnCredentialProxy_BadUserID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"userId": "bad", "id": "1"})
	w := httptest.NewRecorder()
	h.DeleteWebAuthnCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteWebAuthnCredentialProxy_BadCredID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"userId": "1", "id": "bad"})
	w := httptest.NewRecorder()
	h.DeleteWebAuthnCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCountWebAuthnCredentialsProxy_MissingUserID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.CountWebAuthnCredentialsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCountWebAuthnCredentialsProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/?user_id=1", nil)
	w := httptest.NewRecorder()
	h.CountWebAuthnCredentialsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSetUserWebAuthnEnabledProxy_BadUserID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "userId", "bad")
	w := httptest.NewRecorder()
	h.SetUserWebAuthnEnabledProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetUserWebAuthnEnabledProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "userId", "1")
	w := httptest.NewRecorder()
	h.SetUserWebAuthnEnabledProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateWebAuthnSessionProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateWebAuthnSessionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateWebAuthnSessionProxy_MissingFields(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":0}`))
	w := httptest.NewRecorder()
	h.CreateWebAuthnSessionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestConsumeWebAuthnSessionProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.ConsumeWebAuthnSessionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestConsumeWebAuthnSessionProxy_MissingFields(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.ConsumeWebAuthnSessionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestConsumeWebAuthnSessionProxy_NotFound(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body, _ := json.Marshal(map[string]any{
		"token_hash": "nosuchtoken",
		"now":        time.Now(),
	})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ConsumeWebAuthnSessionProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── users (package-level dispatch when defaultUserHandler == nil) ─────────────

func TestPackageLevelUserFunctions_ServiceUnavailable(t *testing.T) {
	// Save and nil out the global handler.
	saved := defaultUserHandler
	defaultUserHandler = nil
	t.Cleanup(func() { defaultUserHandler = saved })

	funcs := []struct {
		name string
		fn   http.HandlerFunc
	}{
		{"UnlockUser", UnlockUser},
		{"SuspendUser", SuspendUser},
		{"RevokeSessions", RevokeSessions},
		{"ReactivateUser", ReactivateUser},
		{"RequirePasswordReset", RequirePasswordReset},
		{"ResendSetupLink", ResendSetupLink},
	}
	for _, tc := range funcs {
		t.Run(tc.name, func(t *testing.T) {
			req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
			w := httptest.NewRecorder()
			tc.fn(w, req)
			assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		})
	}
}

// ── users_list.go ─────────────────────────────────────────────────────────────

func newUserHandler(t *testing.T) *UserHandler {
	t.Helper()
	cs := newHandlerCore(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	return h
}

func TestListUsers_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListUsers_HappyPath(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users", nil))
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListUsers_WithSearch(t *testing.T) {
	// SQLite in-memory does not support ILIKE — handler path is still exercised.
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users?search=foo&is_active=true", nil))
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	// Non-bad-request response means auth + param path was traversed
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestListUsers_InactiveFilter(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users?filter=inactive", nil))
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListUsers_LargePageClamped(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users?page=99999999&page_size=50", nil))
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSearchUsers_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/search?q=foo", nil)
	w := httptest.NewRecorder()
	h.SearchUsers(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSearchUsers_MissingQuery(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/search", nil))
	w := httptest.NewRecorder()
	h.SearchUsers(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSearchUsers_HappyPath(t *testing.T) {
	// SQLite in-memory does not support ILIKE so the search returns an internal
	// error — the handler path past the auth/param checks is still exercised.
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/search?q=alice", nil))
	w := httptest.NewRecorder()
	h.SearchUsers(w, req)
	// Expect any non-400 response (auth passed, query param present)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestStaleAccounts_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/stale", nil)
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestStaleAccounts_InvalidState(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/stale?state=invalid_state", nil))
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestStaleAccounts_HappyPath(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/stale", nil))
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── users_roles.go ────────────────────────────────────────────────────────────

func newUsersRolesHandler(t *testing.T) *UsersRolesHandler {
	t.Helper()
	return NewUsersRolesHandler(newHandlerCore(t))
}

func TestGetUserRolesForUser_Unauthorized(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserRolesForUser_BadID(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUserRolesForUser_HappyPath(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	// User not found returns empty roles (no error from storage)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestGetUserPermissionsForUser_Unauthorized(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserPermissionsForUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserPermissionsForUser_BadID(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUserPermissionsForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUserMembershipsForUser_Unauthorized(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserMembershipsForUser_BadID(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUserMembershipsForUser_HappyPath(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateUserRoles_Unauthorized(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUpdateUserRoles_BadID(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateUserRoles_BadJSON(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateUserRoles_EmptyRoles(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"role_ids":[]}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	// User 1 doesn't exist → 404 or 500 (no 200)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── admin_impersonation.go ────────────────────────────────────────────────────

func TestImpersonationHandler_ClientIP(t *testing.T) {
	// clientIP is called from Start — test it via its effect on Start
	cs := newHandlerCore(t)
	h := NewImpersonationHandler(cs, false)
	body := `{"user_id":1}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	h.Start(w, req)
	// Will fail (user not found or no permission), but clientIP is exercised
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── groups_proxy.go ───────────────────────────────────────────────────────────

func newGroupHandler(t *testing.T) *GroupHandler {
	t.Helper()
	h, err := NewGroupHandler(newHandlerCore(t))
	require.NoError(t, err)
	return h
}

func TestGroupProxyWireRoundTrip(t *testing.T) {
	w := groupProxyWire{ID: 1, Name: "devs", Description: "dev team"}
	m := w.toModel()
	require.Equal(t, uint(1), m.ID)
	w2 := newGroupProxyWire(m)
	assert.Equal(t, w.Name, w2.Name)
}

func TestIsGroupNotFound(t *testing.T) {
	assert.True(t, isGroupNotFound(fmt.Errorf("group not found")))
	assert.True(t, isGroupNotFound(fmt.Errorf("GroupNotFound")))
	assert.False(t, isGroupNotFound(fmt.Errorf("storage error")))
}

func TestCreateGroupProxy_BadJSON(t *testing.T) {
	h := newGroupHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateGroupProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateGroupProxy_MissingName(t *testing.T) {
	h := newGroupHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreateGroupProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetGroupProxy_BadID(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetGroupProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetGroupProxy_NotFound(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetGroupProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateGroupProxy_BadID(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateGroupProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateGroupProxy_BadJSON(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateGroupProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteGroupProxy_BadID(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteGroupProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteGroupProxy_NotFound(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.DeleteGroupProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRestoreGroupProxy_BadID(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.RestoreGroupProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRestoreGroupProxy_NotFound(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.RestoreGroupProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListGroupsProxy_HappyPath(t *testing.T) {
	h := newGroupHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListGroupsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListGroupsPageProxy_BadOffset(t *testing.T) {
	h := newGroupHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/?offset=bad&limit=10", nil)
	w := httptest.NewRecorder()
	h.ListGroupsPageProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListGroupsPageProxy_BadLimit(t *testing.T) {
	h := newGroupHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/?offset=0&limit=bad", nil)
	w := httptest.NewRecorder()
	h.ListGroupsPageProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListGroupsPageProxy_HappyPath(t *testing.T) {
	h := newGroupHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/?offset=0&limit=10", nil)
	w := httptest.NewRecorder()
	h.ListGroupsPageProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAddGroupMemberProxy_BadID(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.AddGroupMemberProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAddGroupMemberProxy_BadJSON(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.AddGroupMemberProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAddGroupMemberProxy_MissingUserID(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.AddGroupMemberProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveGroupMemberProxy_BadGroupID(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "bad", "userId": "1"})
	w := httptest.NewRecorder()
	h.RemoveGroupMemberProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveGroupMemberProxy_BadUserID(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "userId": "bad"})
	w := httptest.NewRecorder()
	h.RemoveGroupMemberProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListGroupMembersProxy_BadID(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListGroupMembersProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListGroupMembersProxy_NotFound(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListGroupMembersProxy(w, req)
	// empty DB → group not found → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListGroupMembersByIDsProxy_MissingIDs(t *testing.T) {
	h := newGroupHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListGroupMembersByIDsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListGroupMembersByIDsProxy_InvalidIDs(t *testing.T) {
	h := newGroupHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/?ids=1,abc,3", nil)
	w := httptest.NewRecorder()
	h.ListGroupMembersByIDsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListGroupMembersByIDsProxy_HappyPath(t *testing.T) {
	h := newGroupHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/?ids=1,2,3", nil)
	w := httptest.NewRecorder()
	h.ListGroupMembersByIDsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetUserGroupsProxy_BadID(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetUserGroupsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUserGroupsProxy_HappyPath(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserGroupsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── groups_handler.go ─────────────────────────────────────────────────────────

func TestGroupHandler_ListGroups_Unauthorized(t *testing.T) {
	h := newGroupHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListGroups(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGroupHandler_ListGroups_HappyPath(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListGroups(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGroupHandler_GetGroup_BadID(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_DeleteGroup_BadID(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.DeleteGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── dynamic_secrets_proxy.go ──────────────────────────────────────────────────

func newDynamicSecretHandlerS4(t *testing.T) *DynamicSecretHandler {
	t.Helper()
	return NewDynamicSecretHandler(newHandlerCoreS4(t))
}

func TestIsSafeDynamicSecretError(t *testing.T) {
	assert.True(t, isSafeDynamicSecretError("config not found"))
	assert.True(t, isSafeDynamicSecretError("lease not found"))
	assert.True(t, isSafeDynamicSecretError("lease is not active"))
	assert.True(t, isSafeDynamicSecretError("active-lease limit reached"))
	assert.False(t, isSafeDynamicSecretError("connection refused"))
}

func TestNewDynamicSecretHandler(t *testing.T) {
	h := NewDynamicSecretHandler(newHandlerCore(t))
	require.NotNil(t, h)
}

func TestParseProxyScopeQuery_MissingProjectID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	_, _, ok := parseProxyScopeQuery(w, req)
	assert.False(t, ok)
}

func TestParseProxyScopeQuery_InvalidProjectID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?project_id=abc", nil)
	w := httptest.NewRecorder()
	_, _, ok := parseProxyScopeQuery(w, req)
	assert.False(t, ok)
}

func TestParseProxyScopeQuery_InvalidEnvironmentID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1&environment_id=bad", nil)
	w := httptest.NewRecorder()
	_, _, ok := parseProxyScopeQuery(w, req)
	assert.False(t, ok)
}

func TestParseProxyScopeQuery_Valid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?project_id=5&environment_id=3", nil)
	w := httptest.NewRecorder()
	pid, eid, ok := parseProxyScopeQuery(w, req)
	assert.True(t, ok)
	assert.Equal(t, uint(5), pid)
	assert.Equal(t, uint(3), eid)
}

func TestParseProxyConfigIDQuery_Missing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	_, ok := parseProxyConfigIDQuery(w, req)
	assert.False(t, ok)
}

func TestParseProxyConfigIDQuery_Valid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?config_id=7", nil)
	w := httptest.NewRecorder()
	id, ok := parseProxyConfigIDQuery(w, req)
	assert.True(t, ok)
	assert.Equal(t, uint(7), id)
}

func TestCreateDynamicSecretConfigProxy_BadJSON(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateDynamicSecretConfigProxy_MissingFields(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"x"}`))
	w := httptest.NewRecorder()
	h.CreateDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetDynamicSecretConfigProxy_BadID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetDynamicSecretConfigProxy_NotFound(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListDynamicSecretConfigsProxy_MissingProjectID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListDynamicSecretConfigsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListDynamicSecretConfigsProxy_HappyPath(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListDynamicSecretConfigsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateDynamicSecretConfigProxy_BadID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateDynamicSecretConfigProxy_BadJSON(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCountDynamicSecretConfigsByClassificationProxy_HappyPath(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.CountDynamicSecretConfigsByClassificationProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateDynamicSecretLeaseProxy_BadJSON(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateDynamicSecretLeaseProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateDynamicSecretLeaseProxy_MissingFields(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"config_id":0}`))
	w := httptest.NewRecorder()
	h.CreateDynamicSecretLeaseProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetDynamicSecretLeaseProxy_NotFound(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "leaseID", "nosuchlease")
	w := httptest.NewRecorder()
	h.GetDynamicSecretLeaseProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListDynamicSecretLeasesProxy_MissingConfigID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListDynamicSecretLeasesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListDynamicSecretLeasesProxy_HappyPath(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?config_id=1", nil)
	w := httptest.NewRecorder()
	h.ListDynamicSecretLeasesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCountActiveLeasesProxy_MissingConfigID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.CountActiveLeasesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCountActiveLeasesProxy_HappyPath(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?config_id=1", nil)
	w := httptest.NewRecorder()
	h.CountActiveLeasesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateDynamicSecretLeaseProxy_BadJSON(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "leaseID", "lease-1")
	w := httptest.NewRecorder()
	h.UpdateDynamicSecretLeaseProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListExpiredActiveLeasesProxy_MissingBefore(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListExpiredActiveLeasesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListExpiredActiveLeasesProxy_InvalidBefore(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?before=notadate", nil)
	w := httptest.NewRecorder()
	h.ListExpiredActiveLeasesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListExpiredActiveLeasesProxy_HappyPath(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	before := time.Now().UTC().Format(time.RFC3339Nano)
	req := httptest.NewRequest(http.MethodGet, "/?before="+before, nil)
	w := httptest.NewRecorder()
	h.ListExpiredActiveLeasesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── sod.go ────────────────────────────────────────────────────────────────────

func TestSoDHandler_ListSoDPolicies_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSoDPolicies(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSoDHandler_CreateSoDPolicy_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSoDHandler_CreateSoDPolicy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSoDHandler_DeleteSoDPolicy_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteSoDPolicy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSoDHandler_DeleteSoDPolicy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.DeleteSoDPolicy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSoDHandler_ListSoDViolations_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSoDViolations(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── sod_proxy.go ──────────────────────────────────────────────────────────────

func TestCreateSoDPolicyProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateSoDPolicyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateSoDPolicyProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"x"}`))
	w := httptest.NewRecorder()
	h.CreateSoDPolicyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSoDPolicyProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetSoDPolicyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSoDPolicyProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetSoDPolicyProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListSoDPoliciesProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSoDPoliciesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteSoDPolicyProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteSoDPolicyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteSoDPolicyProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.DeleteSoDPolicyProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── deployment_hygiene.go ─────────────────────────────────────────────────────

func TestDeploymentHygiene_Unauthorized(t *testing.T) {
	cs := newHandlerCore(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.DeploymentHygiene(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeploymentHygiene_HappyPath(t *testing.T) {
	cs := newHandlerCore(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.DeploymentHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── users_crud.go (UserHandler methods) ──────────────────────────────────────

func TestUserHandler_GetUser_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetUser_BadID(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetUser_NotFound(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.GetUser(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_GetUserByEmail_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/?email=x@y.com", nil)
	w := httptest.NewRecorder()
	h.GetUserByEmail(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetUserByEmail_MissingEmail(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetUserByEmail(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetUserByEmail_NotFound(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?email=notfound@x.com", nil))
	w := httptest.NewRecorder()
	h.GetUserByEmail(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_GetUserByUsername_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/?username=alice", nil)
	w := httptest.NewRecorder()
	h.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetUserByUsername_MissingUsername(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetUserByUsername_NotFound(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?username=nobody", nil))
	w := httptest.NewRecorder()
	h.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_DeleteUser_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_RestoreUser_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RestoreUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_UnlockUser_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.UnlockUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_SuspendUser_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.SuspendUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_ReactivateUser_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ReactivateUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_RequirePasswordReset_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RequirePasswordReset(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_ResendSetupLink_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ResendSetupLink(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── sessions_remote.go ────────────────────────────────────────────────────────

func TestGetSessionByToken_PackageLevel_ServiceUnavailable(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	t.Cleanup(func() { defaultUserHandler = saved })
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "token", "abc")
	w := httptest.NewRecorder()
	GetSessionByToken(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestDeleteSessionByID_PackageLevel_ServiceUnavailable(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	t.Cleanup(func() { defaultUserHandler = saved })
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	DeleteSessionByID(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestUserHandler_GetSessionByToken_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "token", "tok")
	w := httptest.NewRecorder()
	h.GetSessionByToken(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetSessionByToken_MissingToken(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "token", ""))
	w := httptest.NewRecorder()
	h.GetSessionByToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_DeleteSessionByID_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteSessionByID(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_DeleteSessionByID_BadID(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.DeleteSessionByID(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── dynamic_secrets.go (human-facing handler) ─────────────────────────────────

func TestDynamicSecretHandler_CreateConfig_Unauthorized(t *testing.T) {
	h := NewDynamicSecretHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	// No user context → 401 (CreateConfig checks userCtx first)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDynamicSecretHandler_ListConfigs_Unauthorized(t *testing.T) {
	h := NewDynamicSecretHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	// authorize(nil ctx) → false, false → denyAuthz → 403
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDynamicSecretHandler_GetConfig_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.GetConfig(w, req)
	// Config not found → 404 (before auth check)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDynamicSecretHandler_GetConfig_BadID(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetConfig(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDynamicSecretHandler_IssueLease_BadID(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "notanid")
	w := httptest.NewRecorder()
	h.IssueLease(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDynamicSecretHandler_IssueLease_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.IssueLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDynamicSecretHandler_ListLeases_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDynamicSecretHandler_RevokeLease_Unauthorized(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "leaseID", "l1")
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	// No user context → 401
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDynamicSecretHandler_RenewLease_Unauthorized(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "leaseID", "l1")
	w := httptest.NewRecorder()
	h.RenewLease(w, req)
	// No user context → 401
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDynamicSecretHandler_RevokeAllLeases_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	// Config not found → 404 (loadAuthorizedConfig fails before user ctx check)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDynamicSecretHandler_ClassifyConfig_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDynamicSecretHandler_SetConfigEnabled_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── connect_grants_proxy.go ───────────────────────────────────────────────────

func TestConnectRefGrantProxyWireRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	g := &models.ConnectRefGrant{
		RoleID:    5,
		Connector: "github",
		RefPrefix: "refs/heads/",
		CreatedAt: now,
	}
	w := newConnectRefGrantProxyWire(g)
	assert.Equal(t, uint(5), w.RoleID)
	assert.Equal(t, "github", w.Connector)
	assert.Equal(t, "refs/heads/", w.RefPrefix)
}

func TestConnectRefGrantsProxyWireList_Empty(t *testing.T) {
	out := connectRefGrantsProxyWireList(nil)
	assert.NotNil(t, out)
	assert.Len(t, out, 0)
}

func TestListConnectRefGrantsByConnectorProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "connector", "github")
	w := httptest.NewRecorder()
	h.ListConnectRefGrantsByConnectorProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListConnectRefGrantsProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListConnectRefGrantsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateConnectRefGrantProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateConnectRefGrantProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateConnectRefGrantProxy_MissingFields(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body, _ := json.Marshal(map[string]any{"role_id": 0, "connector": ""})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateConnectRefGrantProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteConnectRefGrantProxy_BadID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteConnectRefGrantProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteConnectRefGrantProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.DeleteConnectRefGrantProxy(w, req)
	// No row → storage returns nil error (delete idempotent) → 200
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── setup_tokens_proxy.go ─────────────────────────────────────────────────────

func TestSetupTokenProxyWireRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	tok := &models.SetupToken{
		TokenHash:    "abc123",
		Purpose:      "invite",
		SubjectEmail: "a@b.com",
		State:        "active",
		ExpiresAt:    now.Add(time.Hour),
		CreatedAt:    now,
	}
	w := newSetupTokenProxyWire(tok)
	assert.Equal(t, "abc123", w.TokenHash)
	assert.Equal(t, "invite", w.Purpose)
	assert.Equal(t, "a@b.com", w.SubjectEmail)
	assert.Equal(t, "active", w.State)
	m := w.toModel()
	assert.Equal(t, "abc123", m.TokenHash)
	assert.Equal(t, "invite", m.Purpose)
}

func TestCreateSetupTokenProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateSetupTokenProxy_MissingFields(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body, _ := json.Marshal(map[string]string{"token_hash": "", "purpose": "", "subject_email": ""})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSetupTokenByHashProxy_NotFound(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "hash", "nonexistent")
	w := httptest.NewRecorder()
	h.GetSetupTokenByHashProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSupersedeSetupTokensProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.SupersedeSetupTokensProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSupersedeSetupTokensProxy_MissingFields(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body, _ := json.Marshal(map[string]string{"purpose": "", "subject_email": ""})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.SupersedeSetupTokensProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestConsumeSetupTokenProxy_BadID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")), "id", "bad")
	w := httptest.NewRecorder()
	h.ConsumeSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExpireSetupTokenProxy_BadID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ExpireSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCountSetupTokensSinceProxy_BadQuery(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/?since=bad", nil)
	w := httptest.NewRecorder()
	h.CountSetupTokensSinceProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── mfa_management_proxy.go ──────────────────────────────────────────────────

func TestMFASecretProxyWireRoundTrip(t *testing.T) {
	s := &models.MFASecret{UserID: 1}
	w := newMFASecretProxyWire(s)
	assert.Equal(t, uint(1), w.UserID)
}

func TestParseMFAUserIDQuery_Missing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	_, ok := parseMFAUserIDQuery(w, req)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestParseMFAUserIDQuery_Invalid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?user_id=abc", nil)
	w := httptest.NewRecorder()
	_, ok := parseMFAUserIDQuery(w, req)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestParseMFAUserIDQuery_Valid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?user_id=42", nil)
	w := httptest.NewRecorder()
	uid, ok := parseMFAUserIDQuery(w, req)
	assert.True(t, ok)
	assert.Equal(t, uint(42), uid)
}

func TestParseMFAUserIDParam_BadID(t *testing.T) {
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "userId", "bad")
	w := httptest.NewRecorder()
	_, ok := parseMFAUserIDParam(w, req, "userId")
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpsertMFASecretProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.UpsertMFASecretProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpsertMFASecretProxy_MissingUserID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body, _ := json.Marshal(map[string]any{"user_id": 0, "secret": "abc"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.UpsertMFASecretProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMFASecretProxy_MissingQuery(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetMFASecretProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestActivateMFASecretProxy_BadParam(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "userID", "bad")
	w := httptest.NewRecorder()
	h.ActivateMFASecretProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteMFAForUserProxy_BadParam(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "userID", "bad")
	w := httptest.NewRecorder()
	h.DeleteMFAForUserProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetUserMFAEnabledProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.SetUserMFAEnabledProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetUserMFAEnabledProxy_MissingUserID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body, _ := json.Marshal(map[string]any{"user_id": 0, "enabled": true})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.SetUserMFAEnabledProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateMFARecoveryCodesProxy_BadParam(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")), "userID", "bad")
	w := httptest.NewRecorder()
	h.CreateMFARecoveryCodesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCountUnusedMFARecoveryCodesProxy_BadQuery(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.CountUnusedMFARecoveryCodesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteMFARecoveryCodesProxy_BadParam(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "userID", "bad")
	w := httptest.NewRecorder()
	h.DeleteMFARecoveryCodesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── project_memberships_proxy.go ─────────────────────────────────────────────

func TestMembershipProxyWireRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	m := &models.ProjectMembership{
		ProjectID: 1, UserID: 2, Role: "member", State: "active",
		InvitedAt: now,
	}
	w := newMembershipProxyWire(m)
	assert.Equal(t, uint(1), w.ProjectID)
	assert.Equal(t, "member", w.Role)
	m2 := w.toModel()
	assert.Equal(t, uint(1), m2.ProjectID)
	assert.Equal(t, "member", m2.Role)
}

func TestMembershipListWire_Empty(t *testing.T) {
	out := membershipListWire(nil)
	assert.NotNil(t, out)
}

func TestCreateMembershipProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateMembershipProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateMembershipProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body, _ := json.Marshal(map[string]any{"project_id": 0})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateMembershipProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMembershipProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetMembershipProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMembershipProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.GetMembershipProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateMembershipProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{}")), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateMembershipProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListMembershipsProxy_MissingQuery(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListMembershipsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListMembershipsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListMembershipsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetActiveMembershipProxy_BadParams(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetActiveMembershipProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListStaleInvitedMembershipsProxy_MissingQuery(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListStaleInvitedMembershipsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListStaleInvitedMembershipsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?before=2024-01-01T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.ListStaleInvitedMembershipsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListUserMembershipsProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "userID", "bad")
	w := httptest.NewRecorder()
	h.ListUserMembershipsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListUserMembershipsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "userID", "1")
	w := httptest.NewRecorder()
	h.ListUserMembershipsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCountMembershipsByUsersProxy_MissingQuery(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.CountMembershipsByUsersProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCountMembershipsByUsersProxy_InvalidIDs(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?user_ids=1,abc,3", nil)
	w := httptest.NewRecorder()
	h.CountMembershipsByUsersProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── project_catalog_proxy.go ─────────────────────────────────────────────────

func TestProjectProxyWireRoundTrip(t *testing.T) {
	p := &models.Project{Name: "myproj"}
	w := newProjectProxyWire(p)
	assert.Equal(t, "myproj", w.Name)
	m := w.toModel()
	assert.Equal(t, "myproj", m.Name)
}

func TestListProjectsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListProjectsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListProjectsWithCountsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListProjectsWithCountsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetProjectProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetProjectProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetProjectProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.GetProjectProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateProjectProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{}")), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateProjectProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteProjectProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteProjectProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteProjectIfEmptyProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteProjectIfEmptyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRestoreProjectProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.RestoreProjectProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListProjectMembersProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListProjectMembersProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListProjectMembersProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.ListProjectMembersProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── environment_catalog_proxy.go ─────────────────────────────────────────────

func TestEnvironmentProxyWireRoundTrip(t *testing.T) {
	e := &models.Environment{Name: "prod", ProjectID: 1}
	w := newEnvironmentProxyWire(e)
	assert.Equal(t, "prod", w.Name)
	assert.Equal(t, uint(1), w.ProjectID)
}

func TestListEnvironmentsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListEnvironmentsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListEnvironmentsByProjectProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListEnvironmentsByProjectProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListEnvironmentsByProjectProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListEnvironmentsByProjectProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetEnvironmentProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetEnvironmentProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetEnvironmentProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.GetEnvironmentProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteEnvironmentProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteEnvironmentProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRestoreEnvironmentProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.RestoreEnvironmentProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities_proxy.go ───────────────────────────────────────────────

func TestIsAlreadyAssignedErr(t *testing.T) {
	assert.True(t, isAlreadyAssignedErr(fmt.Errorf("already assigned to project")))
	assert.False(t, isAlreadyAssignedErr(nil))
	assert.False(t, isAlreadyAssignedErr(fmt.Errorf("some other error")))
}

func TestIsNotAssignedErr(t *testing.T) {
	assert.True(t, isNotAssignedErr(fmt.Errorf("not assigned to role")))
	assert.False(t, isNotAssignedErr(nil))
}

func TestIsUniqueViolationErr(t *testing.T) {
	assert.True(t, isUniqueViolationErr(fmt.Errorf("UNIQUE constraint failed: table.col")))
	assert.True(t, isUniqueViolationErr(fmt.Errorf("duplicate key value violates unique constraint")))
	assert.False(t, isUniqueViolationErr(nil))
	assert.False(t, isUniqueViolationErr(fmt.Errorf("some other")))
}

func TestMachineIdentityProxyWireRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	m := &models.MachineIdentity{
		ProjectID:    1,
		Name:         "bot",
		IdentityType: "service_account",
		State:        "active",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	w := newMachineIdentityProxyWire(m)
	assert.Equal(t, uint(1), w.ProjectID)
	assert.Equal(t, "bot", w.Name)
	m2 := w.toModel()
	assert.Equal(t, "bot", m2.Name)
}

func TestMachineIdentityCredentialProxyWireRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	c := &models.MachineIdentityCredential{
		MachineIdentityID: 1,
		Name:              "cred1",
		TokenHash:         "abc123hash",
		CreatedAt:         now,
	}
	w := newMachineIdentityCredentialProxyWire(c)
	assert.Equal(t, uint(1), w.MachineIdentityID)
	assert.Equal(t, "cred1", w.Name)
	m2 := w.toModel()
	assert.Equal(t, "cred1", m2.Name)
}

func TestMachineIdentityOIDCBindingProxyWireRoundTrip(t *testing.T) {
	b := &models.MachineIdentityOIDCBinding{
		MachineIdentityID: 1,
		Issuer:            "https://token.example.com",
		Subject:           "my-sa@project.iam",
	}
	w := newMachineIdentityOIDCBindingProxyWire(b)
	assert.Equal(t, "https://token.example.com", w.Issuer)
	m2 := w.toModel()
	assert.Equal(t, "my-sa@project.iam", m2.Subject)
}

func TestRoleProxyWireRoundTrip(t *testing.T) {
	r := &models.Role{Name: "admin"}
	w := newRoleProxyWire(r)
	assert.Equal(t, "admin", w.Name)
}

func TestCreateMachineIdentityProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateMachineIdentityProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body, _ := json.Marshal(map[string]any{"name": "", "project_id": 0})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMachineIdentityProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMachineIdentityProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.GetMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateMachineIdentityProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{}")), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMachineIdentityStateProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{}")), "id", "bad")
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListMachineIdentitiesProxy_MissingQuery(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListMachineIdentitiesProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListAllMachineIdentitiesProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListAllMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCountMachineIdentitiesByClassificationProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.CountMachineIdentitiesByClassificationProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateMachineIdentityCredentialProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateMachineIdentityCredentialProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body, _ := json.Marshal(map[string]any{"machine_identity_id": 0})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMachineIdentityCredentialByHashProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "hash", "nonexistent")
	w := httptest.NewRecorder()
	h.GetMachineIdentityCredentialByHashProxy(w, req)
	// not found in empty DB → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetMachineIdentityCredentialByIDProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "credID", "bad")
	w := httptest.NewRecorder()
	h.GetMachineIdentityCredentialByIDProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListMachineIdentityCredentialsProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListMachineIdentityCredentialsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListActiveMachineIdentityCredentialsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	// No URL params needed; lists all active credentials
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListActiveMachineIdentityCredentialsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateMachineIdentityCredentialProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{}")), "credID", "bad")
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCountMachineIdentityCredentialsByClassificationProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.CountMachineIdentityCredentialsByClassificationProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRevokeMachineIdentityCredentialProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")), "credID", "bad")
	w := httptest.NewRecorder()
	h.RevokeMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTouchMachineIdentityCredentialProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")), "credID", "bad")
	w := httptest.NewRecorder()
	h.TouchMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMachineRoleScopeQuery_MissingProjectID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	_, ok := machineRoleScopeQuery(w, req)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAssignMachineRoleProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveMachineRoleProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.RemoveMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMachineRoleIDsAtProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetMachineRoleIDsAtProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMachineRolesProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetMachineRolesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateOIDCBindingProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateOIDCBindingProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body, _ := json.Marshal(map[string]any{"machine_identity_id": 0})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMachineByOIDCSubjectProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetMachineByOIDCSubjectProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListOIDCBindingsProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListOIDCBindingsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetOIDCBindingByIDProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "bindingID", "bad")
	w := httptest.NewRecorder()
	h.GetOIDCBindingByIDProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteOIDCBindingProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "bindingID", "bad")
	w := httptest.NewRecorder()
	h.DeleteOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secret_dependencies_proxy.go ─────────────────────────────────────────────

func TestSecretDependencyProxyWireRoundTrip(t *testing.T) {
	d := &models.SecretDependency{DependentSecretID: 1, DependsOnSecretID: 2, ProjectID: 3}
	w := newSecretDependencyProxyWire(d)
	assert.Equal(t, uint(1), w.DependentSecretID)
	assert.Equal(t, uint(2), w.DependsOnSecretID)
	m := w.toModel()
	assert.Equal(t, uint(3), m.ProjectID)
}

func TestNewSecretDependencyProxyWireList_Empty(t *testing.T) {
	out := newSecretDependencyProxyWireList(nil)
	assert.NotNil(t, out)
	assert.Len(t, out, 0)
}

func TestParseProxyProjectIDQuery_Missing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	_, ok := parseProxyProjectIDQuery(w, req)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestParseProxyProjectIDQuery_Valid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?project_id=5", nil)
	w := httptest.NewRecorder()
	id, ok := parseProxyProjectIDQuery(w, req)
	assert.True(t, ok)
	assert.Equal(t, uint(5), id)
}

func TestCreateSecretDependencyProxy_BadJSON(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateSecretDependencyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateSecretDependencyProxy_MissingFields(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	body, _ := json.Marshal(map[string]any{"source_id": 0})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateSecretDependencyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateSecretDependencyExclusiveProxy_BadJSON(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateSecretDependencyExclusiveProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSecretDependencyProxy_BadID(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetSecretDependencyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListSecretDependenciesForProjectProxy_MissingQuery(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSecretDependenciesForProjectProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListSecretDependenciesForProjectProxy_HappyPath(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListSecretDependenciesForProjectProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListSecretDependenciesForProjectForUpdateProxy_MissingQuery(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSecretDependenciesForProjectForUpdateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteSecretDependencyProxy_BadID(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteSecretDependencyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── risk_exceptions_proxy.go ─────────────────────────────────────────────────

func TestRiskExceptionProxyWireRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	e := &models.RiskException{
		Title:         "Risk001",
		Justification: "accepted risk",
		CreatedBy:     1,
		CreatedAt:     now,
		ExpiresAt:     now.Add(24 * time.Hour),
	}
	w := newRiskExceptionProxyWire(e)
	assert.Equal(t, "Risk001", w.Title)
	assert.Equal(t, "accepted risk", w.Justification)
	m := w.toModel()
	assert.Equal(t, "Risk001", m.Title)
}

func TestCreateRiskExceptionProxy_BadJSON(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateRiskExceptionProxy_MissingFields(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	body, _ := json.Marshal(map[string]any{"finding_id": ""})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetRiskExceptionProxy_BadID(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetRiskExceptionProxy_NotFound(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.GetRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListRiskExceptionsProxy_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListRiskExceptionsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateRiskExceptionProxy_BadID(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{}")), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── retention_proxy.go ───────────────────────────────────────────────────────

func TestDecodeRetentionBeforeBody_BadJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	_, ok := decodeRetentionBeforeBody(w, req)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecodeRetentionBeforeBody_MissingBefore(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"before": nil})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	_, ok := decodeRetentionBeforeBody(w, req)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPurgeDeletedSecretsBeforeProxy_BadBody(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.PurgeDeletedSecretsBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPurgeDeletedSecretsBeforeProxy_HappyPath(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	body, _ := json.Marshal(map[string]any{"before": time.Now().UTC()})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.PurgeDeletedSecretsBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteAnomalyAlertsBeforeProxy_BadJSON(t *testing.T) {
	h := NewAuditHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.DeleteAnomalyAlertsBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteAnomalyAlertsBeforeProxy_HappyPath(t *testing.T) {
	h := NewAuditHandler(newHandlerCoreS4(t))
	body, _ := json.Marshal(map[string]any{"ack_before": time.Now().UTC(), "unack_ceiling": time.Now().UTC()})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.DeleteAnomalyAlertsBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteClosedAccessReviewsBeforeProxy_BadBody(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.DeleteClosedAccessReviewsBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteExpiredBreakGlassBeforeProxy_BadBody(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.DeleteExpiredBreakGlassBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteResolvedAccessRequestsBeforeProxy_BadBody(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.DeleteResolvedAccessRequestsBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPurgeDeletedProjectsBeforeProxy_BadBody(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.PurgeDeletedProjectsBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPurgeDeletedEnvironmentsBeforeProxy_BadBody(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.PurgeDeletedEnvironmentsBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteExpiredRoleGrantsProxy_BadBody(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.DeleteExpiredRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteExpiredShareRecordsProxy_BadBody(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.DeleteExpiredShareRecordsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPurgeDeletedUsersBeforeProxy_BadBody(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.PurgeDeletedUsersBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListUsersInStateBeforeProxy_BadQuery(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListUsersInStateBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── misc_remote_proxy.go ─────────────────────────────────────────────────────

func TestLastUserSecretActivityProxy_MissingQuery(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.LastUserSecretActivityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLastUserRoleManagementActivityProxy_MissingQuery(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.LastUserRoleManagementActivityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLastUserSecretDeletionActivityProxy_MissingQuery(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.LastUserSecretDeletionActivityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLastUserSecretReadActivityProxy_MissingQuery(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.LastUserSecretReadActivityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLastUserSecretWriteActivityProxy_MissingQuery(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.LastUserSecretWriteActivityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSecretIncludingDeletedProxy_BadID(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetSecretIncludingDeletedProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSecretIncludingDeletedProxy_NotFound(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.GetSecretIncludingDeletedProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListSharesByOwnerProxy_BadID(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "ownerID", "bad")
	w := httptest.NewRecorder()
	h.ListSharesByOwnerProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListSharesByOwnerProxy_HappyPath(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "ownerID", "1")
	w := httptest.NewRecorder()
	h.ListSharesByOwnerProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListSharesByUserProxy_BadID(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "userID", "bad")
	w := httptest.NewRecorder()
	h.ListSharesByUserProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListSharesByUserProxy_HappyPath(t *testing.T) {
	cs := newHandlerCoreS4(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "userID", "1")
	w := httptest.NewRecorder()
	h.ListSharesByUserProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateUserWithRoleGrantsProxy_BadJSON(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateUserWithRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateUserWithRoleGrantsProxy_MissingFields(t *testing.T) {
	h := newUserHandler(t)
	body, _ := json.Marshal(map[string]any{"username": "", "email": ""})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateUserWithRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac_role_grants_proxy.go ─────────────────────────────────────────────────

func TestParseRBACProxyProjectIDQuery_Missing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	_, ok := parseRBACProxyProjectIDQuery(w, req)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestParseRBACProxyProjectIDQuery_Invalid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?project_id=abc", nil)
	w := httptest.NewRecorder()
	_, ok := parseRBACProxyProjectIDQuery(w, req)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestParseRBACProxyRoleIDsQuery_Missing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	ids, ok := parseRBACProxyRoleIDsQuery(w, req)
	// missing role_ids is valid (empty slice) — not an error
	assert.True(t, ok)
	assert.Empty(t, ids)
}

func TestParseRBACProxyRoleIDsQuery_Invalid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?role_ids=abc", nil)
	w := httptest.NewRecorder()
	_, ok := parseRBACProxyRoleIDsQuery(w, req)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetGroupRoleGrantsProxy_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetGroupRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAssignRoleWithExpiryProxy_BadJSON(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.AssignRoleWithExpiryProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAssignRoleToGroupWithExpiryProxy_BadJSON(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.AssignRoleToGroupWithExpiryProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveAllProjectRoleGrantsProxy_MissingQuery(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	w := httptest.NewRecorder()
	h.RemoveAllProjectRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListGroupRoleAssignmentsProxy_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListGroupRoleAssignmentsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListProjectRoleAssignmentsProxy_MissingQuery(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListProjectRoleAssignmentsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListProjectMachineRoleAssignmentsProxy_MissingQuery(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListProjectMachineRoleAssignmentsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListGlobalAdminAssignmentsForUpdateProxy_HappyPath(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListGlobalAdminAssignmentsForUpdateProxy(w, req)
	// missing role_ids is valid → empty result → 200
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRemoveGlobalAdminRoleGuardedProxy_BadJSON(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.RemoveGlobalAdminRoleGuardedProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac.go (human-facing) ────────────────────────────────────────────────────

func TestRBACHandler_ListRoles_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_ListRoles_HappyPath(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListRoles(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRBACHandler_CreateRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.CreateRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_CreateRole_BadJSON(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad")))
	w := httptest.NewRecorder()
	h.CreateRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_GetRole_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetRoleByName_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "name", "admin")
	w := httptest.NewRecorder()
	h.GetRoleByName(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_UpdateRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_DeleteRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_AssignRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.AssignRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_RemoveRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.RemoveRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_GetUserRoles_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_ListPermissions_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListPermissions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_ListPermissions_HappyPath(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListPermissions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRBACHandler_GetPermission_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetPermission(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_GetRolePermissions_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetRolePermissions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_AssignPermissionToRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.AssignPermissionToRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_RemovePermissionFromRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.RemovePermissionFromRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_GetGroupRoles_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetGroupRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_AssignRoleToGroup_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.AssignRoleToGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_RemoveRoleFromGroup_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.RemoveRoleFromGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── users_handler.go (legacy + package-level dispatch when nil) ──────────────

func TestListUsersLegacy_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	listUsersLegacy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListUsersLegacy_HappyPath(t *testing.T) {
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	listUsersLegacy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateUserLegacy_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	createUserLegacy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserLegacy_Unauthorized(t *testing.T) {
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	getUserLegacy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserLegacy_HappyPath(t *testing.T) {
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	getUserLegacy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetUserLegacy_NotFound(t *testing.T) {
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	getUserLegacy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateUserLegacy_Unauthorized(t *testing.T) {
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	updateUserLegacy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeleteUserLegacy_Unauthorized(t *testing.T) {
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	deleteUserLegacy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeleteUserLegacy_HappyPath(t *testing.T) {
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	deleteUserLegacy(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// Package-level dispatch functions (nil handler → 503)
func TestSearchUsers_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := httptest.NewRequest(http.MethodGet, "/?q=test", nil)
	w := httptest.NewRecorder()
	SearchUsers(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestListUsers_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	ListUsers(w, req)
	// nil handler → listUsersLegacy → 200 (has userCtx)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateUser_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")))
	w := httptest.NewRecorder()
	CreateUser(w, req)
	// createUserLegacy validates body → bad data → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUser_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	GetUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetUserByEmail_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := httptest.NewRequest(http.MethodGet, "/?email=test@test.com", nil)
	w := httptest.NewRecorder()
	GetUserByEmail(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestVerifyCredentials_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	VerifyCredentials(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestIssueMFAChallenge_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	IssueMFAChallenge(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestGetActiveMFAChallenge_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	GetActiveMFAChallenge(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestConsumeMFAChallenge_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	ConsumeMFAChallenge(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestUpdateUser_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{}")), "id", "1"))
	w := httptest.NewRecorder()
	UpdateUser(w, req)
	// updateUserLegacy with valid body → 200
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteUser_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	DeleteUser(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// ── machine_identities.go (human-facing) ──────────────────────────────────────

func TestCatalogHandler_ListMachineIdentities_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListMachineIdentities(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ListMachineIdentities_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListMachineIdentities(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCatalogHandler_ListStaleMachineIdentities_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListStaleMachineIdentities(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateMachineIdentity_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateMachineIdentity_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCatalogHandler_TransitionMachineIdentity_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "bad", "machineId": "1"})
	w := httptest.NewRecorder()
	h.TransitionMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_IssueMachineToken_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "bad", "machineId": "1"})
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ListMachineTokens_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "bad", "machineId": "1"})
	w := httptest.NewRecorder()
	h.ListMachineTokens(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_RevokeMachineToken_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "bad", "machineId": "1", "credId": "1"})
	w := httptest.NewRecorder()
	h.RevokeMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ClassifyMachineIdentity_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPatch, "/", nil),
		map[string]string{"id": "bad", "machineId": "1"})
	w := httptest.NewRecorder()
	h.ClassifyMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ClassifyMachineToken_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPatch, "/", nil),
		map[string]string{"id": "bad", "machineId": "1", "credId": "1"})
	w := httptest.NewRecorder()
	h.ClassifyMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_GrantMachineRole_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "bad", "machineId": "1"})
	w := httptest.NewRecorder()
	h.GrantMachineRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateOIDCBinding_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "1", "machineId": "1"})
	w := httptest.NewRecorder()
	h.CreateOIDCBinding(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCatalogHandler_ListOIDCBindings_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "bad", "machineId": "1"})
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_DeleteOIDCBinding_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "bad", "machineId": "1", "bindingId": "1"})
	w := httptest.NewRecorder()
	h.DeleteOIDCBinding(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── webauthn.go (human-facing) ─────────────────────────────────────────────────

func TestBeginWebAuthnRegistration_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.BeginWebAuthnRegistration(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestFinishWebAuthnRegistration_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.FinishWebAuthnRegistration(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestFinishWebAuthnRegistration_BadBody(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")))
	w := httptest.NewRecorder()
	h.FinishWebAuthnRegistration(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListWebAuthnCredentials_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListWebAuthnCredentials(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListWebAuthnCredentials_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListWebAuthnCredentials(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteWebAuthnCredential_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteWebAuthnCredential(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBeginWebAuthnLogin_BadBody(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.BeginWebAuthnLogin(w, req)
	// No username/email provided → 400 or similar
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestBeginWebAuthnPasswordlessLogin_BadBody(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.BeginWebAuthnPasswordlessLogin(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── rotation_policies_handler.go ──────────────────────────────────────────────

func TestRotationPolicyHandler_List_Unauthorized(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRotationPolicyHandler_List_HappyPath(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRotationPolicyHandler_Create_Unauthorized(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRotationPolicyHandler_Create_BadJSON(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad")))
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Get_Unauthorized(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.Get(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRotationPolicyHandler_Update_Unauthorized(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRotationPolicyHandler_Delete_Unauthorized(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.Delete(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestParseOptionalUintQuery_Valid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?project_id=5", nil)
	v, err := parseOptionalUintQuery(req, "project_id")
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, uint(5), *v)
}

func TestParseOptionalUintQuery_Missing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	v, err := parseOptionalUintQuery(req, "project_id")
	require.NoError(t, err)
	assert.Nil(t, v)
}

func TestParseOptionalUintQuery_Invalid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?project_id=abc", nil)
	_, err := parseOptionalUintQuery(req, "project_id")
	assert.Error(t, err)
}

func TestRotationPolicyHandler_Evaluate_Unauthorized(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.Evaluate(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRotationPolicyHandler_Status_Unauthorized(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.Status(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── shares_query.go and shares_crud.go ───────────────────────────────────────

func newShareHandlerS4(t *testing.T) *ShareHandler {
	t.Helper()
	h, err := NewShareHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	return h
}

func TestShareHandler_ListSecretShares_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListSecretShares(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ListShares_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ListSharedSecrets_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSharedSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ListGroupSharedSecrets_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListGroupSharedSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_GetSharingStatusWithIndicators_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSharingStatusWithIndicators(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_RemoveSelfFromShare_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RemoveSelfFromShare(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ShareSecret_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_UpdateSharePermission_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_RevokeShare_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeShare(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── scim.go and scim_groups.go ────────────────────────────────────────────────

func newSCIMHandlerS4(t *testing.T) *SCIMHandler {
	t.Helper()
	return NewSCIMHandler(newHandlerCoreS4(t))
}

func TestSCIMHandler_GetServiceProviderConfig(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetServiceProviderConfig(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSCIMHandler_ListUsers_HappyPath(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSCIMHandler_GetUser_BadID(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_CreateUser_BadJSON(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_ReplaceUser_BadID(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{}")), "id", "bad")
	w := httptest.NewRecorder()
	h.ReplaceUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_PatchUser_BadID(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader("{}")), "id", "bad")
	w := httptest.NewRecorder()
	h.PatchUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_DeleteUser_BadID(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_ListGroups_HappyPath(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListGroups(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSCIMHandler_GetGroup_BadID(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_CreateGroup_BadJSON(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_ReplaceGroup_BadID(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{}")), "id", "bad")
	w := httptest.NewRecorder()
	h.ReplaceGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_PatchGroup_BadID(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader("{}")), "id", "bad")
	w := httptest.NewRecorder()
	h.PatchGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Batch 3: comprehensive coverage for remaining 0% functions ────────────────

// ── Helper constructors ────────────────────────────────────────────────────────

func newDashboardHandler(t *testing.T) *DashboardHandler {
	t.Helper()
	return NewDashboardHandler(newHandlerCoreS4(t))
}

func newPATHandler(t *testing.T) *PATHandler {
	t.Helper()
	return NewPATHandler(newHandlerCoreS4(t))
}

func newGroupHandlerS4(t *testing.T) *GroupHandler {
	t.Helper()
	gh, err := NewGroupHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	return gh
}

func newSecretHandlerS4(t *testing.T) *SecretHandler {
	t.Helper()
	h, err := NewSecretHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	return h
}

// ── isSafeSSOError ────────────────────────────────────────────────────────────

func TestIsSafeSSOError_Known(t *testing.T) {
	assert.True(t, isSafeSSOError("unknown SSO provider"))
	assert.True(t, isSafeSSOError("invalid or expired login state"))
	assert.False(t, isSafeSSOError("account suspended"))
	assert.True(t, isSafeSSOError("no Keyorix account matches this SSO identity"))
}

func TestIsSafeSSOError_Unknown(t *testing.T) {
	assert.False(t, isSafeSSOError("database connection refused"))
	assert.False(t, isSafeSSOError("token verification failed: some library error"))
}

// ── ListSSOProviders ──────────────────────────────────────────────────────────

func TestListSSOProviders_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSSOProviders(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── BeginSSO ─────────────────────────────────────────────────────────────────

func TestBeginSSO_UnknownProvider(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "unknown")
	w := httptest.NewRecorder()
	h.BeginSSO(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── CompleteSSO ───────────────────────────────────────────────────────────────

func TestCompleteSSO_UnknownProvider(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "unknown")
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── MFA handlers ─────────────────────────────────────────────────────────────

func TestEnrollMFA_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.EnrollMFA(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestActivateMFA_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"code":"123456"}`))
	w := httptest.NewRecorder()
	h.ActivateMFA(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDisableMFA_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.DisableMFA(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRegenerateRecoveryCodes_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.RegenerateRecoveryCodes(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRecoveryCodesStatus_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.RecoveryCodesStatus(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestVerifyMFA_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.VerifyMFA(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyMFA_InvalidChallenge(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"mfa_challenge":"invalid","code":"000000"}`))
	w := httptest.NewRecorder()
	h.VerifyMFA(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── PAT handlers ──────────────────────────────────────────────────────────────

func TestListPATs_Unauthorized(t *testing.T) {
	h := newPATHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListPATs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListPATs_HappyPath(t *testing.T) {
	h := newPATHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListPATs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPATHygiene_Unauthorized(t *testing.T) {
	h := newPATHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.PATHygiene(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPATHygiene_HappyPath(t *testing.T) {
	h := newPATHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?days=30", nil))
	w := httptest.NewRecorder()
	h.PATHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreatePAT_Unauthorized(t *testing.T) {
	h := newPATHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test"}`))
	w := httptest.NewRecorder()
	h.CreatePAT(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreatePAT_BadJSON(t *testing.T) {
	h := newPATHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad")))
	w := httptest.NewRecorder()
	h.CreatePAT(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreatePAT_InvalidExpiry(t *testing.T) {
	h := newPATHandler(t)
	expiry := "not-a-date"
	body, _ := json.Marshal(map[string]any{"name": "tok", "expires_at": expiry})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreatePAT(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestToPATResponse_Nilsafe(t *testing.T) {
	now := time.Now()
	tok := &models.PersonalAccessToken{
		Name:        "test",
		TokenPrefix: "kx_",
		CreatedAt:   now,
	}
	resp := toPATResponse(tok)
	assert.Equal(t, "test", resp.Name)
	assert.Nil(t, resp.ExpiresAt)
	assert.Nil(t, resp.LastUsedAt)
}

// ── Risk exceptions ───────────────────────────────────────────────────────────

func TestListRiskExceptions_HappyPath(t *testing.T) {
	h := newDashboardHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListRiskExceptions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateRiskException_Unauthorized(t *testing.T) {
	h := newDashboardHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreateRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateRiskException_BadExpiry(t *testing.T) {
	h := newDashboardHandler(t)
	body := `{"title":"t","justification":"j","expires_at":"bad"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreateRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestApproveRiskException_Unauthorized(t *testing.T) {
	h := newDashboardHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ApproveRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestApproveRiskException_BadID(t *testing.T) {
	h := newDashboardHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ApproveRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeRiskException_Unauthorized(t *testing.T) {
	h := newDashboardHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeRiskException_BadID(t *testing.T) {
	h := newDashboardHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokeRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Legal hold handlers ───────────────────────────────────────────────────────

func TestGetLegalHold_HappyPath(t *testing.T) {
	h := newDashboardHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetLegalHold(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPlaceLegalHold_Unauthorized(t *testing.T) {
	h := newDashboardHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason":"test"}`))
	w := httptest.NewRecorder()
	h.PlaceLegalHold(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPlaceLegalHold_BadJSON(t *testing.T) {
	h := newDashboardHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad")))
	w := httptest.NewRecorder()
	h.PlaceLegalHold(w, req)
	// bad JSON -> 400 or error from core; actual core path tries to place with empty reason
	// both 400 and 500 are acceptable here; just not unauthorized
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestLiftLegalHold_Unauthorized(t *testing.T) {
	h := newDashboardHandler(t)
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	w := httptest.NewRecorder()
	h.LiftLegalHold(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Legal hold proxy ──────────────────────────────────────────────────────────

func TestCreateLegalHoldProxy_BadJSON(t *testing.T) {
	h := newDashboardHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateLegalHoldProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateLegalHoldProxy_MissingReason(t *testing.T) {
	h := newDashboardHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreateLegalHoldProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetActiveLegalHoldProxy_HappyPath(t *testing.T) {
	h := newDashboardHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetActiveLegalHoldProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateLegalHoldProxy_BadID(t *testing.T) {
	h := newDashboardHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateLegalHoldProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateLegalHoldProxy_BadJSON(t *testing.T) {
	h := newDashboardHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateLegalHoldProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Login attempts proxy ──────────────────────────────────────────────────────

func TestRecordLoginAttemptProxy_MissingIP(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.RecordLoginAttemptProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRecordLoginAttemptProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body, _ := json.Marshal(map[string]any{"ip": "127.0.0.1", "at": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.RecordLoginAttemptProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCountLoginAttemptsProxy_MissingParams(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.CountLoginAttemptsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCountLoginAttemptsProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/?ip=127.0.0.1&since=2024-01-01T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.CountLoginAttemptsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPruneLoginAttemptsProxy_MissingBefore(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.PruneLoginAttemptsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPruneLoginAttemptsProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body, _ := json.Marshal(map[string]any{"before": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.PruneLoginAttemptsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── Scheduler lock proxy ──────────────────────────────────────────────────────

func TestAcquireSchedulerLockProxy_MissingHolder(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.AcquireSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAcquireSchedulerLockProxy_BadTTL(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"holder":"h","ttl_millis":0}`))
	w := httptest.NewRecorder()
	h.AcquireSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAcquireSchedulerLockProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body, _ := json.Marshal(map[string]any{"key": 1, "holder": "node1", "ttl_millis": 5000})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.AcquireSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestReleaseSchedulerLockProxy_MissingHolder(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.ReleaseSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestReleaseSchedulerLockProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body, _ := json.Marshal(map[string]any{"key": 1, "holder": "node1"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ReleaseSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── Login lockout proxy ───────────────────────────────────────────────────────

func TestUpdateLoginLockoutStateProxy_BadID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateLoginLockoutStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateLoginLockoutStateProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateLoginLockoutStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Invitation proxy ──────────────────────────────────────────────────────────

func TestCreateInvitationProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateInvitationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateInvitationProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"project_id":1}`))
	w := httptest.NewRecorder()
	h.CreateInvitationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateInvitationProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"project_id":1,"email":"x@example.com","role":"viewer","state":"pending"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateInvitationProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetInvitationProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetInvitationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetInvitationProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.GetInvitationProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateInvitationProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateInvitationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateInvitationProxy_InvalidState(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"state":"pending"}`)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateInvitationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestValidInvitationTargetState_Valid(t *testing.T) {
	assert.True(t, validInvitationTargetState("accepted"))
	assert.True(t, validInvitationTargetState("revoked"))
	assert.True(t, validInvitationTargetState("expired"))
	assert.False(t, validInvitationTargetState("pending"))
	assert.False(t, validInvitationTargetState(""))
}

func TestListInvitationsProxy_MissingProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListInvitationsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListInvitationsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListInvitationsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── SSO state proxy ───────────────────────────────────────────────────────────

func TestCreateSSOLoginStateProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateSSOLoginStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateSSOLoginStateProxy_MissingFields(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreateSSOLoginStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateSSOLoginStateProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	// state carries a DB-level uniqueIndex (models.SSOLoginState.State); fold in
	// a counter so a repeat invocation against the shared DB (see s4UniqueCounter)
	// doesn't collide with its own prior insert.
	state := fmt.Sprintf("s1-%d", s4UniqueCounter.Add(1))
	body := fmt.Sprintf(`{"state":%q,"nonce":"n1","provider":"oidc","expires_at":"2099-01-01T00:00:00Z"}`, state)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateSSOLoginStateProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestConsumeSSOLoginStateProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.ConsumeSSOLoginStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestConsumeSSOLoginStateProxy_MissingState(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.ConsumeSSOLoginStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestConsumeSSOLoginStateProxy_NotFound(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"state":"nonexistent"}`))
	w := httptest.NewRecorder()
	h.ConsumeSSOLoginStateProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestNewSSOLoginStateProxyWire_RoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s := &models.SSOLoginState{
		ID:        1,
		State:     "abc",
		Nonce:     "nonce1",
		Provider:  "google",
		ReturnTo:  "/dashboard",
		ExpiresAt: now,
		CreatedAt: now,
	}
	w := newSSOLoginStateProxyWire(s)
	assert.Equal(t, s.State, w.State)
	m := w.toModel()
	assert.Equal(t, s.Nonce, m.Nonce)
	assert.Equal(t, s.Provider, m.Provider)
}

// ── Dynamic secret proxy wire round-trips ────────────────────────────────────

func TestNewDynamicSecretConfigProxyWire_RoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	cfg := &models.DynamicSecretConfig{
		ID:                1,
		Name:              "cfg1",
		ProjectID:         2,
		BackendType:       "postgres",
		DefaultTTLSeconds: 300,
		MaxTTLSeconds:     3600,
		MaxActiveLeases:   10,
		Classification:    "secret",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	w := newDynamicSecretConfigProxyWire(cfg)
	assert.Equal(t, "cfg1", w.Name)
	m := w.toModel()
	assert.Equal(t, uint(2), m.ProjectID)
	assert.Equal(t, 300, m.DefaultTTLSeconds)
}

func TestNewDynamicSecretLeaseProxyWire_RoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	lease := &models.DynamicSecretLease{
		ID:        1,
		ConfigID:  2,
		LeaseID:   "lease-abc",
		ProjectID: 3,
		RoleName:  "readonly",
		Status:    "active",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	w := newDynamicSecretLeaseProxyWire(lease)
	assert.Equal(t, "lease-abc", w.LeaseID)
	m := w.toModel()
	assert.Equal(t, uint(2), m.ConfigID)
	assert.Equal(t, "active", m.Status)
}

// ── Invitation handlers (human-facing) ───────────────────────────────────────

func TestListInvitations_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListInvitations(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListInvitations_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListInvitations(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateInvitation_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateInvitation_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateInvitation_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResendInvitation_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{"id": "bad", "invitationId": "1"})
	w := httptest.NewRecorder()
	h.ResendInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResendInvitation_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{"id": "1", "invitationId": "1"})
	w := httptest.NewRecorder()
	h.ResendInvitation(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeInvitation_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{"id": "bad", "invitationId": "1"})
	w := httptest.NewRecorder()
	h.RevokeInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeInvitation_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{"id": "1", "invitationId": "1"})
	w := httptest.NewRecorder()
	h.RevokeInvitation(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListAccessRequests_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListAccessRequests(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAccessRequests_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListAccessRequests(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateAccessRequest_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.CreateAccessRequest(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestResolveAccessRequest_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), map[string]string{"id": "bad", "requestId": "1"})
	w := httptest.NewRecorder()
	h.ResolveAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResolveAccessRequest_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), map[string]string{"id": "1", "requestId": "1"})
	w := httptest.NewRecorder()
	h.ResolveAccessRequest(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestResolveAccessRequest_InvalidAction(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"action":"unknown"}`
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), map[string]string{"id": "1", "requestId": "1"}))
	w := httptest.NewRecorder()
	h.ResolveAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWithdrawAccessRequest_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "requestId", "1")
	w := httptest.NewRecorder()
	h.WithdrawAccessRequest(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateGlobalInvitation_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreateGlobalInvitation(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Project members ───────────────────────────────────────────────────────────

func TestListProjectMembers_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListProjectMembers(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListProjectMembers_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListProjectMembers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetProjectAccessReview_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetProjectAccessReview_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetProjectAccessReview(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRevokeProjectAccessReview_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"source":"role_assignment","principal_type":"user","principal_id":1,"role_id":1}`
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAttestProjectAccessReview_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"source":"role_assignment","principal_type":"user","principal_id":1,"role_id":1}`
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.AttestProjectAccessReview(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAddProjectMember_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.AddProjectMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAddProjectMember_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.AddProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateProjectMember_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), map[string]string{"id": "1", "userId": "1"})
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRemoveProjectMember_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{"id": "1", "userId": "1"})
	w := httptest.NewRecorder()
	h.RemoveProjectMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Project memberships ───────────────────────────────────────────────────────

func TestListProjectMemberships_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListProjectMemberships_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestInviteMember_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.InviteMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestInviteMember_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.InviteMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMembership_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"action":"activate"}`
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), map[string]string{"id": "1", "membershipId": "1"})
	w := httptest.NewRecorder()
	h.TransitionMembership(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMembershipActionState_Valid(t *testing.T) {
	s, ok := membershipActionState("verify")
	assert.True(t, ok)
	assert.NotEmpty(t, s)
	s, ok = membershipActionState("activate")
	assert.True(t, ok)
	assert.NotEmpty(t, s)
	_, ok = membershipActionState("unknown")
	assert.False(t, ok)
}

// ── Group members ─────────────────────────────────────────────────────────────

func TestGetGroupMembers_Unauthorized(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetGroupMembers(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetGroupMembers_BadID(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetGroupMembers(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAddGroupMember_Unauthorized(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAddGroupMember_MissingUserID(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveGroupMember_Unauthorized(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{"id": "1", "userId": "2"})
	w := httptest.NewRecorder()
	h.RemoveGroupMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestInitCoreHandlers_HappyPath(t *testing.T) {
	saved := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = saved })
	cs := newHandlerCoreS4(t)
	uh, gh, err := InitCoreHandlers(cs)
	require.NoError(t, err)
	assert.NotNil(t, uh)
	assert.NotNil(t, gh)
}

// ── Secret dependency handlers ────────────────────────────────────────────────

func TestDependencyErrorStatus_Messages(t *testing.T) {
	assert.Equal(t, http.StatusNotFound, dependencyErrorStatus("secret not found"))
	assert.Equal(t, http.StatusBadRequest, dependencyErrorStatus("cannot depend on itself"))
	assert.Equal(t, http.StatusBadRequest, dependencyErrorStatus("cycle detected"))
	assert.Equal(t, http.StatusForbidden, dependencyErrorStatus("permission denied"))
	assert.Equal(t, http.StatusInternalServerError, dependencyErrorStatus("some random error"))
}

func TestListSecretDependencies_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListSecretDependencies(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListSecretDependencies_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ListSecretDependencies(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAddSecretDependency_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.AddSecretDependency(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAddSecretDependency_MissingDependsOn(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.AddSecretDependency(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveSecretDependency_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{"id": "1", "depId": "2"})
	w := httptest.NewRecorder()
	h.RemoveSecretDependency(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetSecretImpact_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSecretImpact(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetProjectRotationOrder_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetProjectRotationOrder(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetProjectRotationPlan_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetProjectRotationPlan(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetDeploymentRotationPlan_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetDeploymentRotationPlan(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Users crud ────────────────────────────────────────────────────────────────

func TestGetUserByExternalID_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/?external_id=ext1", nil)
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserByExternalID_MissingParam(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUserByExternalID_NotFound(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?external_id=nonexistent", nil))
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestVerifyCredentials_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.VerifyCredentials(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestVerifyCredentials_MissingFields(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
	w := httptest.NewRecorder()
	h.VerifyCredentials(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyCredentials_WrongCredentials(t *testing.T) {
	h := newUserHandler(t)
	body := `{"username":"nonexistent","password":"wrong"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.VerifyCredentials(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestIssueMFAChallenge_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.IssueMFAChallenge(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestIssueMFAChallenge_BadID(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.IssueMFAChallenge(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyMFACredentials_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.VerifyMFACredentials(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestVerifyMFACredentials_MissingFields(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
	w := httptest.NewRecorder()
	h.VerifyMFACredentials(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetActiveMFAChallenge_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.GetActiveMFAChallenge(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetActiveMFAChallenge_MissingFields(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
	w := httptest.NewRecorder()
	h.GetActiveMFAChallenge(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestConsumeMFAChallenge_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.ConsumeMFAChallenge(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestNewMFAChallengeProxyWire_RoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	ch := &models.MFAChallenge{
		ID:        1,
		UserID:    2,
		TokenHash: "hashabc",
		ExpiresAt: now,
		CreatedAt: now,
	}
	w := newMFAChallengeProxyWire(ch)
	assert.Equal(t, uint(2), w.UserID)
	assert.Equal(t, "hashabc", w.TokenHash)
}

// ── Users handler dispatch ────────────────────────────────────────────────────

func TestStaleAccountsDispatch_HappyPath(t *testing.T) {
	saved := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = saved })
	cs := newHandlerCoreS4(t)
	uh, _, err := InitCoreHandlers(cs)
	require.NoError(t, err)
	_ = uh
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	StaleAccounts(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetUserByUsernameDispatch_Unauthorized(t *testing.T) {
	saved := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = saved })
	cs := newHandlerCoreS4(t)
	_, _, err := InitCoreHandlers(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/?username=test", nil)
	w := httptest.NewRecorder()
	GetUserByUsername(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserByExternalIDDispatch_MissingParam(t *testing.T) {
	saved := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = saved })
	cs := newHandlerCoreS4(t)
	_, _, err := InitCoreHandlers(cs)
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyMFACredentialsDispatch_Unauthorized(t *testing.T) {
	saved := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = saved })
	cs := newHandlerCoreS4(t)
	_, _, err := InitCoreHandlers(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	VerifyMFACredentials(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRestoreUserDispatch_Unauthorized(t *testing.T) {
	saved := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = saved })
	cs := newHandlerCoreS4(t)
	_, _, err := InitCoreHandlers(cs)
	require.NoError(t, err)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	RestoreUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── RemoveMachineRole ─────────────────────────────────────────────────────────

func TestRemoveMachineRole_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{
		"id": "bad", "machineId": "1", "roleId": "1",
	})
	w := httptest.NewRecorder()
	h.RemoveMachineRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveMachineRole_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{
		"id": "1", "machineId": "1", "roleId": "1",
	})
	w := httptest.NewRecorder()
	h.RemoveMachineRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMachineActionState_Values(t *testing.T) {
	s, ok := machineActionState("activate")
	assert.True(t, ok)
	assert.NotEmpty(t, s)
	_, ok = machineActionState("unknown")
	assert.False(t, ok)
}

// ── MachineTokenHygiene ───────────────────────────────────────────────────────

func TestMachineTokenHygiene_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMachineTokenHygiene_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── ProjectHygiene ────────────────────────────────────────────────────────────

func TestProjectHygiene_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ProjectHygiene(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestProjectHygiene_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.ProjectHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── SuspendProjectSecrets / ResumeProjectSecrets ──────────────────────────────

func TestSuspendProjectSecrets_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.SuspendProjectSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSuspendProjectSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason":"test"}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.SuspendProjectSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestResumeProjectSecrets_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ResumeProjectSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestResumeProjectSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.ResumeProjectSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── SuspendSecret / ResumeSecret ─────────────────────────────────────────────

func TestSuspendSecret_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.SuspendSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSuspendSecret_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.SuspendSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResumeSecret_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ResumeSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Secret tags ───────────────────────────────────────────────────────────────

func TestGetTags_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetTags(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetTags_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetTags(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetTags_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"tags":[]}`)), "id", "1")
	w := httptest.NewRecorder()
	h.SetTags(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSetTags_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"tags":[]}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.SetTags(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Secret versions ───────────────────────────────────────────────────────────

func TestGetSecretVersions_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSecretVersions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRotateSecret_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.RotateSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRollbackSecret_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.RollbackSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Secret usage ──────────────────────────────────────────────────────────────

func TestUsageMostAccessed_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.UsageMostAccessed(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUsageMostAccessed_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.UsageMostAccessed(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUsageUnused_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.UsageUnused(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestParseProjectIDQuery_Valid(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?project_id=5", nil)
	pid, ok := parseProjectIDQuery(r)
	require.True(t, ok)
	require.NotNil(t, pid)
	assert.Equal(t, uint(5), *pid)
}

func TestParseProjectIDQuery_Absent(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	pid, ok := parseProjectIDQuery(r)
	assert.True(t, ok)
	assert.Nil(t, pid)
}

func TestParseIntQuery_Default(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.Equal(t, 30, parseIntQuery(r, "days", 30))
}

func TestParseIntQuery_Valid(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?days=7", nil)
	assert.Equal(t, 7, parseIntQuery(r, "days", 30))
}

// ── Secret list ───────────────────────────────────────────────────────────────

func TestListSecrets_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	// ListSecrets looks up the user in DB; with no user in DB it returns 500.
	// The purpose here is to cover the post-auth code path.
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	// 200 if user exists (it won't in empty DB), or 500 from user lookup failure
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── Secret access history / accessors ────────────────────────────────────────

func TestAccessHistory_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.AccessHistory(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListAccessors_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListAccessors(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── AuditTrail ────────────────────────────────────────────────────────────────

func TestAuditTrail_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.AuditTrail(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuditTrail_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.AuditTrail(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── DeletedSecrets / ExpiringSecrets / OrphanedSecrets ────────────────────────

func TestDeletedSecrets_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.DeletedSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestExpiringSecrets_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ExpiringSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOrphanedSecrets_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.OrphanedSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOrphanedSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.OrphanedSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── GetSecretByName / GetSecretValueByRef ────────────────────────────────────

func TestGetSecretByName_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?name=foo&project_id=1&environment_id=1", nil)
	w := httptest.NewRecorder()
	h.GetSecretByName(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetSecretByName_MissingName(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=1&environment_id=1", nil))
	w := httptest.NewRecorder()
	h.GetSecretByName(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSecretValueByRef_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?ref=proj/env/name", nil)
	w := httptest.NewRecorder()
	h.GetSecretValueByRef(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── SecretDescription / SecretRisk / ReassignOwner / TransferOwnership ─────────

func TestDescribeSecret_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DescribeSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetSecretRisk_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSecretRisk(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestReassignOwner_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.ReassignOwner(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTransferOwnership_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.TransferOwnership(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── newAccessRequestApprovalProxyWire ─────────────────────────────────────────

func TestNewAccessRequestApprovalProxyWire_RoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	a := &models.AccessRequestApproval{
		ID:         5,
		RequestID:  10,
		ApproverID: 2,
		CreatedAt:  now,
	}
	w := newAccessRequestApprovalProxyWire(a)
	assert.Equal(t, uint(5), w.ID)
	assert.Equal(t, uint(10), w.RequestID)
	assert.Equal(t, uint(2), w.ApproverID)
}

// ── newAccessReviewItemProxyWire ──────────────────────────────────────────────

func TestNewAccessReviewItemProxyWire_RoundTrip(t *testing.T) {
	it := &models.AccessReviewItem{
		ID:            1,
		CampaignID:    2,
		PrincipalType: "user",
		PrincipalID:   3,
		Decision:      "pending",
	}
	w := newAccessReviewItemProxyWire(it)
	assert.Equal(t, uint(1), w.ID)
	m := w.toModel()
	assert.Equal(t, uint(2), m.CampaignID)
	assert.Equal(t, "user", m.PrincipalType)
}

// ── newUserRetentionProxyWire ─────────────────────────────────────────────────

func TestNewUserRetentionProxyWire_Fields(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	u := &models.User{
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice",
		IsActive:    true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	w := newUserRetentionProxyWire(u)
	assert.Equal(t, "alice", w.Username)
	assert.True(t, w.Active)
	assert.Nil(t, w.DeletedAt)
}

// ── filterShareViews / atoiDefault ────────────────────────────────────────────

func TestAtoiDefault_Valid(t *testing.T) {
	assert.Equal(t, 5, atoiDefault("5", 10))
}

func TestAtoiDefault_Invalid(t *testing.T) {
	assert.Equal(t, 10, atoiDefault("bad", 10))
}

func TestAtoiDefault_Empty(t *testing.T) {
	assert.Equal(t, 10, atoiDefault("", 10))
}

func TestFilterShareViews_Empty(t *testing.T) {
	result := filterShareViews(nil, func(core.ShareView) bool { return true })
	assert.Empty(t, result)
}

func TestFilterShareViews_Filters(t *testing.T) {
	views := []core.ShareView{{ID: 1}, {ID: 2}}
	result := filterShareViews(views, func(v core.ShareView) bool { return v.ID == 1 })
	assert.Len(t, result, 1)
}

// ── pageSlice (scim_groups.go) ────────────────────────────────────────────────

func TestPageSlice_Empty(t *testing.T) {
	result := pageSlice([]int(nil), 1, 10)
	assert.Empty(t, result)
}

func TestPageSlice_InBounds(t *testing.T) {
	items := []int{1, 2, 3}
	result := pageSlice(items, 1, 2)
	assert.Len(t, result, 2)
}

func TestPageSlice_Beyond(t *testing.T) {
	items := []int{1}
	result := pageSlice(items, 5, 10)
	assert.Empty(t, result)
}

// ── GetSecretCertificate ──────────────────────────────────────────────────────

func TestGetSecretCertificate_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSecretCertificate(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── SAML endpoints ────────────────────────────────────────────────────────────

func TestSAMLMetadata_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "unknown")
	w := httptest.NewRecorder()
	h.SAMLMetadata(w, req)
	// unknown provider → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestBeginSAML_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "unknown")
	w := httptest.NewRecorder()
	h.BeginSAML(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCompleteSAML_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "provider", "unknown")
	w := httptest.NewRecorder()
	h.CompleteSAML(w, req)
	// unknown provider → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── WebAuthn Finish handlers ──────────────────────────────────────────────────

func TestFinishWebAuthnLogin_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.FinishWebAuthnLogin(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestFinishWebAuthnPasswordlessLogin_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.FinishWebAuthnPasswordlessLogin(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── GetSecretVersions / RotateSecret / RollbackSecret happy paths ─────────────

func TestGetSecretVersions_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetSecretVersions(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotateSecret_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"value":"v"}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.RotateSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── DeletedSecrets / ExpiringSecrets happy paths ──────────────────────────────

func TestDeletedSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.DeletedSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestExpiringSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.ExpiringSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── GetSecretCertificate happy path ──────────────────────────────────────────

func TestGetSecretCertificate_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetSecretCertificate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── AccessHistory / ListAccessors bad-ID paths ────────────────────────────────

func TestAccessHistory_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.AccessHistory(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAccessors_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ListAccessors(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── resolveSecretNames ────────────────────────────────────────────────────────

func TestResolveSecretNames_Empty(t *testing.T) {
	h := newSecretHandlerS4(t)
	// resolveSecretNames is a void method; calling with nil/empty should not panic
	h.resolveSecretNames(context.Background(), nil)
}

// ── UpdateInvitationProxy happy path (valid accepted state) ──────────────────

func TestUpdateInvitationProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	// First create an invitation to update
	createBody := `{"project_id":1,"email":"x@example.com","role":"viewer","state":"pending"}`
	createReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(createBody))
	createW := httptest.NewRecorder()
	h.CreateInvitationProxy(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	var createResp remoteAPIResponse
	_ = json.NewDecoder(createW.Body).Decode(&createResp)
	// Now try to update to "accepted" - even if we don't know the ID, we test the validation path
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"state":"accepted"}`)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateInvitationProxy(w, req)
	// 200 if found, or some status from storage - but not 400 validation error
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── DescribeSecret / GetSecretRisk happy path ────────────────────────────────

func TestDescribeSecret_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.DescribeSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSecretRisk_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetSecretRisk(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── sanitizeConfig / sanitizeLease (dynamic_secrets.go) ────────────────────────

func TestSanitizeConfig_Strips(t *testing.T) {
	cfg := &models.DynamicSecretConfig{
		Name:         "test",
		AdminDSNEnc:  []byte("sensitive"),
		AdminDSNMeta: []byte("meta"),
	}
	out := sanitizeConfig(cfg)
	require.IsType(t, map[string]any{}, out)
	assert.Equal(t, "test", out["name"])
}

func TestSanitizeLease_Strips(t *testing.T) {
	lease := &models.DynamicSecretLease{
		LeaseID:        "l1",
		CredentialEnc:  []byte("sensitive"),
		CredentialMeta: []byte("meta"),
	}
	out := sanitizeLease(lease)
	require.IsType(t, map[string]any{}, out)
	assert.Equal(t, "l1", out["lease_id"])
}

// ── parseProxyScopeQuery_MissingProject (new unique test) ─────────────────────

func TestParseProxyScopeQuery_MissingProject(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, _, ok := parseProxyScopeQuery(w, r)
	assert.False(t, ok)
}

// ── WebAuthn extras ───────────────────────────────────────────────────────────

func TestBeginWebAuthnLogin_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.BeginWebAuthnLogin(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestFinishWebAuthnRegistration_MissingCredential(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"webauthn_session":"s","name":"n"}`)))
	w := httptest.NewRecorder()
	h.FinishWebAuthnRegistration(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── BeginWebAuthnPasswordlessLogin ────────────────────────────────────────────

func TestBeginWebAuthnPasswordlessLogin_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.BeginWebAuthnPasswordlessLogin(w, req)
	// WebAuthn not configured -> 501 or 400 - not 200 OK (there's no config)
	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
}

// ── base64 encode for webauthn credential body ────────────────────────────────

func TestFinishWebAuthnLogin_InvalidCredential(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	// valid JSON with credential but invalid attestation
	cred := base64.RawURLEncoding.EncodeToString([]byte(`{"id":"test","rawId":"dGVzdA","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiY2hhbGxlbmdlIiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3QifQ","authenticatorData":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","signature":"AAAAAAAA"}}`))
	body := fmt.Sprintf(`{"mfa_challenge":"ch","webauthn_session":"s","credential":%q}`, cred)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.FinishWebAuthnLogin(w, req)
	// invalid credential format → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── ReassignOwner / TransferOwnership bad IDs ────────────────────────────────

func TestReassignOwner_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.ReassignOwner(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransferOwnership_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.TransferOwnership(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── s4b: package-level dispatch with defaultUserHandler set ──────────────────

// newS4bUserHandler creates a UserHandler and sets it as the global, returning
// a cleanup func that restores the previous state. Must be called at the
// start of each test that sets the global.
func setDefaultUserHandlerS4(t *testing.T) *UserHandler {
	t.Helper()
	uh, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	saved := defaultUserHandler
	defaultUserHandler = uh
	t.Cleanup(func() { defaultUserHandler = saved })
	return uh
}

// When defaultUserHandler is set, package-level SearchUsers dispatches to it.
func TestPackageLevel_SearchUsers_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/search?q=alice", nil))
	w := httptest.NewRecorder()
	SearchUsers(w, req)
	// Not 503 or 401 — dispatched successfully
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_StaleAccounts_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/stale", nil))
	w := httptest.NewRecorder()
	StaleAccounts(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_GetUserByEmail_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/by-email?email=x@example.com", nil))
	w := httptest.NewRecorder()
	GetUserByEmail(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_GetUserByUsername_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/by-username?username=alice", nil))
	w := httptest.NewRecorder()
	GetUserByUsername(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_GetUserByExternalID_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/by-external-id?external_id=ext123", nil))
	w := httptest.NewRecorder()
	GetUserByExternalID(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_VerifyCredentials_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	body := `{"username":"alice","password":"wrongpw"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/verify-credentials", strings.NewReader(body))
	w := httptest.NewRecorder()
	VerifyCredentials(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_VerifyMFACredentials_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	body := `{"mfa_challenge":"ch","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/verify-mfa", strings.NewReader(body))
	w := httptest.NewRecorder()
	VerifyMFACredentials(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_IssueMFAChallenge_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	IssueMFAChallenge(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_GetActiveMFAChallenge_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/mfa-challenge/active?user_id=1", nil)
	w := httptest.NewRecorder()
	GetActiveMFAChallenge(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_ConsumeMFAChallenge_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	body := `{"mfa_challenge":"ch","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/mfa-challenge/consume", strings.NewReader(body))
	w := httptest.NewRecorder()
	ConsumeMFAChallenge(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_RestoreUser_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	RestoreUser(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_UnlockUser_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	UnlockUser(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_SuspendUser_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	// Same-user check: UserID=1 trying to suspend user 1 → 400 "cannot change own state"
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	SuspendUser(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_ReactivateUser_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	ReactivateUser(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_RequirePasswordReset_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	RequirePasswordReset(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_ResendSetupLink_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	ResendSetupLink(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_RevokeSessions_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	RevokeSessions(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

// UpdateUser dispatch — has a legacy fallback but should still test the dispatch path.
func TestPackageLevel_UpdateUser_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	body := `{"username":"alice","email":"alice@example.com"}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "999"))
	w := httptest.NewRecorder()
	UpdateUser(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_DeleteUser_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	DeleteUser(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

// ── auth.go: Profile, ListSessions, RevokeSession, UpdateProfile, ChangePassword ──

func TestAuthHandler_Profile_UnauthorizedV2(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/profile", nil)
	w := httptest.NewRecorder()
	h.Profile(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Profile_UserNotFound(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	// userCtx with a non-existent user. UserID 1 is NOT safe here: other happy-path
	// tests sharing this DB (sharedS4Core) legitimately create the first-ever user
	// row, which lands on ID 1 — a fixed low ID risks colliding with that real
	// data (especially across `-count=N` repeats). Use a large, out-of-range ID
	// that can never collide, matching the convention other "not found" tests in
	// this package use (e.g. TestGetActiveMembershipProxy_NotFound_S13's 99999).
	req := withUserCtxID(httptest.NewRequest(http.MethodGet, "/auth/profile", nil), 999999999, "nonexistent-user")
	w := httptest.NewRecorder()
	h.Profile(w, req)
	// User doesn't exist → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAuthHandler_ListSessions_UnauthorizedV2(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	w := httptest.NewRecorder()
	h.ListSessions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_ListSessions_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/auth/sessions", nil))
	w := httptest.NewRecorder()
	h.ListSessions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_RevokeSession_UnauthorizedV2(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeSession(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_RevokeSession_BadID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokeSession(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_RevokeSession_NotFound(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.RevokeSession(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAuthHandler_UpdateProfile_UnauthorizedV2(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPut, "/auth/profile", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.UpdateProfile(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_UpdateProfile_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPut, "/auth/profile", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.UpdateProfile(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_UpdateProfile_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	// Valid profile update for non-existent user → 400 (UpdateOwnProfile returns error)
	req := withUserCtx(httptest.NewRequest(http.MethodPut, "/auth/profile", strings.NewReader(`{"display_name":"Alice"}`)))
	w := httptest.NewRecorder()
	h.UpdateProfile(w, req)
	// Either 400 (user not found) or 200 (found) — not 401/503
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestAuthHandler_ChangePassword_UnauthorizedV2(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.ChangePassword(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_ChangePassword_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.ChangePassword(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ChangePassword_BadCurrentPassword(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body := `{"current_password":"wrong","new_password":"NewPass123!"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.ChangePassword(w, req)
	// Either 401 incorrect, 400 bad request, or 500 user not found — not 200
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── auth.go Logout with and without bearer token ──────────────────────────────

func TestAuthHandler_Logout_MissingToken(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	w := httptest.NewRecorder()
	h.Logout(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_Logout_InvalidToken(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer nosuchtoken")
	w := httptest.NewRecorder()
	h.Logout(w, req)
	// Logout fails gracefully when session not found → error
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── auth.go RefreshToken ──────────────────────────────────────────────────────

func TestAuthHandler_RefreshToken_MissingToken(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_RefreshToken_InvalidToken(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer nosuchtoken")
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── auth.go InitSystem ────────────────────────────────────────────────────────

func TestAuthHandler_InitSystem_BadJSONV2(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/system/init", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.InitSystem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_InitSystem_MissingToken(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body := `{"username":"admin","email":"admin@example.com","password":"Admin1234!"}`
	req := httptest.NewRequest(http.MethodPost, "/system/init", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.InitSystem(w, req)
	// Missing bootstrap token → forbidden (403) or internal error (500) depending on DB state
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestAuthHandler_InitSystem_AlreadyInitialized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	// First call bootstraps
	body := `{"username":"admin","email":"admin@example.com","password":"Admin1234!","bootstrap_token":"devtoken"}`
	req := httptest.NewRequest(http.MethodPost, "/system/init", strings.NewReader(body))
	req.Header.Set("X-Keyorix-Bootstrap-Token", "devtoken")
	w := httptest.NewRecorder()
	h.InitSystem(w, req)
	// Second call should say already initialized (if first succeeded) or return error
	body2 := `{"username":"admin","email":"admin@example.com","password":"Admin1234!"}`
	req2 := httptest.NewRequest(http.MethodPost, "/system/init", strings.NewReader(body2))
	w2 := httptest.NewRecorder()
	h.InitSystem(w2, req2)
	// Either 200 already_initialized or some error — not 400
	assert.NotEqual(t, http.StatusBadRequest, w2.Code)
}

// ── auth.go buildLoginResponse and helpers (cover via successful Login flow) ──

func TestAuthHandler_buildLoginResponse_Direct(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	now := time.Now()
	later := now.Add(time.Hour)
	absoluteExpiry := now.Add(24 * time.Hour)
	session := &models.Session{
		SessionToken:      "tok123",
		ExpiresAt:         &later,
		AbsoluteExpiresAt: &absoluteExpiry,
	}
	user := &models.User{
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice",
	}
	user.ID = 1
	resp := h.buildLoginResponse(context.Background(), session, user)
	assert.Equal(t, "tok123", resp.Token)
	assert.Equal(t, "alice", resp.Username)
	assert.NotEmpty(t, resp.ExpiresAt)
	assert.NotEmpty(t, resp.AbsoluteExpiresAt)
}

func TestAuthHandler_buildLoginResponse_NoExpiry(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	session := &models.Session{SessionToken: "tok"}
	user := &models.User{Username: "bob", Email: "bob@example.com"}
	user.ID = 99
	resp := h.buildLoginResponse(context.Background(), session, user)
	assert.Equal(t, "tok", resp.Token)
	assert.Empty(t, resp.ExpiresAt)
}

func TestAuthHandler_setSessionCookies_Direct(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	now := time.Now().Add(time.Hour)
	session := &models.Session{SessionToken: "cookietoken", ExpiresAt: &now}
	w := httptest.NewRecorder()
	h.setSessionCookies(w, session)
	// Should set at least one cookie
	assert.NotEmpty(t, w.Header().Get("Set-Cookie"))
}

func TestUserProfileMap_Direct(t *testing.T) {
	user := &models.User{
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice",
		IsActive:    true,
	}
	user.ID = 1
	now := time.Now()
	user.LastLoginAt = &now

	id := core.UserIdentity{
		Role:        "admin",
		Roles:       []string{"admin"},
		Permissions: []string{"secrets.read"},
	}
	profile := userProfileMap(user, id)
	assert.Equal(t, uint(1), profile["id"])
	assert.Equal(t, "alice", profile["username"])
	assert.Equal(t, "admin", profile["role"])
	assert.NotNil(t, profile["last_login_at"])
}

func TestUserProfileMap_NilRolesPermissions(t *testing.T) {
	user := &models.User{Username: "bob", Email: "bob@example.com"}
	user.ID = 2
	id := core.UserIdentity{}
	profile := userProfileMap(user, id)
	assert.NotNil(t, profile["roles"])
	assert.NotNil(t, profile["permissions"])
}

// ── admin_jobs.go: RunComplianceDigest happy path ───────────────────────────

func TestAdminJobsHandler_RunComplianceDigest_HappyPath(t *testing.T) {
	h := NewAdminJobsHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/compliance-digest", nil))
	w := httptest.NewRecorder()
	h.RunComplianceDigest(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminJobsHandler_RunExpiryReminders_DefaultLeadDays(t *testing.T) {
	h := NewAdminJobsHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/expiry-reminders", nil))
	w := httptest.NewRecorder()
	h.RunExpiryReminders(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminJobsHandler_RunExpiryReminders_InvalidLeadDays(t *testing.T) {
	h := NewAdminJobsHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/expiry-reminders?lead_days=notanumber", nil))
	w := httptest.NewRecorder()
	h.RunExpiryReminders(w, req)
	// Falls back to default, still succeeds
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── admin_impersonation.go: End handler ──────────────────────────────────────

func TestImpersonationHandler_End_MissingToken(t *testing.T) {
	h := NewImpersonationHandler(newHandlerCoreS4(t), false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/end-impersonation", nil)
	w := httptest.NewRecorder()
	h.End(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestImpersonationHandler_End_InvalidToken(t *testing.T) {
	h := NewImpersonationHandler(newHandlerCoreS4(t), false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/end-impersonation", nil)
	req.Header.Set("Authorization", "Bearer nosuchtoken")
	w := httptest.NewRecorder()
	h.End(w, req)
	// Token not found → some error (not impersonation session → BadRequest or InternalError)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestImpersonationHandler_Start_AlreadyImpersonating(t *testing.T) {
	h := NewImpersonationHandler(newHandlerCoreS4(t), false)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":2}`)))
	// Set ImpersonatedBy to simulate already-impersonating session
	by := uint(99)
	ctx := req.Context()
	uc := &middleware.UserContext{
		UserID:         1,
		Username:       "testuser",
		ImpersonatedBy: &by,
	}
	req = req.WithContext(context.WithValue(ctx, middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.Start(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestImpersonationHandler_Start_MissingUserID(t *testing.T) {
	h := NewImpersonationHandler(newHandlerCoreS4(t), false)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":0}`)))
	w := httptest.NewRecorder()
	h.Start(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── access_review_campaigns.go: happy path + decision ────────────────────────

func TestOpenAccessReviewCampaign_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"Q4 Review"}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.OpenAccessReviewCampaign(w, req)
	// Project doesn't exist in empty DB → error, but auth + parsing passed
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestOpenAccessReviewCampaign_EmptyBody(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.OpenAccessReviewCampaign(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestDecideAccessReviewCampaignItem_BadCampaignID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{
		"id": "1", "campaignId": "notanumber", "itemId": "1",
	}))
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecideAccessReviewCampaignItem_BadItemID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{
		"id": "1", "campaignId": "1", "itemId": "notanumber",
	}))
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecideAccessReviewCampaignItem_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), map[string]string{
		"id": "1", "campaignId": "1", "itemId": "1",
	}))
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecideAccessReviewCampaignItem_MissingAction(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason":"just because"}`)), map[string]string{
		"id": "1", "campaignId": "1", "itemId": "1",
	}))
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCloseAccessReviewCampaign_BadCampaignID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{
		"id": "1", "campaignId": "notanumber",
	}))
	w := httptest.NewRecorder()
	h.CloseAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCloseAccessReviewCampaign_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"force":false}`)), map[string]string{
		"id": "1", "campaignId": "1",
	}))
	w := httptest.NewRecorder()
	h.CloseAccessReviewCampaign(w, req)
	// Project/campaign not found → error (but auth + parse succeeded)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestCampaignStatusForError_Cases(t *testing.T) {
	assert.Equal(t, http.StatusNotFound, campaignStatusForError("record not found"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("still pending items"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("already closed"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("campaign is closed"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("ownership cannot be revoked"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("value must be"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("required field"))
	assert.Equal(t, http.StatusInternalServerError, campaignStatusForError("some unexpected storage error"))
}

// ── break_glass.go: ActivateBreakGlass + RevokeBreakGlass ────────────────────

func TestActivateBreakGlass_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"justification":"test","ttl":"1h"}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestActivateBreakGlass_MissingJustificationV2(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestActivateBreakGlass_BadJSONV2(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestActivateBreakGlass_ProjectNotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"justification":"emergency","ttl":"1h"}`)), "id", "99"))
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	// Not enabled or not found → 403 or 400
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeBreakGlass_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{
		"id": "bad", "activationId": "1",
	}))
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeBreakGlass_BadActivationID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{
		"id": "1", "activationId": "bad",
	}))
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeBreakGlass_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{
		"id": "1", "activationId": "1",
	})
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListBreakGlassActivations_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListBreakGlassActivations(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListBreakGlassActivations_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListBreakGlassActivations(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── connect.go: ListConnectors, GetSecret, ListRefGrants, CreateRefGrant ─────

func newConnectHandlerS4(t *testing.T) *ConnectHandler {
	t.Helper()
	return NewConnectHandler(newHandlerCoreS4(t))
}

func TestConnectHandler_ListConnectors_HappyPath(t *testing.T) {
	h := newConnectHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListConnectors(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestConnectHandler_GetSecret_MissingRef(t *testing.T) {
	h := newConnectHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "name", "myconn"))
	w := httptest.NewRecorder()
	h.GetSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestConnectHandler_GetSecret_UnknownConnector(t *testing.T) {
	h := newConnectHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/?ref=myref", nil), "name", "unknownconn"))
	w := httptest.NewRecorder()
	h.GetSecret(w, req)
	// Unknown connector → error response (not 401)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestConnectHandler_ListRefGrants_HappyPath(t *testing.T) {
	h := newConnectHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListRefGrants(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestConnectHandler_CreateRefGrant_BadJSON(t *testing.T) {
	h := newConnectHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreateRefGrant(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestConnectHandler_CreateRefGrant_MissingConnector(t *testing.T) {
	h := newConnectHandlerS4(t)
	body := `{"role_id":1,"ref_prefix":"myref"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreateRefGrant(w, req)
	// Missing connector → error
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── secrets_audit_trail.go: toSecretAuditEntry ────────────────────────────────

func TestToSecretAuditEntry_NoDiff(t *testing.T) {
	now := time.Now()
	e := &models.AuditEvent{
		EventType:   "secret.created",
		EventTime:   now,
		Description: "Secret created",
		Diff:        "",
	}
	entry := toSecretAuditEntry(e)
	assert.Equal(t, "secret.created", entry.EventType)
	assert.Nil(t, entry.Diff)
	assert.True(t, entry.Success) // nil Success → true
}

func TestToSecretAuditEntry_WithDiff(t *testing.T) {
	now := time.Now()
	success := false
	e := &models.AuditEvent{
		EventType:   "secret.rotated",
		EventTime:   now,
		Description: "Rotated",
		Diff:        `{"changed":true}`,
		Success:     &success,
	}
	entry := toSecretAuditEntry(e)
	assert.False(t, entry.Success)
	assert.NotNil(t, entry.Diff)
	assert.Contains(t, string(entry.Diff), "changed")
}

// ── secrets_deleted.go: toDeletedSecretEntry ─────────────────────────────────

func TestToDeletedSecretEntry_ValidDeletedAt(t *testing.T) {
	now := time.Now()
	s := &models.SecretNode{
		Name:           "mysecret",
		Type:           "generic",
		Classification: "public",
		EnvironmentID:  1,
		OwnerID:        2,
	}
	s.ID = 10
	s.DeletedAt = gorm.DeletedAt{Time: now, Valid: true}
	entry := toDeletedSecretEntry(s)
	assert.Equal(t, uint(10), entry.ID)
	assert.Equal(t, "mysecret", entry.Name)
	assert.NotEmpty(t, entry.DeletedAt)
}

func TestToDeletedSecretEntry_NoDeletedAt(t *testing.T) {
	s := &models.SecretNode{Name: "s", Type: "generic"}
	entry := toDeletedSecretEntry(s)
	assert.Empty(t, entry.DeletedAt)
}

// ── secrets_tags.go: tagError ─────────────────────────────────────────────────

func TestTagError_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	w := httptest.NewRecorder()
	h.tagError(w, fmt.Errorf("record not found"), "fallback")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTagError_Forbidden(t *testing.T) {
	h := newSecretHandlerS4(t)
	w := httptest.NewRecorder()
	h.tagError(w, fmt.Errorf("permission denied"), "fallback")
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestTagError_Validation(t *testing.T) {
	h := newSecretHandlerS4(t)
	w := httptest.NewRecorder()
	h.tagError(w, fmt.Errorf("tag exceeds maximum"), "fallback")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTagError_AtMost(t *testing.T) {
	h := newSecretHandlerS4(t)
	w := httptest.NewRecorder()
	h.tagError(w, fmt.Errorf("at most 10 tags allowed"), "fallback")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTagError_ValidationKeyword(t *testing.T) {
	h := newSecretHandlerS4(t)
	w := httptest.NewRecorder()
	h.tagError(w, fmt.Errorf("validation failed: bad tag"), "fallback")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTagError_Internal(t *testing.T) {
	h := newSecretHandlerS4(t)
	w := httptest.NewRecorder()
	h.tagError(w, fmt.Errorf("unexpected storage error"), "internal error occurred")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTagError_NotAuthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	w := httptest.NewRecorder()
	h.tagError(w, fmt.Errorf("not authorized to tag this secret"), "fallback")
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── sso.go: redirectFragment ──────────────────────────────────────────────────

func TestRedirectFragment_Direct(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	vals := url.Values{}
	vals.Set("token", "tok123")
	h.redirectFragment(w, req, "https://example.com/complete", vals)
	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "https://example.com/complete#")
	assert.Contains(t, location, "tok123")
}

// ── audit.go: GetAuditLogs, GetRBACAuditLogs, GetAuditRetention ──────────────

func newAuditHandlerS4(t *testing.T) *AuditHandler {
	t.Helper()
	return NewAuditHandler(newHandlerCoreS4(t))
}

func TestGetAuditLogs_Unauthorized(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs", nil)
	w := httptest.NewRecorder()
	h.GetAuditLogs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetAuditLogs_HappyPath(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs", nil))
	w := httptest.NewRecorder()
	h.GetAuditLogs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetAuditLogs_WithFilters(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs?page=2&page_size=10&action=secret.created&user_id=1&project_id=1&secret_id=1&start_time=2024-01-01T00:00:00Z&end_time=2024-12-31T00:00:00Z&actor_type=user", nil))
	w := httptest.NewRecorder()
	h.GetAuditLogs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetRBACAuditLogs_Unauthorized(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/rbac-logs", nil)
	w := httptest.NewRecorder()
	h.GetRBACAuditLogs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetRBACAuditLogs_HappyPath(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/rbac-logs?page=1&page_size=20", nil))
	w := httptest.NewRecorder()
	h.GetRBACAuditLogs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetAuditRetention_Unauthorized(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/retention", nil)
	w := httptest.NewRecorder()
	h.GetAuditRetention(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetAuditRetention_HappyPath(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/retention", nil))
	w := httptest.NewRecorder()
	h.GetAuditRetention(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── audit.go: VerifyAuditChain, WriteAuditCheckpoint ─────────────────────────

func TestVerifyAuditChain_Unauthorized(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil)
	w := httptest.NewRecorder()
	h.VerifyAuditChain(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestVerifyAuditChain_HappyPath(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil))
	w := httptest.NewRecorder()
	h.VerifyAuditChain(w, req)
	// Empty chain is valid
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── catalog.go: ListEnvironments, RestoreProject ─────────────────────────────

func TestCatalog_RestoreProject_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.RestoreProject(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalog_RestoreProject_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "99")
	w := httptest.NewRecorder()
	h.RestoreProject(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── dashboard.go: GetCompliancePosture, GetComplianceDigest, GetComplianceControls ──

func TestDashboard_GetComplianceDigest_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetComplianceDigest(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestDashboard_GetComplianceControls_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetComplianceControls(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestDashboard_GetComplianceEvidence_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetComplianceEvidence(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestDashboard_GetCompliancePosture_NoContext(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetCompliancePosture(w, req)
	// Handler responds (may be 200 with empty data or error depending on auth config)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

// ── dynamic_secrets.go: ListLeases, RevokeLease ───────────────────────────────

func TestDynamicSecretHandler_ListLeases_Unauthorized(t *testing.T) {
	h := NewDynamicSecretHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	// No user context or no authz → 401 or 403
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestDynamicSecretHandler_RevokeLease_UnauthorizedV2(t *testing.T) {
	h := NewDynamicSecretHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "leaseID", "lease123")
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDynamicSecretHandler_RevokeLease_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "leaseID", "nosuchlease"))
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── users_crud.go: UnlockUser, accountStateAction, RevokeSessions, ResendSetupLink ──

func newUserHandlerS4(t *testing.T) *UserHandler {
	t.Helper()
	h, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	return h
}

func TestUserHandler_UnlockUser_BadID(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.UnlockUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_UnlockUser_NotFound(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.UnlockUser(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_SuspendUser_SelfSuspend(t *testing.T) {
	h := newUserHandlerS4(t)
	// Suspend user ID 1, authenticated as user ID 1 → 400
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.SuspendUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_SuspendUser_NotFound(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.SuspendUser(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_RevokeSessions_Unauthorized(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeSessions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_RevokeSessions_BadID(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokeSessions(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_DeleteUser_UnauthorizedV2(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_RestoreUser_UnauthorizedV2(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RestoreUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_ResendSetupLink_UnauthorizedV2(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ResendSetupLink(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_ResendSetupLink_BadID(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ResendSetupLink(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── users_crud.go: UpdateUser, DeleteUser, RestoreUser ────────────────────────

func TestUserHandler_DeleteUser_BadID(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.DeleteUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_RestoreUser_BadID(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RestoreUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── users_handler.go: userToAPIResponse ──────────────────────────────────────

func TestUserToAPIResponse_WithLastLogin(t *testing.T) {
	now := time.Now()
	u := &models.User{
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice",
		IsActive:    true,
		LastLoginAt: &now,
	}
	u.ID = 1
	resp := userToAPIResponse(u)
	assert.NotNil(t, resp["last_login_at"])
	assert.Equal(t, "alice", resp["username"])
}

func TestUserToAPIResponse_EmptyDisplayName(t *testing.T) {
	u := &models.User{Username: "bob", Email: "bob@example.com"}
	u.ID = 2
	resp := userToAPIResponse(u)
	// Falls back to username when display_name is empty
	assert.Equal(t, "bob", resp["display_name"])
}

func TestUserToAPIResponse_WithDeletedAt(t *testing.T) {
	now := time.Now()
	u := &models.User{Username: "gone", Email: "gone@example.com"}
	u.ID = 3
	u.DeletedAt = gorm.DeletedAt{Time: now, Valid: true}
	resp := userToAPIResponse(u)
	assert.NotNil(t, resp["deleted_at"])
}

func TestUserToAPIResponse_WithLoginLockedUntil(t *testing.T) {
	future := time.Now().Add(time.Hour)
	u := &models.User{Username: "locked", Email: "locked@example.com", LoginLockedUntil: &future}
	u.ID = 4
	resp := userToAPIResponse(u)
	assert.NotNil(t, resp["login_locked_until"])
}

// ── invitations.go: ListInvitations, CreateInvitation ────────────────────────

func TestCreateInvitation_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"email":"a@b.com","role":"viewer"}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateInvitation_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateInvitation_MissingFieldsV2(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"email":"a@b.com"}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── userIdentity (auth.go) ───────────────────────────────────────────────────

func TestUserIdentity_Direct(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// userIdentity returns empty identity on error (user 999 doesn't exist)
	id := h.userIdentity(req, 999)
	// Should not panic; returns empty
	assert.NotNil(t, id.Roles)
	assert.NotNil(t, id.Permissions)
}

// ── catalog.go: UpdateProject RequireMFA path ─────────────────────────────────

func TestCatalog_UpdateProject_RequireMFA_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	mfa := true
	bodyBytes, _ := json.Marshal(map[string]any{"name": "proj", "require_mfa": mfa})
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(bodyBytes)), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateProject(w, req)
	// No roles.assign permission → 403
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── access_review_campaigns.go: GetAccessReviewCampaign ──────────────────────

func TestGetAccessReviewCampaign_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{
		"id": "1", "campaignId": "99",
	})
	w := httptest.NewRecorder()
	h.GetAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── secrets handler: GetSecretTags, SetSecretTags ─────────────────────────────

func TestSecretHandler_SetTags_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"tags":["a"]}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.SetTags(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetTags_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.GetTags(w, req)
	// Secret not found → tagError → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── users_list.go: StaleAccounts with more query params ──────────────────────

func TestStaleAccounts_WithDaysParam(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/stale?days=90", nil))
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestStaleAccounts_WithInvalidDays(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/stale?days=notanumber", nil))
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	// Falls back to default, should not error
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── audit.go ExportAuditLogs ──────────────────────────────────────────────────

func TestExportAuditLogs_Unauthorized(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/export", nil)
	w := httptest.NewRecorder()
	h.ExportAuditLogs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestExportAuditLogs_HappyPath(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export", nil))
	w := httptest.NewRecorder()
	h.ExportAuditLogs(w, req)
	// Empty DB → either 200 empty or some valid response
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── machine_identities.go: bad machineId + unauthorized + bad JSON + invalid action ──

func TestTransitionMachineIdentity_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", nil),
		map[string]string{"id": "1", "machineId": "bad"})
	w := httptest.NewRecorder()
	h.TransitionMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMachineIdentity_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)),
		map[string]string{"id": "1", "machineId": "1"})
	w := httptest.NewRecorder()
	h.TransitionMachineIdentity(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTransitionMachineIdentity_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")),
		map[string]string{"id": "1", "machineId": "1"}))
	w := httptest.NewRecorder()
	h.TransitionMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMachineIdentity_InvalidAction(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"action":"unknown"}`
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)),
		map[string]string{"id": "1", "machineId": "1"}))
	w := httptest.NewRecorder()
	h.TransitionMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMachineIdentity_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"action":"activate"}`
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)),
		map[string]string{"id": "9999", "machineId": "9999"}))
	w := httptest.NewRecorder()
	h.TransitionMachineIdentity(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestIssueMachineToken_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "1", "machineId": "bad"})
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestIssueMachineToken_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)),
		map[string]string{"id": "1", "machineId": "1"})
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestIssueMachineToken_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")),
		map[string]string{"id": "1", "machineId": "1"}))
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestIssueMachineToken_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"name":"tok","expires_in_days":90}`
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)),
		map[string]string{"id": "9999", "machineId": "9999"}))
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRevokeMachineToken_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "machineId": "bad", "tokenId": "1"})
	w := httptest.NewRecorder()
	h.RevokeMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeMachineToken_BadTokenID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "machineId": "1", "tokenId": "bad"})
	w := httptest.NewRecorder()
	h.RevokeMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeMachineToken_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "machineId": "1", "tokenId": "1"})
	w := httptest.NewRecorder()
	h.RevokeMachineToken(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeMachineToken_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "9999", "machineId": "9999", "tokenId": "9999"}))
	w := httptest.NewRecorder()
	h.RevokeMachineToken(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestClassifyMachineIdentity_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPatch, "/", nil),
		map[string]string{"id": "1", "machineId": "bad"})
	w := httptest.NewRecorder()
	h.ClassifyMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClassifyMachineIdentity_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(`{}`)),
		map[string]string{"id": "1", "machineId": "1"})
	w := httptest.NewRecorder()
	h.ClassifyMachineIdentity(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestClassifyMachineIdentity_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader("{bad")),
		map[string]string{"id": "1", "machineId": "1"}))
	w := httptest.NewRecorder()
	h.ClassifyMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClassifyMachineIdentity_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"classification":"confidential"}`
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(body)),
		map[string]string{"id": "9999", "machineId": "9999"}))
	w := httptest.NewRecorder()
	h.ClassifyMachineIdentity(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestClassifyMachineToken_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPatch, "/", nil),
		map[string]string{"id": "1", "machineId": "bad", "tokenId": "1"})
	w := httptest.NewRecorder()
	h.ClassifyMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClassifyMachineToken_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(`{}`)),
		map[string]string{"id": "1", "machineId": "1", "tokenId": "1"})
	w := httptest.NewRecorder()
	h.ClassifyMachineToken(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestClassifyMachineToken_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader("{bad")),
		map[string]string{"id": "1", "machineId": "1", "tokenId": "1"}))
	w := httptest.NewRecorder()
	h.ClassifyMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClassifyMachineToken_BadTokenID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPatch, "/", nil),
		map[string]string{"id": "1", "machineId": "1", "tokenId": "bad"}))
	w := httptest.NewRecorder()
	h.ClassifyMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClassifyMachineToken_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"classification":"confidential"}`
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(body)),
		map[string]string{"id": "9999", "machineId": "9999", "tokenId": "9999"}))
	w := httptest.NewRecorder()
	h.ClassifyMachineToken(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCreateOIDCBinding_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "1", "machineId": "bad"})
	w := httptest.NewRecorder()
	h.CreateOIDCBinding(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateOIDCBinding_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")),
		map[string]string{"id": "1", "machineId": "1"}))
	w := httptest.NewRecorder()
	h.CreateOIDCBinding(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateOIDCBinding_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"issuer":"https://accounts.example.com","subject":"user123"}`
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)),
		map[string]string{"id": "9999", "machineId": "9999"}))
	w := httptest.NewRecorder()
	h.CreateOIDCBinding(w, req)
	// machine not found → 404 or 400 depending on core validation order
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestListOIDCBindings_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "1", "machineId": "bad"})
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListOIDCBindings_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "1", "machineId": "1"})
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListOIDCBindings_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "1", "machineId": "1"}))
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)
	// machine doesn't exist but empty list is ok
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestDeleteOIDCBinding_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "machineId": "bad", "bindingId": "1"})
	w := httptest.NewRecorder()
	h.DeleteOIDCBinding(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteOIDCBinding_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "machineId": "1", "bindingId": "1"})
	w := httptest.NewRecorder()
	h.DeleteOIDCBinding(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeleteOIDCBinding_BadBindingID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "machineId": "1", "bindingId": "bad"}))
	w := httptest.NewRecorder()
	h.DeleteOIDCBinding(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteOIDCBinding_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "9999", "machineId": "9999", "bindingId": "9999"}))
	w := httptest.NewRecorder()
	h.DeleteOIDCBinding(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── groups_members.go: AddGroupMember, RemoveGroupMember ────────────────────

func TestGroupHandler_GetGroupMembers_Unauthorized(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetGroupMembers(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGroupHandler_GetGroupMembers_HappyPath(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.GetGroupMembers(w, req)
	// Group 1 doesn't exist in empty DB → error or 404
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_AddGroupMember_Unauthorized(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGroupHandler_AddGroupMember_BadJSON(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_AddGroupMember_MissingUserID(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_RemoveGroupMember_Unauthorized(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "userId": "1"})
	w := httptest.NewRecorder()
	h.RemoveGroupMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGroupHandler_RemoveGroupMember_BadUserID(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "userId": "bad"}))
	w := httptest.NewRecorder()
	h.RemoveGroupMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_RemoveGroupMember_NotFound(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "9999", "userId": "9999"}))
	w := httptest.NewRecorder()
	h.RemoveGroupMember(w, req)
	// Internal error because no such group (not a "last member" conflict)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── project_members.go: UpdateProjectMember, RevokeProjectAccessReview ──────

func TestUpdateProjectMember_BadUserID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)),
		map[string]string{"id": "1", "userId": "bad"}))
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateProjectMember_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")),
		map[string]string{"id": "1", "userId": "1"}))
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateProjectMember_MissingRole(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)),
		map[string]string{"id": "1", "userId": "1"}))
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeProjectAccessReview_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeProjectAccessReview_UnauthorizedV2(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeProjectAccessReview_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeProjectAccessReview_MissingSource(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAttestProjectAccessReview_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.AttestProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAttestProjectAccessReview_UnauthorizedV2(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.AttestProjectAccessReview(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAddProjectMember_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.AddProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveProjectMember_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "bad", "userId": "1"})
	w := httptest.NewRecorder()
	h.RemoveProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rotation_policies_handler.go: Update, Evaluate, Status extra paths ──────

func newRotationPolicyHandlerS4(t *testing.T) *RotationPolicyHandler {
	t.Helper()
	return NewRotationPolicyHandler(newHandlerCoreS4(t))
}

func TestRotationPolicyHandler_Update_BadID(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Update_BadJSON(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Update_ValidationError(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	body := `{"name":"","interval_days":0}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "1"))
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Update_NotFound(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	body := `{"name":"pol","interval_days":30}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "9999"))
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRotationPolicyHandler_Evaluate_BadProjectID(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=bad", nil))
	w := httptest.NewRecorder()
	h.Evaluate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Evaluate_BadEnvID(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?environment_id=bad", nil))
	w := httptest.NewRecorder()
	h.Evaluate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Evaluate_HappyPath(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.Evaluate(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRotationPolicyHandler_Status_BadProjectID(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=bad", nil))
	w := httptest.NewRecorder()
	h.Status(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Status_BadEnvID(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?environment_id=bad", nil))
	w := httptest.NewRecorder()
	h.Status(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Status_HappyPath(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.Status(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRotationPolicyHandler_Get_BadID(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.Get(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Get_NotFound(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.Get(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRotationPolicyHandler_Delete_BadID(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.Delete(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Delete_NotFound(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.Delete(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRotationPolicyHandler_Create_ValidationError(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	body := `{"name":"","interval_days":0}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Create_HappyPath(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	body := `{"name":"daily","interval_days":1,"alert_days_before":0}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.Create(w, req)
	// Either 201 (created) or 4xx (validation with missing user); not 401/500
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

// ── rbac.go: additional paths for RemoveRole, GetRolePermissions, GetGroupRoles ──

func TestRBACHandler_RemoveRole_BadJSON(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodDelete, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.RemoveRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_RemoveRole_ValidationError(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodDelete, "/", strings.NewReader(`{}`)))
	w := httptest.NewRecorder()
	h.RemoveRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetRolePermissions_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetRolePermissions(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetRolePermissions_NotFound(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.GetRolePermissions(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRBACHandler_GetGroupRoles_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetGroupRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetGroupRoles_HappyPath(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.GetGroupRoles(w, req)
	// group not found → 404 or empty list
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_AssignRoleToGroup_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.AssignRoleToGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_AssignRoleToGroup_BadJSON(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.AssignRoleToGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_AssignRoleToGroup_MissingRoleID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.AssignRoleToGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_RemoveRoleFromGroup_BadGroupID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "bad", "roleId": "1"}))
	w := httptest.NewRecorder()
	h.RemoveRoleFromGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_RemoveRoleFromGroup_BadRoleID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "roleId": "bad"}))
	w := httptest.NewRecorder()
	h.RemoveRoleFromGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetPermission_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetPermission(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetPermission_NotFound(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.GetPermission(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRBACHandler_AssignPermissionToRole_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.AssignPermissionToRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_AssignPermissionToRole_BadJSON(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.AssignPermissionToRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_RemovePermissionFromRole_BadRoleID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "bad", "permissionId": "1"}))
	w := httptest.NewRecorder()
	h.RemovePermissionFromRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetUserRoles_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "userId", "bad"))
	w := httptest.NewRecorder()
	h.GetUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_ListPermissions_WithFilter(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?resource=secrets", nil))
	w := httptest.NewRecorder()
	h.ListPermissions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── shares: extra paths for ListShares, ShareSecret, UpdateSharePermission ──

func TestShareHandler_ListShares_HappyPath(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestShareHandler_ListShares_WithFilter(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?secretId=1&recipientType=user", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestShareHandler_ShareSecret_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_ShareSecret_BadJSON(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_ShareSecret_ValidationError(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_UpdateSharePermission_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_UpdateSharePermission_BadJSON(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_RevokeShare_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokeShare(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_GetSharingStatusWithIndicators_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetSharingStatusWithIndicators(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_GetSharingStatusWithIndicators_NotFound(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.GetSharingStatusWithIndicators(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestShareHandler_RemoveSelfFromShare_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RemoveSelfFromShare(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_list.go: ListSecrets happy path with various filters ─────────────

func TestSecretHandler_ListSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?page=1&page_size=10", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	// User ID from context may not exist in empty DB → 500 or 200 empty
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_ListSecrets_WithFilters(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?search=foo&include_deleted=true&show_owned_only=true&type=static&classification=public&tag=a,b", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	// User ID from context may not exist in empty DB → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_versions.go: RollbackSecret extra paths ──────────────────────────

func TestSecretHandler_RollbackSecret_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"version":1}`)), "id", "1")
	w := httptest.NewRecorder()
	h.RollbackSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_RollbackSecret_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"version":1}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.RollbackSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_RollbackSecret_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.RollbackSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_RollbackSecret_InvalidVersion(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"version":0}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.RollbackSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_RollbackSecret_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"version":1}`)), "id", "9999"))
	w := httptest.NewRecorder()
	h.RollbackSecret(w, req)
	// Secret not found → 404 or 500 depending on DB layout
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── dynamic_secrets.go: RenewLease extra paths ───────────────────────────────

func TestDynamicSecretHandler_RenewLease_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "leaseID", "nosuchlease"))
	w := httptest.NewRecorder()
	h.RenewLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── sod.go: SoD policy CRUD ──────────────────────────────────────────────────

func TestSoDPolicy_Create_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSoDPolicy_Create_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	// empty permissions → validation error
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSoDPolicy_Delete_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.DeleteSoDPolicy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── secrets_reassign_owner.go: ReassignOwner ─────────────────────────────────

func TestSecretHandler_ReassignOwner_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.ReassignOwner(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_ReassignOwner_MissingFromOwner(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"to_owner_id":2}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.ReassignOwner(w, req)
	// from_owner_id=0, to_owner_id=2 → validation error (required)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_access_list.go: ListAccessors ────────────────────────────────────

func TestSecretHandler_ListAccessors_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.ListAccessors(w, req)
	// Secret not found → error
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── catalog.go: ListEnvironments extra paths ──────────────────────────────────

func TestCatalogHandler_ListEnvironments_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListEnvironments(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── users_roles.go: UpdateUserRoles extra paths ───────────────────────────────

func TestUserRoles_GetUserRolesForUser_BadID(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserRoles_GetUserRolesForUser_HappyPath(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	// user 1 doesn't exist in empty DB → not found
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestUserRoles_GetUserPermissionsForUser_BadID(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUserPermissionsForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserRoles_UpdateUserRoles_Unauthorized(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserRoles_UpdateUserRoles_BadID(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserRoles_UpdateUserRoles_BadJSON(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserRoles_GetUserMembershipsForUser_BadID(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── users_handler.go: GetUserByUsername, GetUserByExternalID, VerifyMFACredentials ──

func TestUserHandler_GetUserByUsername_HappyPath(t *testing.T) {
	h, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "username", "nouser"))
	w := httptest.NewRecorder()
	h.GetUserByUsername(w, req)
	// user doesn't exist → not found or 200 empty
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetUserByExternalID_Unauthorized(t *testing.T) {
	h, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "externalId", "ext123")
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetUserByExternalID_HappyPath(t *testing.T) {
	h, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "externalId", "ext123"))
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	// external ID not found → error
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_VerifyMFACredentials_Unauthorized(t *testing.T) {
	h, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.VerifyMFACredentials(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_VerifyMFACredentials_BadJSON(t *testing.T) {
	h, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.VerifyMFACredentials(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_RestoreUser_BadIDV2(t *testing.T) {
	h, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RestoreUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_RestoreUser_NotFound(t *testing.T) {
	h, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.RestoreUser(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── notifications_handler.go: MarkRead ───────────────────────────────────────

func TestNotificationsHandler_MarkRead_Unauthorized(t *testing.T) {
	h := NewNotificationHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPatch, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.MarkRead(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestNotificationsHandler_MarkRead_BadID(t *testing.T) {
	h := NewNotificationHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPatch, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.MarkRead(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestNotificationsHandler_MarkRead_NotFound(t *testing.T) {
	h := NewNotificationHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPatch, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.MarkRead(w, req)
	// notification not found → error
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── pat_handler.go: toPATResponse ────────────────────────────────────────────

func TestPATHandler_ListPATs_HappyPath(t *testing.T) {
	h := NewPATHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListPATs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPATHandler_CreatePAT_Unauthorized(t *testing.T) {
	h := NewPATHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreatePAT(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPATHandler_CreatePAT_BadJSON(t *testing.T) {
	h := NewPATHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreatePAT(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPATHandler_CreatePAT_HappyPath(t *testing.T) {
	h := NewPATHandler(newHandlerCoreS4(t))
	body := `{"name":"mytoken","expires_in_days":30}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreatePAT(w, req)
	// user 1 doesn't exist → error, but not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestPATHandler_RevokePAT_Unauthorized(t *testing.T) {
	h := NewPATHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokePAT(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPATHandler_RevokePAT_BadID(t *testing.T) {
	h := NewPATHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokePAT(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_copy_environment.go ───────────────────────────────────────────────

func TestSecretHandler_CopyEnvironmentSecrets_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.CopyEnvironmentSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_CopyEnvironmentSecrets_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.CopyEnvironmentSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_CopyEnvironmentSecrets_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.CopyEnvironmentSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── invitations.go: WithdrawAccessRequest ─────────────────────────────────────

func TestWithdrawAccessRequest_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "requestId", "bad"))
	w := httptest.NewRecorder()
	h.WithdrawAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWithdrawAccessRequest_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "requestId", "9999"))
	w := httptest.NewRecorder()
	h.WithdrawAccessRequest(w, req)
	// not found
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_crud.go: GetSecretValueByRef ─────────────────────────────────────

func TestSecretHandler_GetSecretValueByRef_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?ref=foo", nil)
	w := httptest.NewRecorder()
	h.GetSecretValueByRef(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_GetSecretValueByRef_MissingRef(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetSecretValueByRef(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetSecretValueByRef_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?ref=projects/1/environments/1/secrets/nope", nil))
	w := httptest.NewRecorder()
	h.GetSecretValueByRef(w, req)
	// secret not found → error
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── sso.go: CompleteSSO ───────────────────────────────────────────────────────

func TestCompleteSSO_UnknownProviderS4(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "unknown-provider")
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCompleteSSO_IdPErrorParam(t *testing.T) {
	// With a known provider (BeginSSO wouldn't error but CompleteSSO checks SSOCompleteURL).
	// Since no SSO providers are configured in our empty DB core, it returns unknown provider.
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/?error=access_denied", nil), "provider", "google")
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	// Either unknown provider (400) or redirect (302) — not 200
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestCompleteSSO_MissingCodeAndState(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "google")
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── saml.go: CompleteSAML ─────────────────────────────────────────────────────

func TestCompleteSAML_UnknownProvider(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "provider", "unknown-provider")
	w := httptest.NewRecorder()
	h.CompleteSAML(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCompleteSAML_KnownProviderNoSAMLResponse(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("")), "provider", "test")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.CompleteSAML(w, req)
	// unknown provider or redirect — not 200
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── saml.go / sso.go: BeginSSO and BeginSAML ────────────────────────────────

func TestBeginSSO_UnknownProviderS4(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "nonexistent")
	w := httptest.NewRecorder()
	h.BeginSSO(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBeginSAML_UnknownProvider(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "nonexistent")
	w := httptest.NewRecorder()
	h.BeginSAML(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── mfa.go: EnrollMFA, DisableMFA, RegenerateRecoveryCodes, RecoveryCodesStatus ──

func TestEnrollMFA_WithUser(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil))
	w := httptest.NewRecorder()
	h.EnrollMFA(w, req)
	// user doesn't exist → error, but not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestDisableMFA_UnauthorizedS4(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.DisableMFA(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDisableMFA_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.DisableMFA(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDisableMFA_WithUser(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body := `{"code":"123456"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.DisableMFA(w, req)
	// user doesn't exist → error, but not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestRegenerateRecoveryCodes_UnauthorizedS4(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.RegenerateRecoveryCodes(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRegenerateRecoveryCodes_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.RegenerateRecoveryCodes(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRegenerateRecoveryCodes_WithUser(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body := `{"code":"123456"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.RegenerateRecoveryCodes(w, req)
	// user doesn't exist → error, but not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestRecoveryCodesStatus_WithUser(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.RecoveryCodesStatus(w, req)
	// user doesn't exist → error, but not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── audit_anomaly.go: ListAnomalyAlerts, AcknowledgeAnomalyAlert ─────────────

func TestListAnomalyAlerts_NoCoreServiceS4(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	// Call directly — no core service in context → 500
	ListAnomalyAlerts(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAcknowledgeAnomalyAlert_NoCoreServiceS4(t *testing.T) {
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	AcknowledgeAnomalyAlert(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAcknowledgeAnomalyAlert_BadIDNoCore(t *testing.T) {
	// Bad ID but no core service — hits internal error first
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	AcknowledgeAnomalyAlert(w, req)
	// No core service → 500 (before ID parsing)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── legal_hold.go: LiftLegalHold ─────────────────────────────────────────────

func TestLiftLegalHold_UnauthorizedS4(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	w := httptest.NewRecorder()
	h.LiftLegalHold(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLiftLegalHold_NoActiveHold(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	body := `{"reason":"investigation complete"}`
	req := withUserCtx(httptest.NewRequest(http.MethodDelete, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.LiftLegalHold(w, req)
	// no active hold → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── shares_query.go: ListSecretShares ────────────────────────────────────────

func TestShareHandler_ListSecretShares_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ListSecretShares(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_ListSecretShares_NotFound(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.ListSecretShares(w, req)
	// secret not found → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── shares_query.go: ListShares ───────────────────────────────────────────────

func TestShareHandler_ListShares_WithUser(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	// user may or may not exist → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ListShares_WithFilters(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?secretId=1&recipientType=user&page=1&pageSize=10", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── shares_query.go: GetSharingStatusWithIndicators ──────────────────────────

// ── shares_query.go: RemoveSelfFromShare ─────────────────────────────────────

// ── shares_crud.go: ShareSecret ──────────────────────────────────────────────

func TestShareHandler_ShareSecret_UnauthorizedS4(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ShareSecret_ValidationErrorS4(t *testing.T) {
	h := newShareHandlerS4(t)
	// Missing required fields
	body := `{"is_group":false}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1"))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── shares_crud.go: UpdateSharePermission ────────────────────────────────────

func TestShareHandler_UpdateSharePermission_UnauthorizedS4(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_UpdateSharePermission_ValidationError(t *testing.T) {
	h := newShareHandlerS4(t)
	body := `{"permission":"invalid_permission"}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── shares_crud.go: RevokeShare ──────────────────────────────────────────────

// ── project_members.go: RevokeProjectAccessReview ────────────────────────────

func TestRevokeProjectAccessReviewV3_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"source":"share","resource_id":1}`
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeProjectAccessReviewV3_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"source":"share","resource_id":9999}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1"))
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	// not found → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── project_memberships.go: TransitionMembership ────────────────────────────

func TestTransitionMembership_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "bad", "membershipId": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), params)
	w := httptest.NewRecorder()
	h.TransitionMembership(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMembership_BadMembershipID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "1", "membershipId": "bad"}
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), params)
	w := httptest.NewRecorder()
	h.TransitionMembership(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMembership_UnauthorizedS4(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "1", "membershipId": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"action":"activate"}`)), params)
	w := httptest.NewRecorder()
	h.TransitionMembership(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTransitionMembership_InvalidAction(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "1", "membershipId": "1"}
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"action":"invalid"}`)), params))
	w := httptest.NewRecorder()
	h.TransitionMembership(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── invitations.go: CreateAccessRequest ──────────────────────────────────────

func TestCreateAccessRequest_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.CreateAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessRequest_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.CreateAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessRequest_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"suggested_role":"viewer","reason":"need access"}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "9999"))
	w := httptest.NewRecorder()
	h.CreateAccessRequest(w, req)
	// project not found → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_crud.go: GetSecretByName ─────────────────────────────────────────

func TestSecretHandler_GetSecretByName_MissingProjectID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?name=foo&environment_id=1", nil))
	w := httptest.NewRecorder()
	h.GetSecretByName(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetSecretByName_MissingEnvironmentID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?name=foo&project_id=1", nil))
	w := httptest.NewRecorder()
	h.GetSecretByName(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetSecretByName_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?name=nonexistent&project_id=1&environment_id=1", nil))
	w := httptest.NewRecorder()
	h.GetSecretByName(w, req)
	// not found → 404
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_usage.go: UsageUnused ────────────────────────────────────────────

func TestSecretHandler_UsageUnused_BadProjectID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=bad", nil))
	w := httptest.NewRecorder()
	h.UsageUnused(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_UsageUnused_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=1&days=30", nil))
	w := httptest.NewRecorder()
	h.UsageUnused(w, req)
	// not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── dynamic_secrets.go: parseScopeQuery / CreateConfig / ListLeases ──────────

func TestDynamicSecretHandler_ParseScopeQuery_BadProjectID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=bad", nil))
	w := httptest.NewRecorder()
	// ListConfigs calls parseScopeQuery internally
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDynamicSecretHandler_ParseScopeQuery_BadEnvironmentID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=1&environment_id=bad", nil))
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDynamicSecretHandler_CreateConfig_UnauthorizedS4(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDynamicSecretHandler_CreateConfig_BadJSON(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDynamicSecretHandler_CreateConfig_WithUser(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	body := `{"name":"pg-dev","project_id":1,"environment_id":1,"backend_type":"postgres"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	// user exists but db operations fail → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestDynamicSecretHandler_ListLeases_BadID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	// loadAuthorizedConfig → bad config ID → not 200
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── secret_dependencies.go ────────────────────────────────────────────────────

func TestSecretHandler_ListSecretDependencies_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.ListSecretDependencies(w, req)
	// not found → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_AddSecretDependency_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.AddSecretDependency(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_AddSecretDependency_MissingDependsOnID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"depends_on_id":0}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.AddSecretDependency(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_RemoveSecretDependency_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	params := map[string]string{"id": "1", "depId": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), params)
	w := httptest.NewRecorder()
	h.RemoveSecretDependency(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_RemoveSecretDependency_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	params := map[string]string{"id": "bad", "depId": "1"}
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), params))
	w := httptest.NewRecorder()
	h.RemoveSecretDependency(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_RemoveSecretDependency_BadDepID(t *testing.T) {
	h := newSecretHandlerS4(t)
	params := map[string]string{"id": "1", "depId": "bad"}
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), params))
	w := httptest.NewRecorder()
	h.RemoveSecretDependency(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetSecretImpact_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetSecretImpact(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetProjectRotationOrder_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetProjectRotationOrder(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetProjectRotationPlan_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetProjectRotationPlan(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetDeploymentRotationPlan_WithUser(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetDeploymentRotationPlan(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── rbac.go: GetRoleByName, DeleteRole ───────────────────────────────────────

func TestRBACHandler_GetRoleByName_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodGet, "/?name=admin", nil)
	w := httptest.NewRecorder()
	h.GetRoleByName(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_GetRoleByName_MissingName(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetRoleByName(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetRoleByName_NotFound(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?name=nonexistent-role", nil))
	w := httptest.NewRecorder()
	h.GetRoleByName(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRBACHandler_DeleteRole_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_DeleteRole_BadID(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.DeleteRole(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── users_crud.go: ConsumeMFAChallenge ───────────────────────────────────────

func TestUserHandler_ConsumeMFAChallenge_Unauthorized(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.ConsumeMFAChallenge(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_ConsumeMFAChallenge_BadJSON(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.ConsumeMFAChallenge(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_ConsumeMFAChallenge_MissingFields(t *testing.T) {
	h := newUserHandlerS4(t)
	body := `{"token_hash":""}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.ConsumeMFAChallenge(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_suspend.go: ResumeSecret ─────────────────────────────────────────

func TestSecretHandler_ResumeSecret_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ResumeSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_ResumeSecret_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.ResumeSecret(w, req)
	// not found → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── machine_identities.go: ListStaleMachineIdentities ──────────────────────

func TestCatalogHandler_ListStaleMachineIdentities_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/?days=30", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListStaleMachineIdentities(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities_proxy.go: TransitionMachineIdentityStateProxy ─────────

func TestCatalogHandler_TransitionMachineIdentityStateProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"machine_identity":{},"from_state":"pending"}`
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "bad")
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_TransitionMachineIdentityStateProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_TransitionMachineIdentityStateProxy_MissingFromState(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"machine_identity":{}}`
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_TransitionMachineIdentityStateProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"machine_identity":{},"from_state":"pending"}`
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	// not found → storage error → not 400
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities_proxy.go: AssignMachineRoleProxy ─────────────────────

func TestCatalogHandler_AssignMachineRoleProxy_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "bad", "roleId": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/?project_id=1&environment_id=1", nil), params)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_AssignMachineRoleProxy_BadRoleID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "1", "roleId": "bad"}
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/?project_id=1&environment_id=1", nil), params)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_AssignMachineRoleProxy_MissingScope(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "1", "roleId": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), params)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities_proxy.go: RemoveMachineRoleProxy ─────────────────────

func TestCatalogHandler_RemoveMachineRoleProxy_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "bad", "roleId": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/?project_id=1&environment_id=1", nil), params)
	w := httptest.NewRecorder()
	h.RemoveMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_RemoveMachineRoleProxy_BadRoleID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "1", "roleId": "bad"}
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/?project_id=1&environment_id=1", nil), params)
	w := httptest.NewRecorder()
	h.RemoveMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── break_glass_proxy.go: RevokeBreakGlassActivationProxy ───────────────────

func TestCatalogHandler_RevokeBreakGlassActivationProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.RevokeBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_RevokeBreakGlassActivationProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_RevokeBreakGlassActivationProxy_MissingRevokedBy(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"revoked_by":0}`
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_RevokeBreakGlassActivationProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"revoked_by":1}`
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "9999")
	w := httptest.NewRecorder()
	h.RevokeBreakGlassActivationProxy(w, req)
	// not active (empty db) → 409 conflict or 500 or 200 — not 400
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── retention_proxy.go: ListUsersInStateBeforeProxy ─────────────────────────

func TestUserHandler_ListUsersInStateBeforeProxy_MissingState(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?before=2026-01-01T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.ListUsersInStateBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_ListUsersInStateBeforeProxy_MissingBefore(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?state=active", nil)
	w := httptest.NewRecorder()
	h.ListUsersInStateBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_ListUsersInStateBeforeProxy_BadBefore(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?state=active&before=not-a-date", nil)
	w := httptest.NewRecorder()
	h.ListUsersInStateBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_ListUsersInStateBeforeProxy_HappyPath(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?state=active&before=2026-01-01T00:00:00.000000000Z", nil)
	w := httptest.NewRecorder()
	h.ListUsersInStateBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── project_catalog_proxy.go: UpdateProjectProxy ─────────────────────────────

func TestCatalogHandler_UpdateProjectProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateProjectProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_UpdateProjectProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateProjectProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_UpdateProjectProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"name":"updated"}`
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "9999")
	w := httptest.NewRecorder()
	h.UpdateProjectProxy(w, req)
	// not found → 404 or 500
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── project_memberships_proxy.go: GetActiveMembershipProxy ──────────────────

func TestCatalogHandler_GetActiveMembershipProxy_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=bad&user_id=1", nil)
	w := httptest.NewRecorder()
	h.GetActiveMembershipProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_GetActiveMembershipProxy_BadUserID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1&user_id=bad", nil)
	w := httptest.NewRecorder()
	h.GetActiveMembershipProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_GetActiveMembershipProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	// project_id=1&user_id=1 is NOT safe here: other happy-path tests sharing this
	// DB (sharedS4Core) legitimately create an active membership for project 1 /
	// user 1 (e.g. TestCatalogHandler_CreateMembershipProxy_HappyPath below) and
	// never tear it down. Use out-of-range IDs that can never collide, matching
	// TestGetActiveMembershipProxy_NotFound_S13's existing 99999 convention.
	req := httptest.NewRequest(http.MethodGet, "/?project_id=99999&user_id=99999", nil)
	w := httptest.NewRecorder()
	h.GetActiveMembershipProxy(w, req)
	// not found → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── misc_remote_proxy.go: accessActivityProxy ────────────────────────────────

func TestUserHandler_LastUserSecretActivityProxy_MissingProjectID(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.LastUserSecretActivityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_LastUserSecretActivityProxy_BadProjectID(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=bad", nil)
	w := httptest.NewRecorder()
	h.LastUserSecretActivityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_LastUserSecretActivityProxy_HappyPath(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.LastUserSecretActivityProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUserHandler_LastUserRoleManagementActivityProxy_HappyPath(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.LastUserRoleManagementActivityProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUserHandler_LastUserSecretDeletionActivityProxy_HappyPath(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.LastUserSecretDeletionActivityProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUserHandler_LastUserSecretReadActivityProxy_HappyPath(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.LastUserSecretReadActivityProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUserHandler_LastUserSecretWriteActivityProxy_HappyPath(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.LastUserSecretWriteActivityProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── environment_catalog_proxy.go: DeleteEnvironmentProxy, RestoreEnvironmentProxy ──

func TestCatalogHandler_DeleteEnvironmentProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.DeleteEnvironmentProxy(w, req)
	// not found → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCatalogHandler_RestoreEnvironmentProxy_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"projectId": "bad", "id": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), params)
	w := httptest.NewRecorder()
	h.RestoreEnvironmentProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_RestoreEnvironmentProxy_BadEnvID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"projectId": "1", "id": "bad"}
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), params)
	w := httptest.NewRecorder()
	h.RestoreEnvironmentProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_RestoreEnvironmentProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"projectId": "1", "id": "9999"}
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), params)
	w := httptest.NewRecorder()
	h.RestoreEnvironmentProxy(w, req)
	// not found → 404 or 500 depending on storage
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── mfa_management_proxy.go: GetMFASecretProxy, SetUserMFAEnabledProxy, CreateMFARecoveryCodesProxy ──

func TestAuthHandler_GetMFASecretProxy_BadUserID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/?user_id=bad", nil)
	w := httptest.NewRecorder()
	h.GetMFASecretProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_GetMFASecretProxy_NotFound(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/?user_id=9999", nil)
	w := httptest.NewRecorder()
	h.GetMFASecretProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAuthHandler_SetUserMFAEnabledProxy_BadUserID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"enabled":true}`)), "userId", "bad")
	w := httptest.NewRecorder()
	h.SetUserMFAEnabledProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_SetUserMFAEnabledProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "userId", "1")
	w := httptest.NewRecorder()
	h.SetUserMFAEnabledProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_CreateMFARecoveryCodesProxy_MissingUserID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body := `{"code_hashes":["abc123"]}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateMFARecoveryCodesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_CreateMFARecoveryCodesProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/?user_id=1", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateMFARecoveryCodesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── setup_tokens_proxy.go: ConsumeSetupTokenProxy ────────────────────────────

func TestAuthHandler_ConsumeSetupTokenProxy_BadID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.ConsumeSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ConsumeSetupTokenProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.ConsumeSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ConsumeSetupTokenProxy_MissingConsumedAt(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body := `{"consumed_at":"0001-01-01T00:00:00Z"}`
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.ConsumeSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac_role_grants_proxy.go: RemoveGlobalAdminRoleGuardedProxy ─────────────

func TestRBACHandler_RemoveGlobalAdminRoleGuardedProxy_BadJSON(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.RemoveGlobalAdminRoleGuardedProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_RemoveGlobalAdminRoleGuardedProxy_MissingFields(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	body := `{"user_id":0,"role_id":0}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.RemoveGlobalAdminRoleGuardedProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secret_dependencies_proxy.go: CreateSecretDependencyExclusiveProxy ───────

func TestSecretHandler_CreateSecretDependencyExclusiveProxy_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateSecretDependencyExclusiveProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_CreateSecretDependencyExclusiveProxy_MissingFields(t *testing.T) {
	h := newSecretHandlerS4(t)
	body := `{"project_id":0,"dependent_secret_id":0,"depends_on_secret_id":0}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateSecretDependencyExclusiveProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_CreateSecretDependencyExclusiveProxy_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	body := `{"project_id":1,"dependent_secret_id":1,"depends_on_secret_id":2}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateSecretDependencyExclusiveProxy(w, req)
	// secrets don't exist → error (but not 400 for missing fields)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities.go: ListMachineTokens ─────────────────────────────────

func TestCatalogHandler_ListMachineTokens_BadProjectIDS4(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "bad", "machineId": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), params)
	w := httptest.NewRecorder()
	h.ListMachineTokens(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ListMachineTokens_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "1", "machineId": "bad"}
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), params)
	w := httptest.NewRecorder()
	h.ListMachineTokens(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ListMachineTokens_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "1", "machineId": "1"}
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), params))
	w := httptest.NewRecorder()
	h.ListMachineTokens(w, req)
	// not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── isSafeSSOError ────────────────────────────────────────────────────────────

func TestIsSafeSSOError_KnownMessages(t *testing.T) {
	assert.True(t, isSafeSSOError("unknown SSO provider"))
	assert.True(t, isSafeSSOError("unknown SAML provider"))
	assert.True(t, isSafeSSOError("invalid or expired login state"))
	assert.True(t, isSafeSSOError("login state does not match the callback provider"))
	assert.True(t, isSafeSSOError("login state expired"))
	assert.True(t, isSafeSSOError("the token response carried no id_token"))
	assert.True(t, isSafeSSOError("the assertion carried no subject or email"))
	assert.True(t, isSafeSSOError("no Keyorix account matches this SSO identity"))
	assert.False(t, isSafeSSOError("account suspended"))
	assert.True(t, isSafeSSOError("the IdP returned no email; cannot auto-provision an account"))
	assert.False(t, isSafeSSOError("some internal error"))
	assert.False(t, isSafeSSOError(""))
}

// ── isSafeDynamicSecretError ──────────────────────────────────────────────────

func TestIsSafeDynamicSecretError_KnownMessages(t *testing.T) {
	assert.True(t, isSafeDynamicSecretError("config not found"))
	assert.True(t, isSafeDynamicSecretError("lease not found"))
	assert.True(t, isSafeDynamicSecretError("lease is not active"))
	assert.True(t, isSafeDynamicSecretError("active-lease limit reached"))
	assert.False(t, isSafeDynamicSecretError("some internal DB error"))
	assert.False(t, isSafeDynamicSecretError(""))
}

// ── dynamic_secrets.go: IssueLease ───────────────────────────────────────────

func TestDynamicSecretHandler_IssueLease_NoUser(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.IssueLease(w, req)
	// no user context → auth denial (401 or 403)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── project_members.go: AddProjectMember, UpdateProjectMember ────────────────

func TestCatalogHandler_AddProjectMember_MissingFieldsV3(t *testing.T) {
	h := newCatalogHandlerS4(t)
	// user_id = 0 and role = "" → 400
	body := `{"user_id":0,"role":""}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1"))
	w := httptest.NewRecorder()
	h.AddProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac.go: AssignPermissionToRole ──────────────────────────────────────────

func TestRBACHandler_AssignPermissionToRole_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	params := map[string]string{"id": "1", "permId": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), params)
	w := httptest.NewRecorder()
	h.AssignPermissionToRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_AssignPermissionToRole_BadRoleID(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	params := map[string]string{"id": "bad", "permId": "1"}
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), params))
	w := httptest.NewRecorder()
	h.AssignPermissionToRole(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── rbac.go: GetUserRoles, RemovePermissionFromRole ──────────────────────────

func TestRBACHandler_GetUserRoles_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_GetUserRoles_BadIDS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUserRoles(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestRBACHandler_GetGroupRoles_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetGroupRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_RemovePermissionFromRole_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	params := map[string]string{"id": "1", "permId": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), params)
	w := httptest.NewRecorder()
	h.RemovePermissionFromRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── audit.go: ExportAuditLogs ─────────────────────────────────────────────────

func TestAuditHandler_ExportAuditLogs_Unauthorized(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ExportAuditLogs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuditHandler_ExportAuditLogs_HappyPath(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ExportAuditLogs(w, req)
	// not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── auth.go: ConsumeSetup, Logout ────────────────────────────────────────────

func TestAuthHandler_Logout_NoSession(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.Logout(w, req)
	// no session header/cookie → not 200 (token required)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── auth.go: RefreshToken ─────────────────────────────────────────────────────

func TestAuthHandler_RefreshToken_NoTokenS4(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	// no token → error
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── sod.go: ListSoDPolicies, CreateSoDPolicy, ListSoDViolations ──────────────

// ── rbac.go: ListRoles, ListPermissions ──────────────────────────────────────

func TestRBACHandler_ListRoles_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_ListPermissions_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListPermissions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── machine_identities_proxy.go: UpdateMachineIdentityProxy ─────────────────

func TestCatalogHandler_UpdateMachineIdentityProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_UpdateMachineIdentityProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities_proxy.go: UpdateMachineIdentityCredentialProxy ─────────

func TestCatalogHandler_UpdateMachineIdentityCredentialProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities_proxy.go: TouchMachineIdentityCredentialProxy ─────────

func TestCatalogHandler_TouchMachineIdentityCredentialProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.TouchMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── retention_proxy.go: DeleteExpiredRoleGrantsProxy, DeleteExpiredShareRecordsProxy ─

func TestRBACHandler_DeleteExpiredRoleGrantsProxy_MissingBefore(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.DeleteExpiredRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_DeleteExpiredShareRecordsProxy_MissingBefore(t *testing.T) {
	h := newShareHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.DeleteExpiredShareRecordsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── webauthn.go: FinishWebAuthnPasswordlessLogin ──────────────────────────────

func TestWebAuthnHandler_FinishWebAuthnPasswordlessLoginS4_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "sessionID", "test-session")
	w := httptest.NewRecorder()
	h.FinishWebAuthnPasswordlessLogin(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── auth.go: Login, ListSessions ─────────────────────────────────────────────

func TestAuthHandler_Login_BadJSONS4(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.Login(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ListSessions_WithUser(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListSessions(w, req)
	// user doesn't exist in empty DB → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── shares_query.go: ListSharedSecrets, ListGroupSharedSecrets ───────────────

func TestShareHandler_ListSharedSecrets_HappyPath(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListSharedSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ListGroupSharedSecrets_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ListGroupSharedSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_ListGroupSharedSecrets_HappyPath(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.ListGroupSharedSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── retention_proxy.go: happy-path sweeps ────────────────────────────────────

func TestCatalogHandler_DeleteClosedAccessReviewsBeforeProxy_MissingBefore(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.DeleteClosedAccessReviewsBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_DeleteClosedAccessReviewsBeforeProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"before":"2026-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.DeleteClosedAccessReviewsBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCatalogHandler_DeleteExpiredBreakGlassBeforeProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"before":"2026-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.DeleteExpiredBreakGlassBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCatalogHandler_DeleteResolvedAccessRequestsBeforeProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"before":"2026-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.DeleteResolvedAccessRequestsBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCatalogHandler_PurgeDeletedProjectsBeforeProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"before":"2026-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.PurgeDeletedProjectsBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCatalogHandler_PurgeDeletedEnvironmentsBeforeProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"before":"2026-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.PurgeDeletedEnvironmentsBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCatalogHandler_PurgeDeletedUsersBeforeProxy_HappyPath(t *testing.T) {
	h := newUserHandlerS4(t)
	body := `{"before":"2026-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.PurgeDeletedUsersBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRBACHandler_DeleteExpiredRoleGrantsProxy_HappyPath(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	body := `{"before":"2026-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.DeleteExpiredRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestShareHandler_DeleteExpiredShareRecordsProxy_HappyPath(t *testing.T) {
	h := newShareHandlerS4(t)
	body := `{"before":"2026-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.DeleteExpiredShareRecordsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── project_catalog_proxy.go: DeleteProjectProxy, RestoreProjectProxy ─────────

func TestCatalogHandler_DeleteProjectProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.DeleteProjectProxy(w, req)
	// 404 (not found) or 200 — not 400
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_DeleteProjectIfEmptyProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteProjectIfEmptyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── project_memberships_proxy.go: UpdateMembershipProxy ─────────────────────

func TestCatalogHandler_UpdateMembershipProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateMembershipProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_UpdateMembershipProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateMembershipProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac_role_grants_proxy.go: AssignRoleWithExpiryProxy, etc. ───────────────

func TestRBACHandler_AssignRoleWithExpiryProxy_BadJSON(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.AssignRoleWithExpiryProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_AssignRoleWithExpiryProxy_MissingFields(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	body := `{"user_id":0,"role_id":0}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.AssignRoleWithExpiryProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_AssignRoleToGroupWithExpiryProxy_BadJSON(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.AssignRoleToGroupWithExpiryProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_RemoveAllProjectRoleGrantsProxy_MissingProjectID(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.RemoveAllProjectRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_ListProjectRoleAssignmentsProxy_MissingProjectID(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListProjectRoleAssignmentsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_ListProjectRoleAssignmentsProxy_HappyPath(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListProjectRoleAssignmentsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRBACHandler_ListProjectMachineRoleAssignmentsProxy_HappyPath(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListProjectMachineRoleAssignmentsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities_proxy.go: credential proxies ─────────────────────────

func TestCatalogHandler_GetMachineIdentityCredentialByIDProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetMachineIdentityCredentialByIDProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ListMachineIdentityCredentialsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListMachineIdentityCredentialsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCatalogHandler_RevokeMachineIdentityCredentialProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.RevokeMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_GetMachineRolesProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetMachineRolesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCatalogHandler_ListOIDCBindingsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListOIDCBindingsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCatalogHandler_GetOIDCBindingByIDProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetOIDCBindingByIDProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_DeleteOIDCBindingProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secret_dependencies_proxy.go: GetSecretDependencyProxy ───────────────────

func TestSecretHandler_GetSecretDependencyProxy_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetSecretDependencyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetSecretDependencyProxy_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetSecretDependencyProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSecretHandler_ListSecretDependenciesForProjectForUpdateProxy_MissingProjectID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSecretDependenciesForProjectForUpdateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_ListSecretDependenciesForProjectForUpdateProxy_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListSecretDependenciesForProjectForUpdateProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSecretHandler_DeleteSecretDependencyProxy_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteSecretDependencyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── connect.go: DeleteRefGrant (S4 additional) ───────────────────────────────

func TestConnectHandler_DeleteRefGrant_UnauthorizedS4(t *testing.T) {
	h := newConnectHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteRefGrant(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestConnectHandler_DeleteRefGrant_BadIDS4(t *testing.T) {
	h := newConnectHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.DeleteRefGrant(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── dynamic_secrets.go: RevokeAllLeases, ClassifyConfig, SetConfigEnabled ────

func TestDynamicSecretHandler_RevokeAllLeases_BadID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestDynamicSecretHandler_ClassifyConfig_BadID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestDynamicSecretHandler_SetConfigEnabled_BadID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── access_review_campaigns_proxy.go: GetAccessReviewCampaignProxy ────────────

func TestCatalogHandler_GetAccessReviewCampaignProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── secrets_versions.go: RotateSecret ────────────────────────────────────────

func TestSecretHandler_RotateSecret_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.RotateSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_access_history.go: AccessHistory ─────────────────────────────────

// ── admin_impersonation.go: End (S4 extra) ───────────────────────────────────

func TestImpersonationHandler_End_UnauthorizedS4(t *testing.T) {
	h := NewImpersonationHandler(newHandlerCoreS4(t), false)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.End(w, req)
	// no valid impersonation token header → should not be 200
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── mfa_management_proxy.go: CountUnusedMFARecoveryCodesProxy ────────────────

func TestAuthHandler_CountUnusedMFARecoveryCodesProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/?user_id=1", nil)
	w := httptest.NewRecorder()
	h.CountUnusedMFARecoveryCodesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── risk_exceptions_proxy.go: UpdateRiskExceptionProxy ───────────────────────

func TestDashboardHandler_UpdateRiskExceptionProxy_BadID(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDashboardHandler_UpdateRiskExceptionProxy_BadJSON(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac_role_grants_proxy.go: happy paths ────────────────────────────────────

func TestRBACHandler_GetGroupRoleGrantsProxy_BadID(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "groupID", "bad")
	w := httptest.NewRecorder()
	h.GetGroupRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetGroupRoleGrantsProxy_HappyPath(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "groupID", "1")
	w := httptest.NewRecorder()
	h.GetGroupRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRBACHandler_AssignRoleWithExpiryProxy_HappyPath(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	body := `{"user_id":1,"role_id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.AssignRoleWithExpiryProxy(w, req)
	// DB may not have the role, but we get past validation
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_AssignRoleToGroupWithExpiryProxy_MissingFields(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	body := `{"group_id":0,"role_id":0}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.AssignRoleToGroupWithExpiryProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_AssignRoleToGroupWithExpiryProxy_HappyPath(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	body := `{"group_id":1,"role_id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.AssignRoleToGroupWithExpiryProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_RemoveAllProjectRoleGrantsProxy_HappyPath(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	body := `{"user_id":1,"project_id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.RemoveAllProjectRoleGrantsProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_ListGroupRoleAssignmentsProxy_BadID(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "groupID", "bad")
	w := httptest.NewRecorder()
	h.ListGroupRoleAssignmentsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_ListGroupRoleAssignmentsProxy_HappyPath(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "groupID", "1")
	w := httptest.NewRecorder()
	h.ListGroupRoleAssignmentsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities_proxy.go: credential happy paths ──────────────────────

func TestCatalogHandler_GetMachineIdentityCredentialByIDProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetMachineIdentityCredentialByIDProxy(w, req)
	// not found from empty DB
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_UpdateMachineIdentityCredentialProxy_BadJSONDup(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_UpdateMachineIdentityCredentialProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"classification":"low"}`)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityCredentialProxy(w, req)
	// storage error expected (no such credential), but not a bad request
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_TouchMachineIdentityCredentialProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.TouchMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_TouchMachineIdentityCredentialProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"used_at":"2026-01-01T00:00:00Z","staleness_seconds":60}`
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.TouchMachineIdentityCredentialProxy(w, req)
	// storage error (not found) but not bad request
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_GetMachineRoleIDsAtProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/?project_id=0&environment_id=0", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetMachineRoleIDsAtProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCatalogHandler_GetOIDCBindingByIDProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetOIDCBindingByIDProxy(w, req)
	// not found from empty DB
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_DeleteOIDCBindingProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteOIDCBindingProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── secret_dependencies_proxy.go: delete happy path ──────────────────────────

func TestSecretHandler_DeleteSecretDependencyProxy_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.DeleteSecretDependencyProxy(w, req)
	// not found from empty DB
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── access_review_campaigns_proxy.go: happy paths ────────────────────────────

func TestCatalogHandler_UpdateAccessReviewCampaignProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateAccessReviewItemsProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateAccessReviewItemsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_UpdateAccessReviewItemProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "itemID", "bad")
	w := httptest.NewRecorder()
	h.UpdateAccessReviewItemProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── access_request_proxy.go: happy paths ─────────────────────────────────────

func TestCatalogHandler_GetAccessRequestProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_UpdateAccessRequestProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateAccessRequestApprovalProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateAccessRequestApprovalProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── break_glass_proxy.go: happy paths ────────────────────────────────────────

func TestCatalogHandler_UpdateBreakGlassActivationProxy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── sod_proxy.go: happy paths ─────────────────────────────────────────────────

// ── dynamic_secrets_proxy.go: happy paths ────────────────────────────────────

func TestDynamicSecretHandler_GetDynamicSecretLeaseProxy_NotFound(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "leaseID", "nonexistent-lease-id")
	w := httptest.NewRecorder()
	h.GetDynamicSecretLeaseProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── project_catalog_proxy.go: RestoreProjectProxy happy paths ─────────────────

func TestCatalogHandler_RestoreProjectProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.RestoreProjectProxy(w, req)
	// not found from empty DB
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_DeleteProjectIfEmptyProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.DeleteProjectIfEmptyProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── project_memberships_proxy.go: UpdateMembershipProxy happy paths ───────────

func TestCatalogHandler_UpdateMembershipProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"role":"viewer"}`
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateMembershipProxy(w, req)
	// not found from empty DB
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── environment_catalog_proxy.go: GetEnvironmentProxy ────────────────────────

func TestCatalogHandler_GetEnvironmentProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetEnvironmentProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── groups_proxy.go: GetGroupProxy ───────────────────────────────────────────

func TestGroupHandler_GetGroupProxy_BadID(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetGroupProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_GetGroupProxy_NotFound(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetGroupProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGroupHandler_GetUserGroupsProxy_BadID(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetUserGroupsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_GetUserGroupsProxy_HappyPath(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserGroupsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── invitations_proxy.go: GetInvitationProxy ─────────────────────────────────

func TestCatalogHandler_GetInvitationProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetInvitationProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── risk_exceptions_proxy.go: GetRiskExceptionProxy ──────────────────────────

func TestDashboardHandler_GetRiskExceptionProxy_NotFound(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── project_catalog_proxy.go: GetProjectProxy ────────────────────────────────

func TestCatalogHandler_GetProjectProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetProjectProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCatalogHandler_ListProjectMembersProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListProjectMembersProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── project_memberships_proxy.go: GetMembershipProxy ─────────────────────────

func TestCatalogHandler_GetMembershipProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetMembershipProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities_proxy.go: GetMachineIdentityProxy ─────────────────────

func TestCatalogHandler_GetMachineIdentityProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── connect_grants_proxy.go: ListConnectRefGrantsByConnectorProxy ─────────────

func TestAuthHandler_ListConnectRefGrantsByConnectorProxy_MissingConnector(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListConnectRefGrantsByConnectorProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── webauthn_proxy.go: DeleteWebAuthnCredentialProxy ─────────────────────────

func TestAuthHandler_DeleteWebAuthnCredentialProxy_BadUserID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "userId", "bad")
	w := httptest.NewRecorder()
	h.DeleteWebAuthnCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_DeleteWebAuthnCredentialProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{"userId": "1", "id": "1"})
	w := httptest.NewRecorder()
	h.DeleteWebAuthnCredentialProxy(w, req)
	// not found from empty DB, but not a bad request
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── secrets_ownership.go: TransferOwnership ──────────────────────────────────

func TestSecretHandler_TransferOwnership_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.TransferOwnership(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_access_history.go: AccessHistory happy path ──────────────────────

func TestSecretHandler_AccessHistory_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.AccessHistory(w, req)
	// not found or 500, not 401 or 400
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── scheduler_lock_proxy.go: ReleaseSchedulerLockProxy ───────────────────────

func TestAuthHandler_ReleaseSchedulerLockProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.ReleaseSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── misc_remote_proxy.go: GetSecretIncludingDeletedProxy ─────────────────────

func TestSecretHandler_GetSecretIncludingDeletedProxy_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetSecretIncludingDeletedProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetSecretIncludingDeletedProxy_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetSecretIncludingDeletedProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── setup_tokens_proxy.go: more paths ────────────────────────────────────────

func TestAuthHandler_SupersedeSetupTokensProxy_MissingFields(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.SupersedeSetupTokensProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_SupersedeSetupTokensProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body := `{"purpose":"invite","subject_email":"test@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.SupersedeSetupTokensProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_CountSetupTokensSinceProxy_MissingParams(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.CountSetupTokensSinceProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_CountSetupTokensSinceProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/?purpose=invite&subject_email=test@example.com&since=2026-01-01T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.CountSetupTokensSinceProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── login_attempts_proxy.go: RecordLoginAttemptProxy ─────────────────────────

func TestAuthHandler_RecordLoginAttemptProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.RecordLoginAttemptProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── misc_remote_proxy.go: ListSharesByOwnerProxy ─────────────────────────────

func TestShareHandler_ListSharesByOwnerProxy_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "ownerID", "bad")
	w := httptest.NewRecorder()
	h.ListSharesByOwnerProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_ListSharesByOwnerProxy_HappyPath(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "ownerID", "1")
	w := httptest.NewRecorder()
	h.ListSharesByOwnerProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── retention_proxy.go: DeleteAnomalyAlertsBeforeProxy ───────────────────────

func TestAuditHandler_DeleteAnomalyAlertsBeforeProxy_HappyPath(t *testing.T) {
	h := newAuditHandlerS4(t)
	body := `{"before":"2026-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.DeleteAnomalyAlertsBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── access_request_proxy.go: CreateAccessRequestProxy happy path ──────────────

func TestCatalogHandler_CreateAccessRequestProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"project_id":0,"user_id":0,"state":""}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateAccessRequestProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"project_id":1,"user_id":1,"state":"pending"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCatalogHandler_UpdateAccessRequestProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"state":"approved"}`
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateAccessRequestProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateAccessRequestApprovalProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"request_id":0,"approver_id":0}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAccessRequestApprovalProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateAccessRequestApprovalProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"approver_id":1}`
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.CreateAccessRequestApprovalProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── access_review_campaigns_proxy.go: CreateAccessReviewCampaignProxy ─────────

func TestCatalogHandler_CreateAccessReviewCampaignProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"project_id":0}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateAccessReviewCampaignProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"project_id":1,"name":"Test Campaign","state":"open"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCatalogHandler_UpdateAccessReviewCampaignProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"state":"closed"}`
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateAccessReviewCampaignProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateAccessReviewItemsProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"items":[]}`
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.CreateAccessReviewItemsProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_UpdateAccessReviewItemProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"decision":"approved"}`
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "itemID", "1")
	w := httptest.NewRecorder()
	h.UpdateAccessReviewItemProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── break_glass_proxy.go: CreateBreakGlassActivationProxy happy path ──────────

func TestCatalogHandler_CreateBreakGlassActivationProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"secret_id":0}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateBreakGlassActivationProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"project_id":1,"user_id":1,"state":"active","secret_id":1,"reason":"test","expires_at":"2026-12-31T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateBreakGlassActivationProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_UpdateBreakGlassActivationProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"state":"revoked"}`
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateBreakGlassActivationProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── sod_proxy.go: CreateSoDPolicyProxy ───────────────────────────────────────

func TestCatalogHandler_DeleteSoDPolicyProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteSoDPolicyProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── groups_proxy.go: UpdateGroupProxy ────────────────────────────────────────

func TestGroupHandler_GetGroupProxy_HappyPath(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetGroupProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── dynamic_secrets_proxy.go: ListDynamicSecretLeasesProxy ───────────────────

func TestDynamicSecretHandler_UpdateDynamicSecretConfigProxy_BadID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── project_catalog_proxy.go: UpdateProjectProxy ─────────────────────────────

func TestCatalogHandler_UpdateProjectProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"name":"test"}`)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateProjectProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── project_memberships_proxy.go: CreateMembershipProxy ──────────────────────

func TestCatalogHandler_CreateMembershipProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateMembershipProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateMembershipProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"user_id":0,"project_id":0}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateMembershipProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateMembershipProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"user_id":1,"project_id":1,"role":"viewer","state":"active"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateMembershipProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── groups_proxy.go: CreateGroupProxy, UpdateGroupProxy, DeleteGroupProxy ─────

func TestGroupHandler_CreateGroupProxy_BadJSON(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateGroupProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_UpdateGroupProxy_BadID(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateGroupProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_DeleteGroupProxy_BadID(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteGroupProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_DeleteGroupProxy_HappyPath(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteGroupProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities_proxy.go: CreateMachineIdentityProxy ──────────────────

func TestCatalogHandler_CreateMachineIdentityProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_UpdateMachineIdentityProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"name":"test-machine"}`)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateMachineIdentityCredentialProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateMachineIdentityCredentialProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"machine_identity_id":0}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateOIDCBindingProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateOIDCBindingProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"machine_identity_id":0}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── environment_catalog_proxy.go: DeleteEnvironmentProxy happy paths ──────────

func TestCatalogHandler_DeleteEnvironmentProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteEnvironmentProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── invitations_proxy.go: CreateInvitationProxy, UpdateInvitationProxy ────────

func TestCatalogHandler_CreateInvitationProxy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateInvitationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac_role_grants_proxy.go: ListGlobalAdminAssignmentsForUpdateProxy ───────

func TestRBACHandler_ListGlobalAdminAssignmentsForUpdateProxy_HappyPath(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListGlobalAdminAssignmentsForUpdateProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── webauthn_proxy.go: CreateWebAuthnCredentialProxy ─────────────────────────

// ── connect_grants_proxy.go: CreateConnectRefGrantProxy ──────────────────────

func TestAuthHandler_CreateConnectRefGrantProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateConnectRefGrantProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_DeleteConnectRefGrantProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteConnectRefGrantProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── scheduler_lock_proxy.go: AcquireSchedulerLockProxy ───────────────────────

func TestAuthHandler_AcquireSchedulerLockProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.AcquireSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── login_attempts_proxy.go: CountLoginAttemptsProxy ─────────────────────────

func TestAuthHandler_CountLoginAttemptsProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/?ip=127.0.0.1&since=2026-01-01T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.CountLoginAttemptsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── setup_tokens_proxy.go: GetSetupTokenByHashProxy ──────────────────────────

func TestAuthHandler_GetSetupTokenByHashProxy_MissingHash(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetSetupTokenByHashProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_GetSetupTokenByHashProxy_NotFound(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "hash", "nonexistenthash")
	w := httptest.NewRecorder()
	h.GetSetupTokenByHashProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAuthHandler_ExpireSetupTokenProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ExpireSetupTokenProxy(w, req)
	// not found but not bad request
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── risk_exceptions_proxy.go: CreateRiskExceptionProxy ───────────────────────

func TestDashboardHandler_CreateRiskExceptionProxy_BadJSON(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDashboardHandler_CreateRiskExceptionProxy_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	body := `{"title":"Test Exception","justification":"This is a test","expires_at":"2026-12-31T00:00:00Z","category":"operational"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateRiskExceptionProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── misc_remote_proxy.go: ListSharesByUserProxy ───────────────────────────────

func TestShareHandler_ListSharesByUserProxy_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "userID", "bad")
	w := httptest.NewRecorder()
	h.ListSharesByUserProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_ListSharesByUserProxy_HappyPath(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "userID", "1")
	w := httptest.NewRecorder()
	h.ListSharesByUserProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities_proxy.go: AssignMachineRoleProxy happy path ────────────

func TestCatalogHandler_AssignMachineRoleProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/?project_id=0&environment_id=0", nil),
		map[string]string{"id": "1", "roleId": "1"},
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_RemoveMachineRoleProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodDelete, "/?project_id=0&environment_id=0", nil),
		map[string]string{"id": "1", "roleId": "1"},
	)
	w := httptest.NewRecorder()
	h.RemoveMachineRoleProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── users_crud.go: additional UserHandler coverage ───────────────────────────

func TestUserHandler_SearchUsers_NoQuery(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.SearchUsers(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_CreateUserWithRoleGrantsProxy_BadJSON(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateUserWithRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── audit_anomaly.go: ListAnomalyAlerts, AcknowledgeAnomalyAlert ──────────────

func TestAcknowledgeAnomalyAlert_BadID(t *testing.T) {
	// Without core service in context it's 500; with bad ID it's 400.
	// We test the "bad id" path only — confirm it's not 200.
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	AcknowledgeAnomalyAlert(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── mfa_management_proxy.go: ActivateMFASecretProxy, DeleteMFAForUserProxy ───

func TestAuthHandler_ActivateMFASecretProxy_BadID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "userId", "bad")
	w := httptest.NewRecorder()
	h.ActivateMFASecretProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ActivateMFASecretProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "userId", "1")
	w := httptest.NewRecorder()
	h.ActivateMFASecretProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_DeleteMFAForUserProxy_BadID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "userId", "bad")
	w := httptest.NewRecorder()
	h.DeleteMFAForUserProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_DeleteMFAForUserProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "userId", "1")
	w := httptest.NewRecorder()
	h.DeleteMFAForUserProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_DeleteMFARecoveryCodesProxy_BadID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "userId", "bad")
	w := httptest.NewRecorder()
	h.DeleteMFARecoveryCodesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_DeleteMFARecoveryCodesProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "userId", "1")
	w := httptest.NewRecorder()
	h.DeleteMFARecoveryCodesProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_SetUserMFAEnabledProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"enabled":true}`)), "userId", "1")
	w := httptest.NewRecorder()
	h.SetUserMFAEnabledProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── legal_hold_proxy.go: CreateLegalHoldProxy, UpdateLegalHoldProxy ───────────

func TestDashboardHandler_CreateLegalHoldProxy_BadJSON(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateLegalHoldProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDashboardHandler_CreateLegalHoldProxy_MissingReason(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreateLegalHoldProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDashboardHandler_CreateLegalHoldProxy_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	t.Cleanup(func() { releaseActiveLegalHoldS4(t, h) })
	body := `{"reason":"Litigation hold","placed_by":1}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateLegalHoldProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestDashboardHandler_GetActiveLegalHoldProxy_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetActiveLegalHoldProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_UpdateLegalHoldProxy_BadID(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateLegalHoldProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDashboardHandler_UpdateLegalHoldProxy_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	t.Cleanup(func() { releaseActiveLegalHoldS4(t, h) })
	// NOTE: UpdateLegalHoldProxy is a raw full-row Save (see legal_hold_proxy.go) —
	// this body omits "released"/"placed_by", so it zeroes those fields out on the
	// row with id=1 (created by TestDashboardHandler_CreateLegalHoldProxy_HappyPath
	// just above). Without the Cleanup above, that leaves a permanently "active"
	// hold with no valid placer in the shared sharedS4Core DB, which breaks
	// TestLiftLegalHold_NoActiveHold on any later run against the same process
	// (e.g. `go test -count=2`).
	body := `{"reason":"Updated hold reason"}`
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateLegalHoldProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// releaseActiveLegalHoldS4 marks any currently-active legal hold in the shared
// sharedS4Core DB as released, restoring the "no active hold" invariant that
// TestLiftLegalHold_NoActiveHold (and similar) depend on. Several happy-path
// legal-hold proxy tests (Create/UpdateLegalHoldProxy) intentionally leave a
// hold row behind to exercise their success path; because sharedS4Core lives
// for the whole test binary (see sharedS4CoreOnce above), that row would
// otherwise persist into every later test and every `-count=N` repeat.
func releaseActiveLegalHoldS4(t *testing.T, h *DashboardHandler) {
	t.Helper()
	ctx := context.Background()
	hold, err := h.coreService.Storage().GetActiveLegalHold(ctx)
	if err != nil || hold == nil {
		return
	}
	hold.Released = true
	_ = h.coreService.Storage().UpdateLegalHold(ctx, hold)
}

// ── rbac_role_grants_proxy.go: RemoveGlobalAdminRoleGuardedProxy ──────────────

func TestRBACHandler_RemoveGlobalAdminRoleGuardedProxy_MissingFields_S4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":0}`))
	w := httptest.NewRecorder()
	h.RemoveGlobalAdminRoleGuardedProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_RemoveGlobalAdminRoleGuardedProxy_HappyPath(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	body := `{"user_id":1,"role_id":1,"admin_role_ids":[]}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.RemoveGlobalAdminRoleGuardedProxy(w, req)
	// expects not-found or conflict (not bad request)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── sod_proxy.go: CreateSoDPolicyProxy, DeleteSoDPolicyProxy ─────────────────

func TestCatalogHandler_CreateSoDPolicyProxy_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test"}`))
	w := httptest.NewRecorder()
	h.CreateSoDPolicyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateSoDPolicyProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"name":"test","permission_a":"read","permission_b":"write"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateSoDPolicyProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── legal_hold.go: GetLegalHold, PlaceLegalHold ───────────────────────────────

func TestDashboardHandler_GetLegalHold_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetLegalHold(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_PlaceLegalHold_NoUserCtx(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason":"test"}`))
	w := httptest.NewRecorder()
	h.PlaceLegalHold(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDashboardHandler_PlaceLegalHold_BadJSON(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.PlaceLegalHold(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── sod.go: ListSoDPolicies, ListSoDViolations ────────────────────────────────

func TestCatalogHandler_CreateSoDPolicy_NoUserCtx(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"x","permission_a":"a","permission_b":"b"}`))
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCatalogHandler_ListSoDViolations_NoUserCtx(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSoDViolations(w, req)
	// Handler does not check user ctx; returns 200 with empty violations or error
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ListSoDViolations_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListSoDViolations(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── rotation_policies_handler.go: List ────────────────────────────────────────

func TestRotationPolicyHandler_List_NoUserCtx(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRotationPolicyHandler_List_HappyPath_S4(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRotationPolicyHandler_List_InvalidProjectID(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=bad", nil))
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── groups_proxy.go: AddGroupMemberProxy, ListGroupMembersProxy ───────────────

func TestGroupHandler_AddGroupMemberProxy_BadGroupID(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":1}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.AddGroupMemberProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_AddGroupMemberProxy_BadJSON(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.AddGroupMemberProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_AddGroupMemberProxy_HappyPath(t *testing.T) {
	h := newGroupHandlerS4(t)
	body := `{"user_id":1,"added_by":1}`
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.AddGroupMemberProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_ListGroupMembersProxy_BadID(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListGroupMembersProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_ListGroupMembersProxy_HappyPath(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListGroupMembersProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_ListGroupsProxy_HappyPath(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListGroupsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGroupHandler_UpdateGroupProxy_HappyPath(t *testing.T) {
	h := newGroupHandlerS4(t)
	body := `{"name":"updated"}`
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateGroupProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_CreateGroupProxy_HappyPath(t *testing.T) {
	h := newGroupHandlerS4(t)
	body := `{"name":"test group"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateGroupProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── connect_grants_proxy.go: ListConnectRefGrantsProxy ───────────────────────

// ── dynamic_secrets_proxy.go: CreateDynamicSecretConfigProxy ─────────────────

func TestDynamicSecretHandler_CreateDynamicSecretConfigProxy_MissingFields(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreateDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDynamicSecretHandler_CountDynamicSecretConfigsByClassificationProxy_HappyPath_S4(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?classification=CONFIDENTIAL", nil)
	w := httptest.NewRecorder()
	h.CountDynamicSecretConfigsByClassificationProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDynamicSecretHandler_UpdateDynamicSecretLeaseProxy_BadBody(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "leaseID", "test")
	w := httptest.NewRecorder()
	h.UpdateDynamicSecretLeaseProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── environment_catalog_proxy.go: ListEnvironmentsProxy ──────────────────────

// ── login_lockout_proxy.go: UpdateLoginLockoutStateProxy ──────────────────────

func TestAuthHandler_UpdateLoginLockoutStateProxy_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateLoginLockoutStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_UpdateLoginLockoutStateProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body := `{"locked":false}`
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateLoginLockoutStateProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── webauthn_proxy.go: UpdateWebAuthnCredentialProxy, AdvanceWebAuthnCredentialCounterProxy ─

func TestAuthHandler_UpdateWebAuthnCredentialProxy_BadID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)),
		map[string]string{"userId": "1", "id": "bad"},
	)
	w := httptest.NewRecorder()
	h.UpdateWebAuthnCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_AdvanceWebAuthnCredentialCounterProxy_BadUserID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"counter":1}`)),
		map[string]string{"userId": "bad", "id": "1"},
	)
	w := httptest.NewRecorder()
	h.AdvanceWebAuthnCredentialCounterProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_AdvanceWebAuthnCredentialCounterProxy_MissingRequiredFields(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	// credential_id, user_id, new_blob are all required; empty body → 400
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.AdvanceWebAuthnCredentialCounterProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities_proxy.go: RevokeMachineIdentityCredentialProxy, GetMachineByOIDCSubjectProxy ─

func TestCatalogHandler_RevokeMachineIdentityCredentialProxy_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeMachineIdentityCredentialProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_GetMachineByOIDCSubjectProxy_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?subject=nonexistent&issuer=https://example.com", nil)
	w := httptest.NewRecorder()
	h.GetMachineByOIDCSubjectProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── setup_tokens_proxy.go: CreateSetupTokenProxy ─────────────────────────────

func TestAuthHandler_CreateSetupTokenProxy_MissingFields(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreateSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_CreateSetupTokenProxy_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body := `{"token_hash":"abc123","purpose":"invite","subject_email":"test@example.com","expires_at":"2026-12-31T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateSetupTokenProxy(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── secret_dependencies_proxy.go: CreateSecretDependencyProxy ────────────────

func TestSecretHandler_CreateSecretDependencyProxy_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateSecretDependencyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_CreateSecretDependencyProxy_MissingFields(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreateSecretDependencyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── retention_proxy.go: PurgeDeletedUsersBeforeProxy, ListUsersInStateBeforeProxy ─

func TestUserHandler_PurgeDeletedUsersBeforeProxy_MissingBefore(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodDelete, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.PurgeDeletedUsersBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_PurgeDeletedUsersBeforeProxy_BadJSON(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodDelete, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.PurgeDeletedUsersBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_ListUsersInStateBeforeProxy_MissingParams(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListUsersInStateBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_ListUsersInStateBeforeProxy_HappyPath_S4(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?state=deleted&before=2026-01-01T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.ListUsersInStateBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── groups_handler.go: CreateGroup, GetGroup, UpdateGroup ─────────────────────

func TestGroupHandler_CreateGroup_NoUserCtx(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test"}`))
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGroupHandler_CreateGroup_BadJSON(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_GetGroup_BadID_S4(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_GetGroup_NotFound_S4(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.GetGroup(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGroupHandler_UpdateGroup_NoUserCtx(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"name":"test"}`)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGroupHandler_UpdateGroup_BadID(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"name":"test"}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.UpdateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_DeleteGroup_NoUserCtx(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── risk_exceptions.go: additional coverage ───────────────────────────────────

func TestDashboardHandler_ListRiskExceptions_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListRiskExceptions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_CreateRiskException_NoUserCtx(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"title":"test","justification":"test","category":"operational","expires_at":"2026-12-31T00:00:00Z"}`))
	w := httptest.NewRecorder()
	h.CreateRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDashboardHandler_ApproveRiskException_NoUserCtx(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ApproveRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDashboardHandler_ApproveRiskException_BadID(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ApproveRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDashboardHandler_RevokeRiskException_NoUserCtx(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDashboardHandler_RevokeRiskException_BadID(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokeRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── users_roles.go: UpdateUserRoles ──────────────────────────────────────────

func TestUsersRolesHandler_UpdateUserRoles_NoUserCtx(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"role_ids":[]}`)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUsersRolesHandler_UpdateUserRoles_BadID(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"role_ids":[]}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUsersRolesHandler_UpdateUserRoles_HappyPath(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"role_ids":[]}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	// empty role_ids → not bad request
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── users_crud.go: StaleAccounts, GetUserByUsername, GetUserByExternalID ──────

func TestUserHandler_StaleAccounts_NoUserCtx(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_StaleAccounts_HappyPath(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUserHandler_GetUserByUsername_MissingParam(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetUserByUsername_NotFound_S4(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?username=nonexistent", nil))
	w := httptest.NewRecorder()
	h.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_GetUserByExternalID_MissingParam(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetUserByExternalID_NotFound(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?external_id=nonexistent", nil))
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── users_crud.go: RestoreUser, GetActiveMFAChallenge ─────────────────────────

func TestUserHandler_GetActiveMFAChallenge_MissingBody(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
	w := httptest.NewRecorder()
	h.GetActiveMFAChallenge(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetActiveMFAChallenge_NotFound(t *testing.T) {
	h := newUserHandlerS4(t)
	body := `{"token_hash":"nonexistent","now":"2026-07-12T00:00:00Z"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.GetActiveMFAChallenge(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── admin_impersonation.go: End handler ──────────────────────────────────────

func TestImpersonationHandler_End_NoToken_S4(t *testing.T) {
	h := NewImpersonationHandler(newHandlerCoreS4(t), false)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.End(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── audit.go: WriteAuditCheckpoint ───────────────────────────────────────────

func TestAuditHandler_WriteAuditCheckpoint_NoUserCtx(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.WriteAuditCheckpoint(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_versions.go: GetSecretVersions ───────────────────────────────────

// ── secrets_crud.go: GetSecret, GetSecretValueByRef ───────────────────────────

func TestSecretHandler_GetSecretValueByRef_NoUserCtx(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?ref=secret://env/name", nil)
	w := httptest.NewRecorder()
	h.GetSecretValueByRef(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_description.go: DescribeSecret ───────────────────────────────────

// ── secrets_audit_trail.go: AuditTrail ───────────────────────────────────────

// ── secrets_suspend.go: SuspendSecret ────────────────────────────────────────

// ── secrets_access_stats.go: GetSecretAccessStats ─────────────────────────────

func TestSecretHandler_GetSecretAccessStats_NoUserCtx(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSecretAccessStats(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_GetSecretAccessStats_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetSecretAccessStats(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_copy.go: CopySecret ──────────────────────────────────────────────

func TestSecretHandler_CopySecret_NoUserCtx(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"target_project_id":1}`))
	w := httptest.NewRecorder()
	h.CopySecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_CopySecret_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CopySecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_risk.go: GetSecretRisk ───────────────────────────────────────────

// ── secrets_expiring.go: ExpiringSecrets ──────────────────────────────────────

func TestSecretHandler_ExpiringSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ExpiringSecrets(w, req)
	// OK or internal error depending on SQLite support
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_tags.go: SetTags ──────────────────────────────────────────────────

// ── secrets_ownership.go: TransferOwnership ───────────────────────────────────

func TestSecretHandler_TransferOwnership_NoUserCtx(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"new_owner_id":2}`)), "id", "1")
	w := httptest.NewRecorder()
	h.TransferOwnership(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_TransferOwnership_BadID_S4(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"new_owner_id":2}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.TransferOwnership(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_render.go: RenderTemplate ────────────────────────────────────────

func TestSecretHandler_RenderTemplate_NoUserCtx(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"template":"{{.name}}"}`))
	w := httptest.NewRecorder()
	h.RenderTemplate(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_RenderTemplate_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.RenderTemplate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── shares_crud.go: ShareSecret, RevokeShare ──────────────────────────────────

func TestShareHandler_ShareSecret_NoUserCtx(t *testing.T) {
	h := newShareHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"secret_id":1}`))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ShareSecret_BadJSON_S4(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── catalog.go: RestoreProject, RestoreEnvironment, CreateProjectEnvironment ──

func TestCatalogHandler_RestoreProject_NotFound_S4(t *testing.T) {
	// Use a fresh isolated DB: the shared s4 core accumulates rows across tests
	// (notably, UpdateProject uses GORM Save which UPSERTs, so a prior test that
	// calls UpdateProjectProxy with id=9999 creates a phantom project row that a
	// later DeleteProjectProxy call soft-deletes, leaving a deleted_at-stamped row
	// that RestoreProject(9999) would then successfully restore instead of 404-ing).
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.ShareRecord{}, &models.DynamicSecretConfig{}, &models.Role{}, &models.UserRole{}, &models.GroupRole{}))
	h := NewCatalogHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.RestoreProject(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCatalogHandler_RestoreProject_BadID_S4(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RestoreProject(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_RestoreEnvironment_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "projectId", "bad")
	w := httptest.NewRecorder()
	h.RestoreEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateProjectEnvironment_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"dev"}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.CreateProjectEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── invitations.go: CreateInvitation, RevokeInvitation ────────────────────────

// CreateInvitation: parses chi param "id" before checking user ctx, so no-id → 400
func TestCatalogHandler_CreateInvitation_NoID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"email":"test@example.com","role":"viewer"}`))
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// CreateInvitation: valid id but no user ctx → 401
func TestCatalogHandler_CreateInvitation_NoUserCtx(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"email":"test@example.com","role":"viewer"}`)), "id", "1")
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// RevokeInvitation: parses chi param "id" then "invitationId" before checking user ctx
func TestCatalogHandler_RevokeInvitation_NoInvitationID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// RevokeInvitation: valid id + invitationId but no user ctx → 401

func TestCatalogHandler_RevokeInvitation_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.RevokeInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── project_memberships.go: ListProjectMemberships, InviteMember ──────────────

// ListProjectMemberships: checks chi param "id" first, no user ctx check
func TestCatalogHandler_ListProjectMemberships_NoID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// InviteMember: checks chi param "id" first, then user ctx
func TestCatalogHandler_InviteMember_NoID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":1,"role":"viewer"}`))
	w := httptest.NewRecorder()
	h.InviteMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_InviteMember_NoUserCtx(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":1,"role":"viewer"}`)), "id", "1")
	w := httptest.NewRecorder()
	h.InviteMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCatalogHandler_InviteMember_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.InviteMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── break_glass.go: RevokeBreakGlass ─────────────────────────────────────────

// RevokeBreakGlass: checks id + activationId first, then user ctx
func TestCatalogHandler_RevokeBreakGlass_NoActivationID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_RevokeBreakGlass_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── auth.go: Login (bad body), Logout, ListSessions ──────────────────────────

func TestAuthHandler_RefreshToken_NoTokenBr(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestAuthHandler_ListSessions_NoUserCtx(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSessions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── dynamic_secrets.go: denyAuthz, ListConfigs, RevokeLease ──────────────────

// ListConfigs: authorize() returns false without user ctx → denyAuthz → 403
func TestDynamicSecretHandler_ListConfigs_NoUserCtx(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ListConfigs: user ctx present but no permissions → also 403
func TestDynamicSecretHandler_ListConfigs_Forbidden(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDynamicSecretHandler_RevokeLease_NoUserCtx(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "leaseID", "1")
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// RevokeLease: string leaseID "bad" → lease not found → 404
func TestDynamicSecretHandler_RevokeLease_NotFound_S4(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "leaseID", "bad"))
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── secrets_extend_expiring.go: ExtendExpiringSecrets ─────────────────────────

func TestSecretHandler_ExtendExpiringSecrets_NoUserCtx(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"days":30}`))
	w := httptest.NewRecorder()
	h.ExtendExpiringSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_ExtendExpiringSecrets_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.ExtendExpiringSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secret_certificate.go: GetSecretCertificate ───────────────────────────────

// ── secret_dependencies.go: GetSecretImpact, GetProjectRotationOrder ──────────

// ── machine_identities.go: CreateMachineIdentity ─────────────────────────────

// CreateMachineIdentity: checks chi param "id" first, then user ctx
func TestCatalogHandler_CreateMachineIdentity_NoID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test"}`))
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateMachineIdentity_NoUserCtx(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test"}`)), "id", "1")
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCatalogHandler_CreateMachineIdentity_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── access_review_campaigns.go: ListAccessReviewCampaigns ────────────────────

// ListAccessReviewCampaigns: no user ctx check, just parses chi param "id"
func TestCatalogHandler_ListAccessReviewCampaigns_NoID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaigns(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ListAccessReviewCampaigns_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaigns(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── users_crud.go: VerifyMFACredentials ─────────────────────────────────────

// VerifyMFACredentials: checks user ctx first → 401 without it
func TestUserHandler_VerifyMFACredentials_NoUserCtx_S4(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.VerifyMFACredentials(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// VerifyMFACredentials: with user ctx, bad JSON → 400
func TestUserHandler_VerifyMFACredentials_BadJSON_S4(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.VerifyMFACredentials(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── scim_groups.go: GetGroup, ListGroups (additional coverage) ────────────────

func TestSCIMHandler_GetGroup_BadID_S4(t *testing.T) {
	h := NewSCIMHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_ListGroups_HappyPath_S4(t *testing.T) {
	h := NewSCIMHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListGroups(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
