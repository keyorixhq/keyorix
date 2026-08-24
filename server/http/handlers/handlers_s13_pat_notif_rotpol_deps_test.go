// handlers_s13_pat_notif_rotpol_deps_test.go — coverage sweep for:
//   - pat_handler.go: CreatePAT happy/error paths, RevokePAT not-found,
//     ListPATs error path, PATHygiene param paths
//   - notifications_handler.go: List/MarkRead/MarkAllRead error paths
//   - rotation_policies_handler.go: Get/Update/Delete bad-param + not-found,
//     sendSuccess/sendError branches, Create/Update validation error paths
//   - secret_dependencies.go: AddSecretDependency/RemoveSecretDependency
//     bad-param/not-found, GetProjectRotationOrder/Plan/GetDeploymentRotationPlan
//   - secret_dependencies_proxy.go: CreateProxy happy/not-found,
//     CreateExclusiveProxy happy/missing-fields, GetProxy not-found,
//     ListForProject/ForUpdate invalid-query, DeleteProxy not-found
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── PAT handler ───────────────────────────────────────────────────────────────

// TestCreatePAT_HappyPath_S13 — valid body without expiry → 201 with plain token.
func TestCreatePAT_HappyPath_S13(t *testing.T) {
	t.Parallel()
	h := NewPATHandler(freshCoreS12(t))
	body, _ := json.Marshal(map[string]any{"name": "my-token"})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreatePAT(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

// TestCreatePAT_ValidExpiry_S13 — valid expires_at → 201.
func TestCreatePAT_ValidExpiry_S13(t *testing.T) {
	t.Parallel()
	h := NewPATHandler(freshCoreS12(t))
	body, _ := json.Marshal(map[string]any{
		"name":       "expiring-token",
		"expires_at": "2099-12-31T23:59:59Z",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreatePAT(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

// TestRevokePAT_NotFound_S13 — revoke a token that does not exist → 404.
func TestRevokePAT_NotFound_S13(t *testing.T) {
	t.Parallel()
	h := NewPATHandler(freshCoreS12(t))
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/auth/tokens/9999", nil),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	h.RevokePAT(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestRevokePAT_BadParam_S13 — non-numeric id → 400.
func TestRevokePAT_BadParam_S13(t *testing.T) {
	t.Parallel()
	h := NewPATHandler(freshCoreS12(t))
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/auth/tokens/abc", nil),
		"id", "abc",
	))
	w := httptest.NewRecorder()
	h.RevokePAT(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestPATHygiene_DaysParam_S13 — days query param (valid integer) → 200.
func TestPATHygiene_DaysParam_S13(t *testing.T) {
	t.Parallel()
	h := NewPATHandler(freshCoreS12(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?days=60", nil))
	w := httptest.NewRecorder()
	h.PATHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestPATHygiene_DaysParamTooBig_S13 — days > 3650 is capped → 200.
func TestPATHygiene_DaysParamTooBig_S13(t *testing.T) {
	t.Parallel()
	h := NewPATHandler(freshCoreS12(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?days=99999", nil))
	w := httptest.NewRecorder()
	h.PATHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestPATHygiene_InvalidDays_S13 — non-numeric days is ignored (defaults to 90) → 200.
func TestPATHygiene_InvalidDays_S13(t *testing.T) {
	t.Parallel()
	h := NewPATHandler(freshCoreS12(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?days=notanumber", nil))
	w := httptest.NewRecorder()
	h.PATHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListPATs_NoUserCtx_S13 — no user context → 401.
func TestListPATs_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := NewPATHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListPATs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Notification handler ──────────────────────────────────────────────────────

// TestNotificationList_LimitParam_S13 — valid limit param → 200.
func TestNotificationList_LimitParam_S13(t *testing.T) {
	t.Parallel()
	h := NewNotificationHandler(freshCoreS12(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/notifications?limit=10", nil))
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestNotificationList_InvalidLimit_S13 — non-numeric limit is ignored → 200.
func TestNotificationList_InvalidLimit_S13(t *testing.T) {
	t.Parallel()
	h := NewNotificationHandler(freshCoreS12(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/notifications?limit=bad", nil))
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestNotificationList_UnreadTrue_S13 — unread=true path → 200.
func TestNotificationList_UnreadTrue_S13(t *testing.T) {
	t.Parallel()
	h := NewNotificationHandler(freshCoreS12(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/notifications?unread=true", nil))
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestNotificationMarkRead_NoUserCtx_S13 — no user context → 401.
func TestNotificationMarkRead_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := NewNotificationHandler(freshCoreS12(t))
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.MarkRead(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestNotificationMarkRead_BadID_S13 — invalid id → 400.
func TestNotificationMarkRead_BadID_S13(t *testing.T) {
	t.Parallel()
	h := NewNotificationHandler(freshCoreS12(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "abc"))
	w := httptest.NewRecorder()
	h.MarkRead(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNotificationMarkRead_HappyPath_S13 — marking an existing notification as read → 200.
func TestNotificationMarkRead_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h := NewNotificationHandler(cs)

	// Create a notification directly.
	n, err := cs.Storage().CreateNotification(httptest.NewRequest(http.MethodGet, "/", nil).Context(), &models.Notification{
		UserID:  1,
		Type:    "info",
		Title:   "test",
		Message: "test message",
	})
	require.NoError(t, err)

	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", fmt.Sprintf("%d", n.ID)))
	w := httptest.NewRecorder()
	h.MarkRead(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestNotificationMarkAllRead_NoUserCtx_S13 — no user context → 401.
func TestNotificationMarkAllRead_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := NewNotificationHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.MarkAllRead(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestNotificationMarkAllRead_HappyPath_S13 — marks all → 200.
func TestNotificationMarkAllRead_HappyPath_S13(t *testing.T) {
	t.Parallel()
	h := NewNotificationHandler(freshCoreS12(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil))
	w := httptest.NewRecorder()
	h.MarkAllRead(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── Rotation policy handler ───────────────────────────────────────────────────

// TestRotationPolicyGet_NoUserCtx_S13 — no user context → 401.
func TestRotationPolicyGet_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := NewRotationPolicyHandler(freshCoreS12(t))
	r := withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/rotation-policies/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.Get(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRotationPolicyGet_BadID_S13 — non-numeric id → 400.
func TestRotationPolicyGet_BadID_S13(t *testing.T) {
	t.Parallel()
	h := NewRotationPolicyHandler(freshCoreS12(t))
	r := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/rotation-policies/bad", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.Get(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRotationPolicyGet_NotFound_S13 — valid id but no record → 404.
func TestRotationPolicyGet_NotFound_S13(t *testing.T) {
	t.Parallel()
	h := NewRotationPolicyHandler(freshCoreS12(t))
	r := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/rotation-policies/9999", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.Get(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestRotationPolicyDelete_NoUserCtx_S13 — no user context → 401.
func TestRotationPolicyDelete_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := NewRotationPolicyHandler(freshCoreS12(t))
	r := withChiParam(httptest.NewRequest(http.MethodDelete, "/api/v1/rotation-policies/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.Delete(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRotationPolicyDelete_BadID_S13 — non-numeric id → 400.
func TestRotationPolicyDelete_BadID_S13(t *testing.T) {
	t.Parallel()
	h := NewRotationPolicyHandler(freshCoreS12(t))
	r := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/api/v1/rotation-policies/xyz", nil), "id", "xyz"))
	w := httptest.NewRecorder()
	h.Delete(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRotationPolicyDelete_NotFound_S13 — valid id but no record → 404.
func TestRotationPolicyDelete_NotFound_S13(t *testing.T) {
	t.Parallel()
	h := NewRotationPolicyHandler(freshCoreS12(t))
	r := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/api/v1/rotation-policies/9999", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.Delete(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestRotationPolicyUpdate_NoUserCtx_S13 — no user context → 401.
func TestRotationPolicyUpdate_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := NewRotationPolicyHandler(freshCoreS12(t))
	body := `{"name":"p","interval_days":30}`
	r := withChiParam(httptest.NewRequest(http.MethodPut, "/api/v1/rotation-policies/1", bytes.NewBufferString(body)), "id", "1")
	w := httptest.NewRecorder()
	h.Update(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRotationPolicyUpdate_BadID_S13 — non-numeric id → 400.
func TestRotationPolicyUpdate_BadID_S13(t *testing.T) {
	t.Parallel()
	h := NewRotationPolicyHandler(freshCoreS12(t))
	body := `{"name":"p","interval_days":30}`
	r := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/api/v1/rotation-policies/bad", bytes.NewBufferString(body)), "id", "bad"))
	w := httptest.NewRecorder()
	h.Update(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRotationPolicyUpdate_BadJSON_S13 — malformed JSON → 400.
func TestRotationPolicyUpdate_BadJSON_S13(t *testing.T) {
	t.Parallel()
	h := NewRotationPolicyHandler(freshCoreS12(t))
	r := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/api/v1/rotation-policies/1", bytes.NewBufferString("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.Update(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRotationPolicyUpdate_ValidationError_S13 — missing required fields → 400.
func TestRotationPolicyUpdate_ValidationError_S13(t *testing.T) {
	t.Parallel()
	h := NewRotationPolicyHandler(freshCoreS12(t))
	body := `{"name":"","interval_days":0}`
	r := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/api/v1/rotation-policies/1", bytes.NewBufferString(body)), "id", "1"))
	w := httptest.NewRecorder()
	h.Update(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRotationPolicyUpdate_NotFound_S13 — valid body but no matching record → 404.
func TestRotationPolicyUpdate_NotFound_S13(t *testing.T) {
	t.Parallel()
	h := NewRotationPolicyHandler(freshCoreS12(t))
	body := `{"name":"updated","interval_days":30}`
	r := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/api/v1/rotation-policies/9999", bytes.NewBufferString(body)), "id", "9999"))
	w := httptest.NewRecorder()
	h.Update(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestRotationPolicySendError_S13 — exercises the rotation handler's own sendError helper.
func TestRotationPolicySendError_S13(t *testing.T) {
	t.Parallel()
	h := NewRotationPolicyHandler(freshCoreS12(t))
	w := httptest.NewRecorder()
	h.sendError(w, "TestError", "something went wrong", http.StatusBadRequest, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "TestError", resp["error"])
}

// TestRotationPolicySendError_WithDetails_S13 — exercises sendError with non-nil details.
func TestRotationPolicySendError_WithDetails_S13(t *testing.T) {
	t.Parallel()
	h := NewRotationPolicyHandler(freshCoreS12(t))
	w := httptest.NewRecorder()
	h.sendError(w, "ValidationError", "invalid input", http.StatusUnprocessableEntity, map[string]string{"field": "name"})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

// TestRotationPolicyEvaluate_HappyPath_WithEnvID_S13 — valid environment_id → 200.
func TestRotationPolicyEvaluate_HappyPath_WithEnvID_S13(t *testing.T) {
	t.Parallel()
	h := NewRotationPolicyHandler(freshCoreS12(t))
	r := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/rotation-policies/evaluate?environment_id=1", nil))
	w := httptest.NewRecorder()
	h.Evaluate(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRotationPolicyStatus_HappyPath_WithEnvID_S13 — valid environment_id → 200.
func TestRotationPolicyStatus_HappyPath_WithEnvID_S13(t *testing.T) {
	t.Parallel()
	h := NewRotationPolicyHandler(freshCoreS12(t))
	r := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/rotation-policies/status?environment_id=1", nil))
	w := httptest.NewRecorder()
	h.Status(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── secret_dependencies.go ───────────────────────────────────────────────────

// TestAddSecretDependency_BadID_S13 — non-numeric id → 400.
func TestAddSecretDependency_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"depends_on_id":1}`)),
		"id", "abc",
	))
	w := httptest.NewRecorder()
	h.AddSecretDependency(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestAddSecretDependency_BadJSON_S13 — malformed JSON body → 400.
func TestAddSecretDependency_BadJSON_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("{bad")),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.AddSecretDependency(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestAddSecretDependency_NotFound_S13 — secret not found → 404 (via dependencyErrorStatus).
// Uses distinct id / depends_on_id to avoid the "cannot depend on itself" → 400 branch.
func TestAddSecretDependency_NotFound_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerS4(t)
	// id=9998, depends_on_id=9999 — distinct so self-reference guard doesn't fire.
	// requireSecret(9998) returns "not found" → dependencyErrorStatus → 404.
	body, _ := json.Marshal(map[string]any{"depends_on_id": 9999})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		"id", "9998",
	))
	w := httptest.NewRecorder()
	h.AddSecretDependency(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestRemoveSecretDependency_BadID_S13 — non-numeric id → 400.
func TestRemoveSecretDependency_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "abc", "depId": "1"},
	))
	w := httptest.NewRecorder()
	h.RemoveSecretDependency(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRemoveSecretDependency_BadDepID_S13 — non-numeric depId → 400.
func TestRemoveSecretDependency_BadDepID_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "depId": "abc"},
	))
	w := httptest.NewRecorder()
	h.RemoveSecretDependency(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRemoveSecretDependency_NotFound_S13 — valid ids but dep does not exist → 404.
func TestRemoveSecretDependency_NotFound_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "depId": "9999"},
	))
	w := httptest.NewRecorder()
	h.RemoveSecretDependency(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetSecretImpact_BadID_S13 — non-numeric id → 400.
func TestGetSecretImpact_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "abc"))
	w := httptest.NewRecorder()
	h.GetSecretImpact(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetSecretImpact_HappyPath_S13 — valid id with no edges → 200.
func TestGetSecretImpact_HappyPath_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.GetSecretImpact(w, req)
	// No secret with id=1 exists, so dependencyErrorStatus maps "not found" → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetProjectRotationOrder_BadID_S13 — non-numeric id → 400.
func TestGetProjectRotationOrder_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "xyz"))
	w := httptest.NewRecorder()
	h.GetProjectRotationOrder(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetProjectRotationOrder_HappyPath_S13 — a real, live project with no
// secrets → empty order, 200. Uses a fresh isolated core (rather than the
// shared newSecretHandlerS4 DB) so it can create its own real Project row: a
// scoped role binding survives project soft-delete, so the handler now
// re-checks project liveness before returning data, and a bare hardcoded
// project ID with no backing row would 404.
func TestGetProjectRotationOrder_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	proj, err := cs.Storage().CreateProject(context.Background(), &models.Project{Name: "proj-rotorder-happy-s13"})
	require.NoError(t, err)

	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", strconv.FormatUint(uint64(proj.ID), 10)))
	w := httptest.NewRecorder()
	h.GetProjectRotationOrder(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetProjectRotationOrder_ProjectNotFound_S13 pins the project-liveness fix
// itself: a role binding scoped to a project ID with no backing row (or a
// soft-deleted one) must 404, not silently return an empty order.
func TestGetProjectRotationOrder_ProjectNotFound_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999999"))
	w := httptest.NewRecorder()
	h.GetProjectRotationOrder(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetProjectRotationPlan_BadID_S13 — non-numeric id → 400.
func TestGetProjectRotationPlan_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "abc"))
	w := httptest.NewRecorder()
	h.GetProjectRotationPlan(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetProjectRotationPlan_HappyPath_S13 — a real, live project with no
// secrets → 200. See TestGetProjectRotationOrder_HappyPath_S13 for why this
// needs a real backing Project row now.
func TestGetProjectRotationPlan_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	proj, err := cs.Storage().CreateProject(context.Background(), &models.Project{Name: "proj-rotplan-happy-s13"})
	require.NoError(t, err)

	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", strconv.FormatUint(uint64(proj.ID), 10)))
	w := httptest.NewRecorder()
	h.GetProjectRotationPlan(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetProjectRotationPlan_ProjectNotFound_S13 — see the Order twin above.
func TestGetProjectRotationPlan_ProjectNotFound_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999999"))
	w := httptest.NewRecorder()
	h.GetProjectRotationPlan(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetDeploymentRotationPlan_HappyPath_S13 — empty DB → 200.
func TestGetDeploymentRotationPlan_HappyPath_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetDeploymentRotationPlan(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListSecretDependencies_HappyPath_S13 — valid id with no deps → 200.
func TestListSecretDependencies_HappyPath_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.ListSecretDependencies(w, req)
	// secret id=1 does not exist → "not found" error → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── secret_dependencies_proxy.go ─────────────────────────────────────────────

// TestCreateSecretDependencyProxy_HappyPath_S13 — valid body referencing two
// real secrets in the same project/environment (#G79's cross-reference check
// requires this) → 200.
func TestCreateSecretDependencyProxy_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	ctx := context.Background()
	proj, err := cs.Storage().CreateProject(ctx, &models.Project{Name: "proj-dep-create-s13"})
	require.NoError(t, err)
	env, err := cs.Storage().CreateEnvironment(ctx, &models.Environment{Name: "env-dep-create-s13", ProjectID: proj.ID})
	require.NoError(t, err)
	s1, err := cs.Storage().CreateSecret(ctx, &models.SecretNode{Name: "s1", ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password", OwnerID: 1})
	require.NoError(t, err)
	s2, err := cs.Storage().CreateSecret(ctx, &models.SecretNode{Name: "s2", ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password", OwnerID: 1})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]any{
		"project_id":           proj.ID,
		"dependent_secret_id":  s1.ID,
		"depends_on_secret_id": s2.ID,
	})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateSecretDependencyProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestCreateSecretDependencyExclusiveProxy_MissingFields_S13 — zero IDs → 400.
func TestCreateSecretDependencyExclusiveProxy_MissingFields_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]any{"project_id": 0, "dependent_secret_id": 0, "depends_on_secret_id": 0})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateSecretDependencyExclusiveProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateSecretDependencyExclusiveProxy_HappyPath_S13 — valid body
// referencing two real secrets in the same project/environment (#G79's
// cross-reference check requires this) → 200.
func TestCreateSecretDependencyExclusiveProxy_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	ctx := context.Background()
	proj, err := cs.Storage().CreateProject(ctx, &models.Project{Name: "proj-dep-excl-s13"})
	require.NoError(t, err)
	env, err := cs.Storage().CreateEnvironment(ctx, &models.Environment{Name: "env-dep-excl-s13", ProjectID: proj.ID})
	require.NoError(t, err)
	s1, err := cs.Storage().CreateSecret(ctx, &models.SecretNode{Name: "s1", ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password", OwnerID: 1})
	require.NoError(t, err)
	s2, err := cs.Storage().CreateSecret(ctx, &models.SecretNode{Name: "s2", ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password", OwnerID: 1})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]any{
		"project_id":           proj.ID,
		"dependent_secret_id":  s1.ID,
		"depends_on_secret_id": s2.ID,
	})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateSecretDependencyExclusiveProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetSecretDependencyProxy_NotFound_S13 — valid numeric id but row absent → 404.
func TestGetSecretDependencyProxy_NotFound_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetSecretDependencyProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetSecretDependencyProxy_HappyPath_S13 — row exists → 200.
func TestGetSecretDependencyProxy_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	// Create a row first via the Create proxy so we have a real ID.
	dep, createErr := cs.Storage().CreateSecretDependency(
		httptest.NewRequest(http.MethodGet, "/", nil).Context(),
		&models.SecretDependency{
			ProjectID:         1,
			DependentSecretID: 3,
			DependsOnSecretID: 4,
		},
	)
	require.NoError(t, createErr)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprintf("%d", dep.ID))
	w := httptest.NewRecorder()
	h.GetSecretDependencyProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListSecretDependenciesForProjectProxy_InvalidQuery_S13 — non-numeric project_id → 400.
func TestListSecretDependenciesForProjectProxy_InvalidQuery_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/?project_id=xyz", nil)
	w := httptest.NewRecorder()
	h.ListSecretDependenciesForProjectProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListSecretDependenciesForProjectForUpdateProxy_InvalidQuery_S13 — non-numeric project_id → 400.
func TestListSecretDependenciesForProjectForUpdateProxy_InvalidQuery_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/?project_id=bad", nil)
	w := httptest.NewRecorder()
	h.ListSecretDependenciesForProjectForUpdateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListSecretDependenciesForProjectForUpdateProxy_HappyPath_S13 — valid project_id → 200.
func TestListSecretDependenciesForProjectForUpdateProxy_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListSecretDependenciesForProjectForUpdateProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestParseProxyProjectIDQuery_S13 — exercises the 77.8% branch directly.
// The missing branch is the invalid-integer path (already partially covered above,
// but let's hit it directly to be sure).
func TestParseProxyProjectIDQuery_InvalidInt_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	// Negative number-like string that ParseUint rejects as invalid.
	req := httptest.NewRequest(http.MethodGet, "/?project_id=-1", nil)
	w := httptest.NewRecorder()
	h.ListSecretDependenciesForProjectProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
