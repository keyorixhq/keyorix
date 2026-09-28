// session_i_access_request_duplicate_test.go — regression coverage for
// CreateAccessRequest (POST /api/v1/projects/{id}/access-requests) mapping
// the ordinary "you already have a pending access request for this project"
// case (internal/core/invitations.go's RequestProjectAccess, #G82's own
// duplicate-pending guard) to 409 Conflict instead of a generic 500. Found
// live by SESSION-I's fresh-install API smoke driver (scripts/e2e) issuing
// two requests for the same (user, project) pair in quick succession.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newAccessRequestDuplicateTestHandler(t *testing.T) *CatalogHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Project{}, &models.AccessRequest{},
		&models.AuditEvent{}, &models.Notification{}, &models.Role{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "e2e-smoke-project"}).Error)
	return NewCatalogHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
}

func createAccessRequestReq(projectID string) *http.Request {
	body := `{"suggested_role":"","reason":"e2e smoke"}`
	return withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", projectID))
}

// TestCreateAccessRequest_DuplicatePending_ReturnsConflictNotInternalError is
// the red/green regression: before the fix, the second request 500s because
// CreateAccessRequest's error switch only recognized errUnknownRole/"required"
// as non-500; "you already have a pending access request for this project"
// matched neither and fell through to the generic InternalError branch.
func TestCreateAccessRequest_DuplicatePending_ReturnsConflictNotInternalError(t *testing.T) {
	h := newAccessRequestDuplicateTestHandler(t)

	w1 := httptest.NewRecorder()
	h.CreateAccessRequest(w1, createAccessRequestReq("1"))
	require.Equal(t, http.StatusCreated, w1.Code, "first request must succeed: %s", w1.Body.String())

	w2 := httptest.NewRecorder()
	h.CreateAccessRequest(w2, createAccessRequestReq("1"))
	assert.Equal(t, http.StatusConflict, w2.Code,
		"a second pending request for the same (user, project) pair must be a 409 Conflict, not a 500: %s", w2.Body.String())
	assert.Contains(t, w2.Body.String(), "already have a pending")
}

// TestCreateAccessRequest_UnknownProject_ReturnsNotFoundNotInternalError
// covers the sibling classification gap this same fix closes: GetProject
// failing (target project missing/soft-deleted) previously also fell
// through to the generic 500 branch.
func TestCreateAccessRequest_UnknownProject_ReturnsNotFoundNotInternalError(t *testing.T) {
	h := newAccessRequestDuplicateTestHandler(t)

	w := httptest.NewRecorder()
	h.CreateAccessRequest(w, createAccessRequestReq("999999"))
	assert.Equal(t, http.StatusNotFound, w.Code, "a request against a nonexistent project must be 404, not 500: %s", w.Body.String())
}
