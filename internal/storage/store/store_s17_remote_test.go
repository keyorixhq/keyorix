// store_s17_remote_test.go — black-box remote coverage sweep for s17 gaps.
//
// Targets (remote):
//   - remote_rbac.go:1133   RemoveGlobalAdminRoleGuarded error branches
//   - remote_auth.go:350    newSetupTokenWire with non-nil ConsumedAt
//   - remote_rbac.go:719    projectWire.toModel with non-nil DeletedAt
//   - remote_rbac.go:735    newProjectWire with valid DeletedAt
//   - remote_rbac.go:897    environmentWire.toModel with non-nil DeletedAt
//   - remote_users.go:702   newGroupWire with valid DeletedAt
package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// s17ErrorBody returns the flat server-error JSON body that the remote client
// maps to an *HTTPError whose ErrorType == code and Message == msg.
func s17ErrorBody(code, msg string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"success": false,
		"error":   code,
		"message": msg,
	})
	return b
}

// s17OK wraps data in the standard {"success":true,"data":...} envelope.
func s17OK(data interface{}) []byte {
	b, _ := json.Marshal(map[string]interface{}{"success": true, "data": data})
	return b
}

// ---------------------------------------------------------------------------
// remote_rbac.go:1133 — RemoveGlobalAdminRoleGuarded error branches
// ---------------------------------------------------------------------------

// TestRemoteStorage_RemoveGlobalAdminRoleGuarded_WouldStrandLastAdmin verifies
// that WOULD_STRAND_LAST_ADMIN is translated to storage.ErrWouldStrandLastAdmin.
func TestRemoteStorage_RemoveGlobalAdminRoleGuarded_WouldStrandLastAdmin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write(s17ErrorBody("WOULD_STRAND_LAST_ADMIN", "cannot remove the last admin"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemoveGlobalAdminRoleGuarded(context.Background(), 10, 1, []uint{1})
	require.Error(t, err)
	assert.True(t, errors.Is(err, corestorage.ErrWouldStrandLastAdmin),
		"expected ErrWouldStrandLastAdmin, got: %v", err)
}

// TestRemoteStorage_RemoveGlobalAdminRoleGuarded_RoleNotAssigned verifies that
// ROLE_NOT_ASSIGNED is translated to storage.ErrRoleNotAssigned.
func TestRemoteStorage_RemoveGlobalAdminRoleGuarded_RoleNotAssigned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(s17ErrorBody("ROLE_NOT_ASSIGNED", "role not assigned to user"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemoveGlobalAdminRoleGuarded(context.Background(), 10, 1, []uint{1})
	require.Error(t, err)
	assert.True(t, errors.Is(err, corestorage.ErrRoleNotAssigned),
		"expected ErrRoleNotAssigned, got: %v", err)
}

// TestRemoteStorage_RemoveGlobalAdminRoleGuarded_GenericError verifies that a
// non-sentinel HTTP error is surfaced as a generic error (fallthrough branch).
func TestRemoteStorage_RemoveGlobalAdminRoleGuarded_GenericError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(s17ErrorBody("INTERNAL_ERROR", "something went wrong"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemoveGlobalAdminRoleGuarded(context.Background(), 10, 1, []uint{1})
	require.Error(t, err)
	assert.False(t, errors.Is(err, corestorage.ErrWouldStrandLastAdmin))
	assert.False(t, errors.Is(err, corestorage.ErrRoleNotAssigned))
}

// ---------------------------------------------------------------------------
// remote_auth.go:350 — newSetupTokenWire with non-nil ConsumedAt
// ---------------------------------------------------------------------------

// TestRemoteStorage_CreateSetupToken_WithConsumedAt exercises the
// t.ConsumedAt != nil branch in newSetupTokenWire (line 352-354).
func TestRemoteStorage_CreateSetupToken_WithConsumedAt(t *testing.T) {
	consumedAt := time.Now().UTC().Add(-time.Hour)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		// Verify that consumed_at was serialized in the request body.
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.NotNil(t, req["consumed_at"], "consumed_at must be serialized when non-nil")

		body := map[string]interface{}{
			"id":              float64(20),
			"token_hash":      "abc123",
			"purpose":         "account_setup",
			"subject_user_id": nil,
			"subject_email":   "bob@example.com",
			"invitation_id":   nil,
			"state":           "consumed",
			"expires_at":      time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
			"created_by":      float64(1),
			"created_at":      time.Now().UTC().Format(time.RFC3339Nano),
			"consumed_at":     consumedAt.Format(time.RFC3339Nano),
		}
		_, _ = w.Write(s17OK(body))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	tok, err := rs.CreateSetupToken(context.Background(), &models.SetupToken{
		TokenHash:    "abc123",
		Purpose:      "account_setup",
		SubjectEmail: "bob@example.com",
		State:        "consumed",
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		CreatedBy:    1,
		CreatedAt:    time.Now().UTC(),
		ConsumedAt:   &consumedAt,
	})
	require.NoError(t, err)
	assert.Equal(t, "consumed", tok.State)
	assert.NotNil(t, tok.ConsumedAt)
}

// ---------------------------------------------------------------------------
// remote_rbac.go:719 — projectWire.toModel with non-nil DeletedAt
// ---------------------------------------------------------------------------

// TestRemoteStorage_GetProject_WithDeletedAt exercises the w.DeletedAt != nil
// branch in projectWire.toModel (line 728-731).
func TestRemoteStorage_GetProject_WithDeletedAt(t *testing.T) {
	deletedAt := time.Now().UTC().Add(-24 * time.Hour)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := map[string]interface{}{
			"id":          float64(42),
			"name":        "old-project",
			"description": "a deleted project",
			"require_mfa": false,
			"created_at":  time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339Nano),
			"updated_at":  time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339Nano),
			"deleted_at":  deletedAt.Format(time.RFC3339Nano),
		}
		_, _ = w.Write(s17OK(body))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	project, err := rs.GetProject(context.Background(), 42)
	require.NoError(t, err)
	assert.Equal(t, uint(42), project.ID)
	assert.True(t, project.DeletedAt.Valid, "DeletedAt.Valid must be true for a soft-deleted project")
}

// ---------------------------------------------------------------------------
// remote_rbac.go:735 — newProjectWire with valid DeletedAt
// ---------------------------------------------------------------------------

// TestRemoteStorage_UpdateProject_WithDeletedAt exercises the p.DeletedAt.Valid
// branch in newProjectWire (line 744-747).
func TestRemoteStorage_UpdateProject_WithDeletedAt(t *testing.T) {
	deletedAt := time.Now().UTC().Add(-time.Hour)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the serialized payload includes deleted_at.
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.NotNil(t, req["deleted_at"], "deleted_at must be present in the wire payload")

		body := map[string]interface{}{
			"id":   float64(7),
			"name": "soft-deleted-proj",
		}
		_, _ = w.Write(s17OK(body))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	project, err := rs.UpdateProject(context.Background(), &models.Project{
		ID:        7,
		Name:      "soft-deleted-proj",
		DeletedAt: gorm.DeletedAt{Time: deletedAt, Valid: true},
	})
	require.NoError(t, err)
	assert.Equal(t, uint(7), project.ID)
}

// ---------------------------------------------------------------------------
// remote_rbac.go:897 — environmentWire.toModel with non-nil DeletedAt
// ---------------------------------------------------------------------------

// TestRemoteStorage_GetEnvironment_WithDeletedAt exercises the
// w.DeletedAt != nil branch in environmentWire.toModel (line 905-908).
func TestRemoteStorage_GetEnvironment_WithDeletedAt(t *testing.T) {
	deletedAt := time.Now().UTC().Add(-12 * time.Hour)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := map[string]interface{}{
			"id":         float64(11),
			"project_id": float64(3),
			"name":       "staging",
			"created_at": time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339Nano),
			"updated_at": time.Now().UTC().Add(-12 * time.Hour).Format(time.RFC3339Nano),
			"deleted_at": deletedAt.Format(time.RFC3339Nano),
		}
		_, _ = w.Write(s17OK(body))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	env, err := rs.GetEnvironment(context.Background(), 11)
	require.NoError(t, err)
	assert.Equal(t, uint(11), env.ID)
	assert.Equal(t, uint(3), env.ProjectID)
	assert.True(t, env.DeletedAt.Valid, "DeletedAt.Valid must be true for a soft-deleted environment")
}

// ---------------------------------------------------------------------------
// remote_users.go:702 — newGroupWire with valid DeletedAt
// ---------------------------------------------------------------------------

// TestRemoteStorage_UpdateGroup_WithDeletedAt exercises the g.DeletedAt.Valid
// branch in newGroupWire (line 710-712).
func TestRemoteStorage_UpdateGroup_WithDeletedAt(t *testing.T) {
	deletedAt := time.Now().UTC().Add(-2 * time.Hour)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify deleted_at was included in the serialized payload.
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.NotNil(t, req["deleted_at"], "deleted_at must be present in the wire payload")

		body := minimalGroupWire(5, "old-group")
		_, _ = w.Write(s17OK(body))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	group, err := rs.UpdateGroup(context.Background(), &models.Group{
		ID:        5,
		Name:      "old-group",
		DeletedAt: gorm.DeletedAt{Time: deletedAt, Valid: true},
	})
	require.NoError(t, err)
	assert.Equal(t, uint(5), group.ID)
}
