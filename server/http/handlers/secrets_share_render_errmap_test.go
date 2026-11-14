package handlers

// secrets_share_render_errmap_test.go — ERRMAP-CATALOG-NOV-1 item 3. The waiver rows of
// the stateful fuzzer for restoreSecret, renderSecretTemplate and shareSecret named
// concrete inputs (restore of a non-deleted / absent secret, a schema-valid template that
// fails to render, a self-share / duplicate share / unknown target). Each input is driven
// through the real handler here; the answer is pinned so that a regression to a 500 is a
// failing test, not a fuzzer waiver.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestRestoreSecret_RefusalsAnswerTheirStatus(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	w := seedErrmapWorld(t, cs, db)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	// A secret soft-deleted under a live environment, and one whose environment is gone too.
	deleted := &models.SecretNode{Name: "restore-me", ProjectID: w.projectA, EnvironmentID: w.envA, OwnerID: secretsAdminID, Type: "static", Status: "active"}
	require.NoError(t, db.Create(deleted).Error)
	require.NoError(t, db.Delete(deleted).Error)
	orphanEnv := &models.Environment{Name: "doomed-env", ProjectID: w.projectA}
	require.NoError(t, db.Create(orphanEnv).Error)
	orphan := &models.SecretNode{Name: "orphaned", ProjectID: w.projectA, EnvironmentID: orphanEnv.ID, OwnerID: secretsAdminID, Type: "static", Status: "active"}
	require.NoError(t, db.Create(orphan).Error)
	require.NoError(t, db.Delete(orphan).Error)
	require.NoError(t, db.Delete(orphanEnv).Error)

	cases := []struct {
		name   string
		id     string
		status int
	}{
		{"live secret: nothing to restore", uintStrS28(w.suspendedSecret), http.StatusConflict},
		{"absent secret", "987654", http.StatusNotFound},
		{"parent environment deleted", uintStrS28(orphan.ID), http.StatusConflict},
		{"deleted secret restores", uintStrS28(deleted.ID), http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.RestoreSecret(rec, withChiParam(errmapJSON(http.MethodPost, ""), "id", tc.id))
			assert.Equal(t, tc.status, rec.Code, rec.Body.String())
		})
	}
}

func TestRenderTemplate_FailuresAnswerTheirStatus(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	w := seedErrmapWorld(t, cs, db)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	cases := []struct {
		name     string
		template string
		status   int
	}{
		{"no placeholders", "plain text", http.StatusOK},
		{"unterminated placeholder", "x ${secret:errmap-env/db", http.StatusBadRequest},
		{"empty placeholder", "x ${secret:}", http.StatusBadRequest},
		{"placeholder without an environment", "x ${secret:db}", http.StatusBadRequest},
		{"unknown environment", "x ${secret:nowhere/db}", http.StatusNotFound},
		{"unknown secret", "x ${secret:errmap-env/nothing}", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			body := fmt.Sprintf(`{"template":%q}`, tc.template)
			h.RenderTemplate(rec, withChiParam(errmapJSON(http.MethodPost, body), "id", uintStrS28(w.projectA)))
			assert.Equal(t, tc.status, rec.Code, rec.Body.String())
		})
	}
}

func TestShareSecret_RefusalsAnswerTheirStatus(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	// The sharer (user 1, the owner) and the recipient (user 2) both hold a role in project 1.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "share-target", UsernameFolded: "share-target",
		Email: "share-target@example.com", EmailFolded: "share-target@example.com", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 101, Name: "share-me", IsSecret: true, OwnerID: 1, ProjectID: 1}).Error)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	cases := []struct {
		name   string
		secret string
		body   string
		status int
	}{
		{"share with a project member", "101", `{"recipient_id":2,"permission":"read"}`, http.StatusCreated},
		{"duplicate share", "101", `{"recipient_id":2,"permission":"read"}`, http.StatusCreated},
		{"self-share", "101", `{"recipient_id":1,"permission":"read"}`, http.StatusBadRequest},
		{"unknown recipient", "101", `{"recipient_id":99999,"permission":"read"}`, http.StatusForbidden},
		{"unknown group", "101", `{"recipient_id":99999,"is_group":true,"permission":"read"}`, http.StatusForbidden},
		{"absent secret", "987654", `{"recipient_id":2,"permission":"read"}`, http.StatusNotFound},
		{"expiry in the past", "101", `{"recipient_id":2,"permission":"read","expires_at":"2001-01-01T00:00:00Z"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body)), "id", tc.secret))
			rec := httptest.NewRecorder()
			h.ShareSecret(rec, req)
			assert.Equal(t, tc.status, rec.Code, rec.Body.String())
		})
	}
}
