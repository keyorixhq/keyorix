// secrets_crud_client_origin_test.go — #2545: a secret written by keyorix-migrate was
// indistinguishable in the audit trail from one a human created by hand. The migrate tool now
// sends core.ClientOriginHeader ("keyorix-migrate/<ver> source=<vault path>"); these tests
// drive the real CreateSecret/UpdateSecret handlers and read the persisted audit row, asserting
// the origin is recorded — and that it stays a labelled, client-asserted note: ActorType is
// still derived from the authenticated principal, never from the header.
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const originTestValue = "canary-value-must-never-reach-audit"

func seedOriginWriter(t *testing.T, db *gorm.DB) (userID, projectID, envID uint) {
	t.Helper()
	proj := &models.Project{Name: "proj-origin"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-origin", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	user := &models.User{Username: "migrator", Email: "migrator@example.com"}
	require.NoError(t, db.Create(user).Error)
	role := &models.Role{Name: "origin_writer"}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{}
	if err := db.Where("name = ?", permSecretsWrite).First(perm).Error; err != nil {
		perm = &models.Permission{Name: permSecretsWrite, Resource: "secrets", Action: "write"}
		require.NoError(t, db.Create(perm).Error)
	}
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: user.ID, RoleID: role.ID, ProjectID: proj.ID}).Error)
	return user.ID, proj.ID, env.ID
}

func createSecretWithOrigin(t *testing.T, h *SecretHandler, userID, projectID, envID uint, name, origin string) uint {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"name": name, "value": originTestValue, "project_id": projectID, "environment_id": envID, "type": "static",
	})
	require.NoError(t, err)
	req := withUserCtxID(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body)), userID, "migrator")
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set(core.ClientOriginHeader, origin)
	}
	w := httptest.NewRecorder()
	h.CreateSecret(w, req)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var env struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	require.NotZero(t, env.Data.ID)
	return env.Data.ID
}

// waitAuditEvent polls for the (asynchronously written) audit row of eventType on secretID.
func waitAuditEvent(t *testing.T, db *gorm.DB, eventType string, secretID uint) models.AuditEvent {
	t.Helper()
	var ev models.AuditEvent
	require.Eventually(t, func() bool {
		return db.Where("event_type = ? AND secret_node_id = ?", eventType, secretID).First(&ev).Error == nil
	}, 5*time.Second, 10*time.Millisecond, "no %s audit event for secret %d", eventType, secretID)
	return ev
}

func TestCreateAndUpdateSecret_ClientOriginRecordedInAudit(t *testing.T) {
	h, db := freshMachineAuthzFixture(t)
	userID, projectID, envID := seedOriginWriter(t, db)
	const origin = "keyorix-migrate/1.2.3 source=vault:secret/team-a/db#password"

	id := createSecretWithOrigin(t, h, userID, projectID, envID, "migrated-secret", origin)
	created := waitAuditEvent(t, db, "secret.created", id)
	assert.Contains(t, created.Description, "[client-asserted origin: "+origin+"]",
		"#2545: a migrated secret's audit event must record the migration origin")
	assert.Equal(t, core.ActorTypeUser, created.ActorType,
		"the origin header must never change ActorType — attribution comes from the authenticated principal only")
	assert.NotContains(t, created.Description, originTestValue)

	upd, err := json.Marshal(map[string]any{"value": originTestValue + "-v2"})
	require.NoError(t, err)
	req := withChiParam(withUserCtxID(httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", id), bytes.NewReader(upd)), userID, "migrator"), "id", fmt.Sprint(id))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(core.ClientOriginHeader, origin)
	w := httptest.NewRecorder()
	h.UpdateSecret(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	updated := waitAuditEvent(t, db, "secret.updated", id)
	assert.Contains(t, updated.Description, "[client-asserted origin: "+origin+"]")
	assert.NotContains(t, updated.Description, originTestValue)
	assert.NotContains(t, updated.Diff, originTestValue)
}

// TestCreateSecret_NoOriginHeader_NoNote is the converse: an ordinary create carries no
// origin note, so the marker actually distinguishes the two.
func TestCreateSecret_NoOriginHeader_NoNote(t *testing.T) {
	h, db := freshMachineAuthzFixture(t)
	userID, projectID, envID := seedOriginWriter(t, db)
	id := createSecretWithOrigin(t, h, userID, projectID, envID, "manual-secret", "")
	ev := waitAuditEvent(t, db, "secret.created", id)
	assert.NotContains(t, ev.Description, "client-asserted origin")
}

// TestCreateSecret_ClientOriginSanitizedAndCapped: the header is caller-controlled text headed
// for a hash-chained audit row, so control characters are dropped and the length is capped.
func TestCreateSecret_ClientOriginSanitizedAndCapped(t *testing.T) {
	h, db := freshMachineAuthzFixture(t)
	userID, projectID, envID := seedOriginWriter(t, db)
	origin := "tool\x1b[31m\x00x" + strings.Repeat("a", 1000)
	id := createSecretWithOrigin(t, h, userID, projectID, envID, "noisy-origin", origin)
	ev := waitAuditEvent(t, db, "secret.created", id)
	assert.NotContains(t, ev.Description, "\x1b")
	assert.NotContains(t, ev.Description, "\x00")
	assert.Contains(t, ev.Description, "client-asserted origin: tool[31mx")
	assert.Less(t, len(ev.Description), 600, "origin must be capped")
}
