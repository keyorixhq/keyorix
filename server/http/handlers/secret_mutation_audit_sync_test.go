package handlers

// #3276: the audit row of a secret mutation must exist when the handler returns, not
// "eventually". The handlers used to write it from a detached goroutine after responding, so
// a client that refetched History straight away could miss the event (web-e2e
// secrets-crud.spec.ts "Rotated" flake). These tests read the audit table the instant the
// handler returns, with NO wait and NO DrainBackgroundGoroutines, so they go red if any of
// these writes becomes asynchronous again.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func requireAuditRowNow(t *testing.T, db *gorm.DB, eventType string, secretID uint) {
	t.Helper()
	var n int64
	require.NoError(t, db.Table("audit_events").
		Where("event_type = ? AND secret_node_id = ?", eventType, secretID).Count(&n).Error)
	assert.EqualValues(t, 1, n, "%s audit row must exist when the handler returns (#3276)", eventType)
}

func TestSecretMutations_AuditRowExistsWhenHandlerReturns(t *testing.T) {
	t.Run("rotate", func(t *testing.T) {
		h, _, secret, db := freshSecretFixtureS15(t)
		body, _ := json.Marshal(map[string]string{"new_value": "rotated-3276"})
		r := withAdminCtxS15(withChiParam(
			httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
			"id", fmt.Sprint(secret.ID)))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.RotateSecret(w, r)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		requireAuditRowNow(t, db, "secret.rotated", secret.ID)
	})

	t.Run("update", func(t *testing.T) {
		h, _, secret, db := freshSecretFixtureS15(t)
		body, _ := json.Marshal(map[string]any{"value": "updated-3276"})
		r := withAdminCtxS15(withChiParam(
			httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body)),
			"id", fmt.Sprint(secret.ID)))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.UpdateSecret(w, r)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		requireAuditRowNow(t, db, "secret.updated", secret.ID)
	})

	t.Run("delete", func(t *testing.T) {
		h, _, secret, db := freshSecretFixtureS15(t)
		r := withAdminCtxS15(withChiParam(
			httptest.NewRequest(http.MethodDelete, "/", nil),
			"id", fmt.Sprint(secret.ID)))
		w := httptest.NewRecorder()
		h.DeleteSecret(w, r)
		require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
		requireAuditRowNow(t, db, "secret.deleted", secret.ID)
	})

	t.Run("create", func(t *testing.T) {
		h, db := freshMachineAuthzFixture(t)
		userID, projectID, envID := seedOriginWriter(t, db)
		id := createSecretWithOrigin(t, h, userID, projectID, envID, "sync-audit-3276", "")
		requireAuditRowNow(t, db, "secret.created", id)
	})
}
