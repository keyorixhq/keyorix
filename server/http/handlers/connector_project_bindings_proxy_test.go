// connector_project_bindings_proxy_test.go — ADR-082 branch 3 / issue #1477's
// audit half: CreateConnectorProjectBindingProxy previously had zero test
// coverage (verified during branch 3's Stage 1 investigation) and, before this
// branch, wrote a ConnectorProjectBinding with no audit event at all despite it
// being an authorization input (it feeds core.ConnectOwnership downstream).
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newConnectorProjectBindingProxyHandler(t *testing.T) (*AuthHandler, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.ConnectorProjectBinding{}, &models.AuditEvent{}))
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	return NewAuthHandler(cs, false), db
}

// TestCreateConnectorProjectBindingProxy_Audited proves the remote-proxy write
// path (the literal subject of issue #1477) persists an audit event alongside
// the binding itself: same event type as the boot-time write
// (server/connect_ownership_resolution_test.go's counterpart), ProjectID
// populated with the bound project (not left nil), Success=true, and actored
// as "system" since this endpoint is reached only by a node-credential/
// system.write caller, never a human session.
func TestCreateConnectorProjectBindingProxy_Audited(t *testing.T) {
	h, db := newConnectorProjectBindingProxyHandler(t)

	body, err := json.Marshal(map[string]any{
		"connector":    "aws",
		"project_id":   7,
		"project_name": "payments",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/connector-project-bindings", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateConnectorProjectBindingProxy(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var event models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", core.EventConnectorProjectBindingCreate).First(&event).Error)
	require.NotNil(t, event.ProjectID, "the binding's owning project must be recorded on the audit event, not left nil")
	assert.EqualValues(t, 7, *event.ProjectID)
	require.NotNil(t, event.Success)
	assert.True(t, *event.Success)
	assert.Equal(t, core.ActorTypeSystem, event.ActorType)
	assert.Contains(t, event.Description, "aws")
	assert.Contains(t, event.Description, "payments")
}

// TestCreateConnectorProjectBindingProxy_StorageFailureStillReturnsError proves
// a storage-level create failure (e.g. a duplicate connector) still surfaces as
// an error response — no audit event should be written for a write that never
// actually persisted.
func TestCreateConnectorProjectBindingProxy_StorageFailureStillReturnsError(t *testing.T) {
	h, db := newConnectorProjectBindingProxyHandler(t)

	body, err := json.Marshal(map[string]any{
		"connector":    "aws",
		"project_id":   7,
		"project_name": "payments",
	})
	require.NoError(t, err)

	// First create succeeds.
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/system/connector-project-bindings", bytes.NewReader(body))
	w1 := httptest.NewRecorder()
	h.CreateConnectorProjectBindingProxy(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code)

	// A second create for the SAME connector violates the unique index.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/system/connector-project-bindings", bytes.NewReader(body))
	w2 := httptest.NewRecorder()
	h.CreateConnectorProjectBindingProxy(w2, req2)
	require.Equal(t, http.StatusInternalServerError, w2.Code)

	var count int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", core.EventConnectorProjectBindingCreate).Count(&count).Error)
	assert.EqualValues(t, 1, count, "only the successful create should be audited, not the failed duplicate attempt")
}
