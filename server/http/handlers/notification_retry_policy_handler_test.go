// notification_retry_policy_handler_test.go — HTTP handler tests for
// PUT/GET /api/v1/notification-channels/{id}/retry-policy.
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var retryPolicyDBCounter atomic.Int64

// freshCoreRetryPolicy opens a unique in-memory SQLite DB that includes
// models.NotificationChannel (plus the dependencies AuditEvent needs) and
// returns a ready-to-use KeyorixCore.
func freshCoreRetryPolicy(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := retryPolicyDBCounter.Add(1)
	dsn := fmt.Sprintf("file:kx_retry_policy_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.AuditEvent{},
		&models.NotificationChannel{},
	))
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// seedChannel creates a NotificationChannel row directly in the DB and returns its ID.
func seedChannel(t *testing.T, db *gorm.DB) uint {
	t.Helper()
	ch := &models.NotificationChannel{
		Name:           "test-webhook",
		Type:           "webhook",
		URL:            "https://example.com/hook",
		Enabled:        true,
		MaxRetries:     3,
		RetryBackoffMs: 1000,
	}
	require.NoError(t, db.Create(ch).Error)
	return ch.ID
}

// freshCoreRetryPolicyWithChannel opens the DB, migrates, and seeds one channel.
// Returns the core and the channel ID.
func freshCoreRetryPolicyWithChannel(t *testing.T) (*core.KeyorixCore, *gorm.DB, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := retryPolicyDBCounter.Add(1)
	dsn := fmt.Sprintf("file:kx_retry_policy_ch_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.AuditEvent{},
		&models.NotificationChannel{},
	))
	id := seedChannel(t, db)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db, id
}

// ── SetRetryPolicy ────────────────────────────────────────────────────────────

// TestSetRetryPolicy_HappyPath — valid body → 200 with policy fields.
func TestSetRetryPolicy_HappyPath(t *testing.T) {
	t.Parallel()
	cs, _, chanID := freshCoreRetryPolicyWithChannel(t)
	h := NewNotificationChannelHandler(cs)

	body, _ := json.Marshal(map[string]any{"max_retries": 5, "retry_backoff_ms": 2000})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", chanID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SetRetryPolicy(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, float64(5), data["max_retries"])
	assert.Equal(t, float64(2000), data["retry_backoff_ms"])
}

// TestSetRetryPolicy_ValidationError_MaxRetries — max_retries=11 → 400.
func TestSetRetryPolicy_ValidationError_MaxRetries(t *testing.T) {
	t.Parallel()
	cs, _, chanID := freshCoreRetryPolicyWithChannel(t)
	h := NewNotificationChannelHandler(cs)

	body, _ := json.Marshal(map[string]any{"max_retries": 11, "retry_backoff_ms": 1000})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", chanID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SetRetryPolicy(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSetRetryPolicy_ValidationError_BackoffMs — retry_backoff_ms=50 → 400.
func TestSetRetryPolicy_ValidationError_BackoffMs(t *testing.T) {
	t.Parallel()
	cs, _, chanID := freshCoreRetryPolicyWithChannel(t)
	h := NewNotificationChannelHandler(cs)

	body, _ := json.Marshal(map[string]any{"max_retries": 3, "retry_backoff_ms": 50})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", chanID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SetRetryPolicy(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSetRetryPolicy_NoAuth — missing user context → 401.
func TestSetRetryPolicy_NoAuth(t *testing.T) {
	t.Parallel()
	cs := freshCoreRetryPolicy(t)
	h := NewNotificationChannelHandler(cs)

	body, _ := json.Marshal(map[string]any{"max_retries": 3, "retry_backoff_ms": 1000})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body)),
		"id", "1",
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SetRetryPolicy(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestSetRetryPolicy_BadID — non-numeric id → 400.
func TestSetRetryPolicy_BadID(t *testing.T) {
	t.Parallel()
	cs := freshCoreRetryPolicy(t)
	h := NewNotificationChannelHandler(cs)

	body, _ := json.Marshal(map[string]any{"max_retries": 3, "retry_backoff_ms": 1000})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body)),
		"id", "abc",
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SetRetryPolicy(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSetRetryPolicy_InvalidBody — malformed JSON → 400.
func TestSetRetryPolicy_InvalidBody(t *testing.T) {
	t.Parallel()
	cs := freshCoreRetryPolicy(t)
	h := NewNotificationChannelHandler(cs)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/", bytes.NewReader([]byte("not-json"))),
		"id", "1",
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SetRetryPolicy(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSetRetryPolicy_NotFound — channel ID does not exist → 404.
func TestSetRetryPolicy_NotFound(t *testing.T) {
	t.Parallel()
	cs := freshCoreRetryPolicy(t)
	h := NewNotificationChannelHandler(cs)

	body, _ := json.Marshal(map[string]any{"max_retries": 3, "retry_backoff_ms": 1000})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body)),
		"id", "9999",
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SetRetryPolicy(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── GetRetryPolicy ────────────────────────────────────────────────────────────

// TestGetRetryPolicy_HappyPath — existing channel → 200 with current policy.
func TestGetRetryPolicy_HappyPath(t *testing.T) {
	t.Parallel()
	cs, _, chanID := freshCoreRetryPolicyWithChannel(t)
	h := NewNotificationChannelHandler(cs)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", fmt.Sprintf("%d", chanID),
	)
	w := httptest.NewRecorder()
	h.GetRetryPolicy(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, float64(3), data["max_retries"])
	assert.Equal(t, float64(1000), data["retry_backoff_ms"])
	assert.Equal(t, float64(chanID), data["channel_id"])
}

// TestGetRetryPolicy_NotFound — unknown channel ID → 404.
func TestGetRetryPolicy_NotFound(t *testing.T) {
	t.Parallel()
	cs := freshCoreRetryPolicy(t)
	h := NewNotificationChannelHandler(cs)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.GetRetryPolicy(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetRetryPolicy_BadID — non-numeric id → 400.
func TestGetRetryPolicy_BadID(t *testing.T) {
	t.Parallel()
	cs := freshCoreRetryPolicy(t)
	h := NewNotificationChannelHandler(cs)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetRetryPolicy(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
