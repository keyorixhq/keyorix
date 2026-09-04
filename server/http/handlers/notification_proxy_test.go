// notification_proxy_test.go — regression coverage for CreateNotificationProxy
// (notification_proxy.go, #1589): before this handler existed,
// storage.type: remote deployments silently, permanently dropped every
// notification because CreateNotification was an unconditional stub, and
// notify()/notifyWithSeverity() (internal/core/notifications.go) swallow the
// error by design — nothing surfaced the failure. This file is the
// regression guard: it exercises the full wire<->model round-trip
// (including the deliberate IsRead=false invariant on create) and both
// storage-error branches (duplicate reminder -> 409, generic -> 500) so a
// future refactor that reopens #1589 fails a test instead of failing silently.
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

var notifProxyDBCounter atomic.Int64

// freshCoreNotifProxy creates a brand-new in-memory SQLite DB migrated for
// models.Notification, plus the same partial unique reminder-dedup index
// production installs via internal/storage/factory.go's
// ensureReminderNotificationDedupIndex ("uniq_notifications_unread_reminder"
// on (user_id, type, project_id) WHERE is_read = false AND type IN
// ('rotation.reminder', 'secret.expiry_reminder')) — without this index,
// CreateNotification can never return storage.ErrDuplicateReminderNotification
// and the 409 branch would be untestable. Returns both the gorm handle (so a
// test can close the underlying *sql.DB to force a generic storage error) and
// the KeyorixCore built on top of it.
func freshCoreNotifProxy(t *testing.T) (*gorm.DB, *core.KeyorixCore) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := notifProxyDBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_notifproxy_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Notification{}))
	require.NoError(t, db.Exec(
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_notifications_unread_reminder "+
			"ON notifications (user_id, type, project_id) "+
			"WHERE is_read = false AND type IN ('rotation.reminder', 'secret.expiry_reminder')",
	).Error)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	return db, cs
}

func newNotifProxyRequest(t *testing.T, body interface{}) *http.Request {
	t.Helper()
	var raw []byte
	switch v := body.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		var err error
		raw, err = json.Marshal(v)
		require.NoError(t, err)
	}
	return httptest.NewRequest(http.MethodPost, "/api/v1/system/notifications", bytes.NewReader(raw))
}

// ── missing/zero UserID -> 400 ──────────────────────────────────────────────

func TestCreateNotificationProxy_ZeroUserID(t *testing.T) {
	_, cs := freshCoreNotifProxy(t)
	h := NewCatalogHandler(cs)
	req := newNotifProxyRequest(t, notificationProxyWire{
		UserID:  0,
		Type:    "secret.shared",
		Title:   "hi",
		Message: "hello",
	})
	w := httptest.NewRecorder()
	h.CreateNotificationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.False(t, resp.Success)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
	assert.Equal(t, "user_id is required", resp.Error.Message)
}

func TestCreateNotificationProxy_MissingUserIDField(t *testing.T) {
	_, cs := freshCoreNotifProxy(t)
	h := NewCatalogHandler(cs)
	req := newNotifProxyRequest(t, `{"type":"secret.shared","title":"hi","message":"hello"}`)
	w := httptest.NewRecorder()
	h.CreateNotificationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// ── bad JSON body -> 400 ────────────────────────────────────────────────────

func TestCreateNotificationProxy_BadJSON(t *testing.T) {
	_, cs := freshCoreNotifProxy(t)
	h := NewCatalogHandler(cs)
	req := newNotifProxyRequest(t, "{not valid json")
	w := httptest.NewRecorder()
	h.CreateNotificationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.False(t, resp.Success)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
	assert.Equal(t, errInvalidBody, resp.Error.Message)
}

// ── success: full field round-trip, including the IsRead=false invariant ──

func TestCreateNotificationProxy_Success_FullRoundTrip(t *testing.T) {
	db, cs := freshCoreNotifProxy(t)
	h := NewCatalogHandler(cs)

	secretNodeID := uint(42)
	projectID := uint(7)
	createdAt := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)

	body := map[string]interface{}{
		"user_id":        99,
		"secret_node_id": secretNodeID,
		"project_id":     projectID,
		"type":           "rotation.reminder",
		"title":          "Rotate your secret",
		"message":        "This secret is due for rotation.",
		"link":           "/projects/7/secrets/42",
		"severity":       int(models.NotificationSeverityCritical),
		// Adversarial: a caller-supplied is_read=true must NOT survive to
		// the created record — creation always forces IsRead=false per the
		// handler's own documented invariant.
		"is_read":    true,
		"created_at": createdAt,
	}

	req := newNotifProxyRequest(t, body)
	w := httptest.NewRecorder()
	h.CreateNotificationProxy(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodeRemoteResp(t, w)
	require.True(t, resp.Success)

	dataBytes, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var wire notificationProxyWire
	require.NoError(t, json.Unmarshal(dataBytes, &wire))

	assert.NotZero(t, wire.ID, "ID must be assigned by the database, not trusted from the wire")
	assert.Equal(t, uint(99), wire.UserID)
	require.NotNil(t, wire.SecretNodeID)
	assert.Equal(t, secretNodeID, *wire.SecretNodeID)
	require.NotNil(t, wire.ProjectID)
	assert.Equal(t, projectID, *wire.ProjectID)
	assert.Equal(t, "rotation.reminder", wire.Type)
	assert.Equal(t, "Rotate your secret", wire.Title)
	assert.Equal(t, "This secret is due for rotation.", wire.Message)
	assert.Equal(t, "/projects/7/secrets/42", wire.Link)
	assert.Equal(t, int(models.NotificationSeverityCritical), wire.Severity)
	assert.False(t, wire.IsRead, "creation must always force IsRead=false regardless of what the wire body requested")

	// Confirm the invariant landed in storage too, not just the response.
	var stored models.Notification
	require.NoError(t, db.First(&stored, wire.ID).Error)
	assert.False(t, stored.IsRead)
}

// ── success: nil pointer fields round-trip as nil, not zero ────────────────

func TestCreateNotificationProxy_Success_NilOptionalFields(t *testing.T) {
	_, cs := freshCoreNotifProxy(t)
	h := NewCatalogHandler(cs)

	body := notificationProxyWire{
		UserID:  5,
		Type:    "secret.shared",
		Title:   "A secret was shared with you",
		Message: "See details.",
	}
	req := newNotifProxyRequest(t, body)
	w := httptest.NewRecorder()
	h.CreateNotificationProxy(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodeRemoteResp(t, w)
	require.True(t, resp.Success)

	dataBytes, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var wire notificationProxyWire
	require.NoError(t, json.Unmarshal(dataBytes, &wire))

	assert.Nil(t, wire.SecretNodeID)
	assert.Nil(t, wire.ProjectID)
	assert.False(t, wire.IsRead)
	assert.Equal(t, int(models.NotificationSeverityNone), wire.Severity)
}

// ── duplicate reminder -> 409 with the documented error code ───────────────

func TestCreateNotificationProxy_DuplicateReminder(t *testing.T) {
	_, cs := freshCoreNotifProxy(t)
	h := NewCatalogHandler(cs)

	first := notificationProxyWire{
		UserID:    11,
		ProjectID: uintPtrNotifProxy(3),
		Type:      "rotation.reminder",
		Title:     "Rotate now",
		Message:   "first reminder",
	}
	req1 := newNotifProxyRequest(t, first)
	w1 := httptest.NewRecorder()
	h.CreateNotificationProxy(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code, "body: %s", w1.Body.String())

	// Second unread reminder of the same (user, type, project) must hit the
	// partial unique dedup index (#488) and surface as
	// storage.ErrDuplicateReminderNotification via errors.Is.
	second := notificationProxyWire{
		UserID:    11,
		ProjectID: uintPtrNotifProxy(3),
		Type:      "rotation.reminder",
		Title:     "Rotate now (again)",
		Message:   "duplicate reminder",
	}
	req2 := newNotifProxyRequest(t, second)
	w2 := httptest.NewRecorder()
	h.CreateNotificationProxy(w2, req2)

	assert.Equal(t, http.StatusConflict, w2.Code)
	resp := decodeRemoteResp(t, w2)
	assert.False(t, resp.Success)
	assert.Equal(t, notificationDuplicateReminderCode, resp.Error.Code)
	assert.Equal(t, "DUPLICATE_REMINDER_NOTIFICATION", resp.Error.Code)
}

// ── generic storage error -> 500 STORAGE_ERROR ──────────────────────────────

func TestCreateNotificationProxy_GenericStorageError(t *testing.T) {
	db, cs := freshCoreNotifProxy(t)
	h := NewCatalogHandler(cs)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	req := newNotifProxyRequest(t, notificationProxyWire{
		UserID:  1,
		Type:    "secret.shared",
		Title:   "t",
		Message: "m",
	})
	w := httptest.NewRecorder()
	h.CreateNotificationProxy(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.False(t, resp.Success)
	assert.Equal(t, "STORAGE_ERROR", resp.Error.Code)
}

func uintPtrNotifProxy(v uint) *uint { return &v }
