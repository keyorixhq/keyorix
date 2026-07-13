package store_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func notificationWireBody(id uint) map[string]any {
	return map[string]any{
		"id":         id,
		"type":       "info",
		"title":      "Test notification",
		"message":    "This is a test",
		"link":       "",
		"is_read":    false,
		"created_at": time.Now().UTC().Format(time.RFC3339),
	}
}

func notificationListResp(items []map[string]any, unreadCount int64) map[string]any {
	return map[string]any{
		"notifications": items,
		"unread_count":  unreadCount,
	}
}

func TestRemoteStorage_ListNotifications(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/notifications", r.URL.Path)
		_, _ = w.Write(apiOK(notificationListResp(
			[]map[string]any{notificationWireBody(1), notificationWireBody(2)},
			2,
		)))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListNotifications(context.Background(), 0, false, 10)
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, uint(1), results[0].ID)
}

func TestRemoteStorage_ListNotifications_UnreadOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "true", r.URL.Query().Get("unread"))
		_, _ = w.Write(apiOK(notificationListResp(
			[]map[string]any{notificationWireBody(1)},
			1,
		)))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListNotifications(context.Background(), 0, true, 5)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}

func TestRemoteStorage_CountUnreadNotifications(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		_, _ = w.Write(apiOK(notificationListResp(
			[]map[string]any{notificationWireBody(1)},
			7,
		)))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	count, err := rs.CountUnreadNotifications(context.Background(), 0)
	require.NoError(t, err)
	assert.Equal(t, int64(7), count)
}

func TestRemoteStorage_MarkNotificationRead_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/notifications/42/read", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.MarkNotificationRead(context.Background(), 42, 0)
	require.NoError(t, err)
}

func TestRemoteStorage_MarkAllNotificationsRead_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/notifications/read-all", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.MarkAllNotificationsRead(context.Background(), 0)
	require.NoError(t, err)
}

func TestRemoteStorage_CreateNotification_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19997"))
	require.NoError(t, err)

	_, err = rs.CreateNotification(context.Background(), nil)
	assert.Error(t, err)
}

func TestRemoteStorage_HasUnreadNotification_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19997"))
	require.NoError(t, err)

	_, err = rs.HasUnreadNotification(context.Background(), 0, "", 0)
	assert.Error(t, err)
}

func TestRemoteStorage_GetUnreadNotification_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19997"))
	require.NoError(t, err)

	_, err = rs.GetUnreadNotification(context.Background(), 0, "", 0)
	assert.Error(t, err)
}

func TestRemoteStorage_UpdateNotification_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19997"))
	require.NoError(t, err)

	err = rs.UpdateNotification(context.Background(), nil)
	assert.Error(t, err)
}

func TestRemoteStorage_ListNotifications_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"error":   map[string]string{"code": "BAD_REQUEST", "message": "server error"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListNotifications(context.Background(), 0, false, 10)
	assert.Error(t, err)
}
