// remote_group_d_notifications_error_sweep_test.go covers remote_notifications.go
// branches left uncovered by remote_notifications_test.go /
// remote_coverage_mfa_rbac_secrets_test.go: CreateNotification's generic
// transport-error branch, its !resp.Success branch (a non-duplicate-reminder
// failure), and the resp.Data decode-error branches for CreateNotification and
// fetchNotifications (shared by ListNotifications/CountUnreadNotifications), plus
// the transport-error branches of MarkNotificationRead/MarkAllNotificationsRead.
package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- CreateNotification ---

func TestRemoteStorage_CreateNotification_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateNotification(context.Background(), &models.Notification{UserID: 1})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create notification")
}

func TestRemoteStorage_CreateNotification_SuccessFalse_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "STORAGE_ERROR", "db unavailable"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateNotification(context.Background(), &models.Notification{UserID: 1})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create notification failed")
}

func TestRemoteStorage_CreateNotification_BadJSON_GroupD(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateNotification(context.Background(), &models.Notification{UserID: 1})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- fetchNotifications (via ListNotifications) ---

func TestRemoteStorage_ListNotifications_BadJSON_GroupD(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/notifications", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListNotifications(context.Background(), 0, false, 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- MarkNotificationRead / MarkAllNotificationsRead transport errors ---

func TestRemoteStorage_MarkNotificationRead_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "notification not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.MarkNotificationRead(context.Background(), 42, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to mark notification read")
}

func TestRemoteStorage_MarkAllNotificationsRead_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "db down"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.MarkAllNotificationsRead(context.Background(), 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to mark all notifications read")
}
