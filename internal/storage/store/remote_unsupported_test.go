package store_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unwired RemoteStorage stubs return ErrRemoteUnsupported (errors.Is-able), so
// client mode degrades cleanly instead of with ad-hoc "not implemented" strings.
func TestRemoteStorage_UnsupportedSentinel(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("https://unused.example"))
	require.NoError(t, err)
	ctx := context.Background()

	calls := map[string]func() error{
		"CreateGroup":             func() error { _, e := rs.CreateGroup(ctx, &models.Group{}); return e },
		"CreateProjectMembership": func() error { _, e := rs.CreateProjectMembership(ctx, &models.ProjectMembership{}); return e },
		"ListProjectInvitations":  func() error { _, e := rs.ListProjectInvitations(ctx, 1); return e },
		"CreateNotification":      func() error { _, e := rs.CreateNotification(ctx, &models.Notification{}); return e },
		"ListPermissions":         func() error { _, e := rs.ListPermissions(ctx); return e },
		"CreateMachineIdentity":   func() error { _, e := rs.CreateMachineIdentity(ctx, &models.MachineIdentity{}); return e },
	}
	for name, call := range calls {
		err := call()
		require.Error(t, err, "%s should error", name)
		assert.True(t, errors.Is(err, store.ErrRemoteUnsupported),
			"%s should wrap ErrRemoteUnsupported, got %v", name, err)
	}
}

func TestRemoteStorage_MarkAllNotificationsRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/notifications/read-all", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)
	require.NoError(t, rs.MarkAllNotificationsRead(context.Background(), 1))
}

func TestRemoteStorage_MarkNotificationRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/notifications/5/read", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)
	require.NoError(t, rs.MarkNotificationRead(context.Background(), 5, 0))
}

func TestRemoteStorage_RemovePermissionFromRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/roles/2/permissions/8", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)
	require.NoError(t, rs.RemovePermissionFromRole(context.Background(), 2, 8))
}
