package store_test

import (
	"context"
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
		// ListProjectInvitations (#507) now makes a real HTTP call rather than
		// stubbing out — see server/http/remote_storage_invitations_test.go for its
		// end-to-end coverage against a real router.
		"CreateAccessRequest":   func() error { _, e := rs.CreateAccessRequest(ctx, &models.AccessRequest{}); return e },
		"CreateNotification":    func() error { _, e := rs.CreateNotification(ctx, &models.Notification{}); return e },
		"ListPermissions":       func() error { _, e := rs.ListPermissions(ctx); return e },
		"CreateMachineIdentity": func() error { _, e := rs.CreateMachineIdentity(ctx, &models.MachineIdentity{}); return e },
	}
	for name, call := range calls {
		err := call()
		require.Error(t, err, "%s should error", name)
		assert.True(t, errors.Is(err, store.ErrRemoteUnsupported),
			"%s should wrap ErrRemoteUnsupported, got %v", name, err)
	}
}

// TestRemoteStorage_SetAccountState_HardFails proves the #454 fix: since
// account_state has no field in the wire format UpdateUser sends (only
// username/email/display_name/active — see core.UpdateUserRequest), RemoteStorage
// must refuse the write outright rather than silently no-op it. No httptest server is
// needed at all: SetAccountState never makes an HTTP call — the whole point is that
// there is nowhere to send this field.
func TestRemoteStorage_SetAccountState_HardFails(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("https://unused.example"))
	require.NoError(t, err)

	err = rs.SetAccountState(context.Background(), 1, "suspended", time.Now())
	require.Error(t, err, "an account_state change must hard-fail under remote storage, not silently succeed")
	assert.True(t, errors.Is(err, store.ErrRemoteUnsupported))
	assert.True(t, errors.Is(err, corestorage.ErrUnsupportedByBackend))
}

// TestRemoteStorage_SetPasswordHash_HardFails proves the #484 fix: since
// models.User.PasswordHash is tagged json:"-", it never even reaches the JSON body a
// RemoteStorage UpdateUser call would send — there is no way to persist a password
// change through the remote API at all. RemoteStorage must refuse the write outright
// rather than silently no-op it, exactly mirroring SetAccountState's #454 hard-fail
// treatment above. No httptest server is needed: SetPasswordHash never makes an HTTP
// call — the whole point is that there is nowhere to send this field.
func TestRemoteStorage_SetPasswordHash_HardFails(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("https://unused.example"))
	require.NoError(t, err)

	err = rs.SetPasswordHash(context.Background(), 1, "$2a$10$fakehash", time.Now())
	require.Error(t, err, "a password change must hard-fail under remote storage, not silently succeed")
	assert.True(t, errors.Is(err, store.ErrRemoteUnsupported))
	assert.True(t, errors.Is(err, corestorage.ErrUnsupportedByBackend))
}

// TestRemoteStorage_UpdateLoginLockoutState_ReturnsUnsupportedSentinel proves the
// #454 fix for the lockout-accounting columns: same wire-format gap as
// SetAccountState, but this one is a passive backstop counter, not an explicit
// security directive — the caller (login_lockout.go) distinguishes it from
// SetAccountState's hard-fail treatment by matching storage.ErrUnsupportedByBackend
// via isUnsupportedByBackend, so it must errors.Is-wrap that sentinel too.
func TestRemoteStorage_UpdateLoginLockoutState_ReturnsUnsupportedSentinel(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("https://unused.example"))
	require.NoError(t, err)

	err = rs.UpdateLoginLockoutState(context.Background(), 1, 3, nil, nil, 1)
	require.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrRemoteUnsupported))
	assert.True(t, errors.Is(err, corestorage.ErrUnsupportedByBackend))
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
