package store_test

import (
	"context"
	"encoding/json"
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

// minimalUserWire returns a JSON-compatible map matching userWireResponse fields.
func minimalUserWire(id int, username, email string) map[string]interface{} {
	return map[string]interface{}{
		"id":                    float64(id),
		"username":              username,
		"email":                 email,
		"display_name":          "Test User",
		"active":                true,
		"account_state":         "active",
		"external_id":           "",
		"mfa_enabled":           false,
		"created_at":            time.Now().UTC().Format(time.RFC3339Nano),
		"updated_at":            time.Now().UTC().Format(time.RFC3339Nano),
		"last_login_at":         nil,
		"deleted_at":            nil,
		"failed_login_attempts": 0,
		"login_lockout_count":   0,
		"last_failed_login_at":  nil,
	}
}

// minimalGroupWire returns a JSON-compatible map matching groupWire fields.
func minimalGroupWire(id int, name string) map[string]interface{} {
	return map[string]interface{}{
		"id":          float64(id),
		"name":        name,
		"description": "A test group",
		"created_at":  time.Now().UTC().Format(time.RFC3339Nano),
		"updated_at":  time.Now().UTC().Format(time.RFC3339Nano),
		"deleted_at":  nil,
	}
}

// --- CreateUser ---

func TestRemoteStorage_CreateUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/users", r.URL.Path)
		_, _ = w.Write(apiOK(minimalUserWire(1, "alice", "alice@example.com")))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	user, err := rs.CreateUser(context.Background(), &models.User{
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice",
		IsActive:    true,
	}, "plaintext-pw")
	require.NoError(t, err)
	assert.Equal(t, uint(1), user.ID)
	assert.Equal(t, "alice", user.Username)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.True(t, user.IsActive)
}

func TestRemoteStorage_CreateUser_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "CONFLICT", "message": "user already exists"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateUser(context.Background(), &models.User{Username: "alice", Email: "alice@example.com"})
	assert.Error(t, err)
}

// --- GetUser ---

func TestRemoteStorage_GetUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/users/1", r.URL.Path)
		_, _ = w.Write(apiOK(minimalUserWire(1, "alice", "alice@example.com")))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	user, err := rs.GetUser(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, uint(1), user.ID)
	assert.Equal(t, "alice", user.Username)
}

func TestRemoteStorage_GetUser_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "NOT_FOUND", "message": "user not found"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetUser(context.Background(), 999)
	assert.Error(t, err)
}

// --- LockUserForUpdate ---

func TestRemoteStorage_LockUserForUpdate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/users/2", r.URL.Path)
		wire := minimalUserWire(2, "bob", "bob@example.com")
		wire["failed_login_attempts"] = float64(3)
		wire["login_lockout_count"] = float64(1)
		_, _ = w.Write(apiOK(wire))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	user, err := rs.LockUserForUpdate(context.Background(), 2)
	require.NoError(t, err)
	assert.Equal(t, uint(2), user.ID)
	assert.Equal(t, "bob", user.Username)
	assert.Equal(t, 3, user.FailedLoginAttempts)
	assert.Equal(t, 1, user.LoginLockoutCount)
}

// --- GetUserByEmail ---

func TestRemoteStorage_GetUserByEmail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/users/by-email", r.URL.Path)
		assert.Equal(t, "alice@example.com", r.URL.Query().Get("email"))
		_, _ = w.Write(apiOK(minimalUserWire(1, "alice", "alice@example.com")))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	user, err := rs.GetUserByEmail(context.Background(), "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", user.Email)
}

func TestRemoteStorage_GetUserByEmail_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "NOT_FOUND", "message": "user not found"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetUserByEmail(context.Background(), "nobody@example.com")
	assert.Error(t, err)
}

// --- GetUserByUsername ---

func TestRemoteStorage_GetUserByUsername(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/users/by-username", r.URL.Path)
		assert.Equal(t, "alice", r.URL.Query().Get("username"))
		_, _ = w.Write(apiOK(minimalUserWire(1, "alice", "alice@example.com")))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	user, err := rs.GetUserByUsername(context.Background(), "alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", user.Username)
}

func TestRemoteStorage_GetUserByUsername_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "NOT_FOUND", "message": "user not found"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetUserByUsername(context.Background(), "nobody")
	assert.Error(t, err)
}

// --- GetUserByExternalID ---

func TestRemoteStorage_GetUserByExternalID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/users/by-external-id", r.URL.Path)
		assert.Equal(t, "ext-123", r.URL.Query().Get("external_id"))
		wire := minimalUserWire(1, "alice", "alice@example.com")
		wire["external_id"] = "ext-123"
		_, _ = w.Write(apiOK(wire))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	user, err := rs.GetUserByExternalID(context.Background(), "ext-123")
	require.NoError(t, err)
	assert.Equal(t, "ext-123", user.ExternalID)
}

// --- UpdateUser ---

func TestRemoteStorage_UpdateUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/users/1", r.URL.Path)
		wire := minimalUserWire(1, "alice-updated", "alice@example.com")
		wire["display_name"] = "Alice Updated"
		_, _ = w.Write(apiOK(wire))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	user, err := rs.UpdateUser(context.Background(), &models.User{
		ID:          1,
		Username:    "alice-updated",
		Email:       "alice@example.com",
		DisplayName: "Alice Updated",
		IsActive:    true,
	})
	require.NoError(t, err)
	assert.Equal(t, "alice-updated", user.Username)
	assert.Equal(t, "Alice Updated", user.DisplayName)
}

// --- UpdateUserIfActiveStateMatches ---

func TestRemoteStorage_UpdateUserIfActiveStateMatches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/system/users/4/active-transition", r.URL.Path)
		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, false, body["active"])
		assert.Equal(t, true, body["from_active"])
		_, _ = w.Write(apiOK(map[string]interface{}{"matched": true}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	matched, err := rs.UpdateUserIfActiveStateMatches(context.Background(),
		&models.User{ID: 4, Username: "frank", Email: "frank@example.com", IsActive: false}, true)
	require.NoError(t, err)
	assert.True(t, matched)
}

func TestRemoteStorage_UpdateUserIfActiveStateMatches_NotMatched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{"matched": false}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	matched, err := rs.UpdateUserIfActiveStateMatches(context.Background(),
		&models.User{ID: 4, IsActive: false}, true)
	require.NoError(t, err)
	assert.False(t, matched)
}

func TestRemoteStorage_UpdateUserIfActiveStateMatches_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "DUPLICATE_EMAIL", "message": "duplicate email"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.UpdateUserIfActiveStateMatches(context.Background(), &models.User{ID: 4}, true)
	require.Error(t, err)
}

func TestRemoteStorage_UpdateUser_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "NOT_FOUND", "message": "user not found"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.UpdateUser(context.Background(), &models.User{ID: 999, Username: "ghost"})
	assert.Error(t, err)
}

// --- UpdateLastLogin (unsupported in remote mode) ---

func TestRemoteStorage_UpdateLastLogin_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19999"))
	require.NoError(t, err)

	err = rs.UpdateLastLogin(context.Background(), 1, time.Now())
	assert.ErrorIs(t, err, store.ErrRemoteUnsupported)
}

// --- SetAccountState (returns ErrRemoteUnsupported) ---

func TestRemoteStorage_SetAccountState_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19999"))
	require.NoError(t, err)

	err = rs.SetAccountState(context.Background(), 1, "suspended", time.Now())
	assert.Error(t, err)
	assert.ErrorIs(t, err, store.ErrRemoteUnsupported)
}

// --- SetPasswordHash (returns ErrRemoteUnsupported) ---

func TestRemoteStorage_SetPasswordHash_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19999"))
	require.NoError(t, err)

	err = rs.SetPasswordHash(context.Background(), 1, "newhash", time.Now())
	assert.Error(t, err)
	assert.ErrorIs(t, err, store.ErrRemoteUnsupported)
}

// --- DeleteUser ---

func TestRemoteStorage_DeleteUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/users/1", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteUser(context.Background(), 1)
	require.NoError(t, err)
}

// --- RestoreUser ---

func TestRemoteStorage_RestoreUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/users/1/restore", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RestoreUser(context.Background(), 1)
	require.NoError(t, err)
}

// --- Purge retention ---

func TestRemoteStorage_PurgeDeletedUsersBefore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/retention/users/purge", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"purged": float64(5)}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	count, err := rs.PurgeDeletedUsersBefore(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(5), count)
}

func TestRemoteStorage_PurgeDeletedProjectsBefore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/retention/projects/purge", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"purged": float64(2)}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	count, err := rs.PurgeDeletedProjectsBefore(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

func TestRemoteStorage_PurgeDeletedEnvironmentsBefore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/retention/environments/purge", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"purged": float64(0)}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	count, err := rs.PurgeDeletedEnvironmentsBefore(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

// --- ListUsers ---

func TestRemoteStorage_ListUsers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/users", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"users": []interface{}{
				minimalUserWire(1, "alice", "alice@example.com"),
				minimalUserWire(2, "bob", "bob@example.com"),
			},
			"total": float64(2),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	users, total, err := rs.ListUsers(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, int64(2), total)
	assert.Equal(t, "alice", users[0].Username)
	assert.Equal(t, "bob", users[1].Username)
}

func TestRemoteStorage_ListUsers_WithFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/users", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"users": []interface{}{
				minimalUserWire(1, "alice", "alice@example.com"),
			},
			"total": float64(1),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	username := "alice"
	users, total, err := rs.ListUsers(context.Background(), &corestorage.UserFilter{
		Username: &username,
		Page:     1,
		PageSize: 10,
	})
	require.NoError(t, err)
	assert.Len(t, users, 1)
	assert.Equal(t, int64(1), total)
}

func TestRemoteStorage_ListUsers_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "BAD_REQUEST", "message": "server error"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, _, err = rs.ListUsers(context.Background(), nil)
	assert.Error(t, err)
}

// --- ListUsersInStateBefore ---

func TestRemoteStorage_ListUsersInStateBefore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/retention/users/stale", r.URL.Path)
		assert.Equal(t, "inactive", r.URL.Query().Get("state"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"users": []interface{}{
				minimalUserWire(3, "stale-user", "stale@example.com"),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	users, err := rs.ListUsersInStateBefore(context.Background(), "inactive", time.Now())
	require.NoError(t, err)
	assert.Len(t, users, 1)
	assert.Equal(t, "stale-user", users[0].Username)
}

// --- CreateUserWithRoleGrants ---

func TestRemoteStorage_CreateUserWithRoleGrants(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/users/with-role-grants", r.URL.Path)
		_, _ = w.Write(apiOK(minimalUserWire(10, "newuser", "new@example.com")))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	grants := []corestorage.RoleGrant{
		{RoleID: 1, Scope: corestorage.Scope{ProjectID: 0, EnvironmentID: 0}},
	}
	user, err := rs.CreateUserWithRoleGrants(context.Background(), &models.User{
		Username:     "newuser",
		Email:        "new@example.com",
		DisplayName:  "New User",
		IsActive:     true,
		AccountState: "active",
	}, grants)
	require.NoError(t, err)
	assert.Equal(t, uint(10), user.ID)
	assert.Equal(t, "newuser", user.Username)
}

// --- GetUserGroups ---

func TestRemoteStorage_GetUserGroups(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/users/1/groups", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"groups": []interface{}{
				minimalGroupWire(1, "admins"),
				minimalGroupWire(2, "developers"),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	groups, err := rs.GetUserGroups(context.Background(), 1)
	require.NoError(t, err)
	assert.Len(t, groups, 2)
	assert.Equal(t, "admins", groups[0].Name)
	assert.Equal(t, "developers", groups[1].Name)
}

func TestRemoteStorage_GetUserGroups_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{
			"groups": []interface{}{},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	groups, err := rs.GetUserGroups(context.Background(), 1)
	require.NoError(t, err)
	assert.Empty(t, groups)
}

// --- CreateGroup ---

func TestRemoteStorage_CreateGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/groups", r.URL.Path)
		_, _ = w.Write(apiOK(minimalGroupWire(5, "engineering")))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	group, err := rs.CreateGroup(context.Background(), &models.Group{
		Name:        "engineering",
		Description: "Engineering team",
	})
	require.NoError(t, err)
	assert.Equal(t, uint(5), group.ID)
	assert.Equal(t, "engineering", group.Name)
}

func TestRemoteStorage_CreateGroup_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "CONFLICT", "message": "group already exists"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateGroup(context.Background(), &models.Group{Name: "engineering"})
	assert.Error(t, err)
}

// --- GetGroup ---

func TestRemoteStorage_GetGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/groups/5", r.URL.Path)
		_, _ = w.Write(apiOK(minimalGroupWire(5, "engineering")))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	group, err := rs.GetGroup(context.Background(), 5)
	require.NoError(t, err)
	assert.Equal(t, uint(5), group.ID)
	assert.Equal(t, "engineering", group.Name)
}

func TestRemoteStorage_GetGroup_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "NOT_FOUND", "message": "group not found"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetGroup(context.Background(), 999)
	assert.Error(t, err)
}

// --- UpdateGroup ---

func TestRemoteStorage_UpdateGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/system/groups/5", r.URL.Path)
		wire := minimalGroupWire(5, "engineering-updated")
		wire["description"] = "Updated description"
		_, _ = w.Write(apiOK(wire))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	group, err := rs.UpdateGroup(context.Background(), &models.Group{
		ID:          5,
		Name:        "engineering-updated",
		Description: "Updated description",
	})
	require.NoError(t, err)
	assert.Equal(t, "engineering-updated", group.Name)
	assert.Equal(t, "Updated description", group.Description)
}

// --- DeleteGroup ---

func TestRemoteStorage_DeleteGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/system/groups/5", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteGroup(context.Background(), 5)
	require.NoError(t, err)
}

// --- RestoreGroup ---

func TestRemoteStorage_RestoreGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/groups/5/restore", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RestoreGroup(context.Background(), 5)
	require.NoError(t, err)
}

// --- ListGroups ---

func TestRemoteStorage_ListGroups(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/groups", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"groups": []interface{}{
				minimalGroupWire(1, "admins"),
				minimalGroupWire(2, "developers"),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	groups, err := rs.ListGroups(context.Background())
	require.NoError(t, err)
	assert.Len(t, groups, 2)
	assert.Equal(t, "admins", groups[0].Name)
}

func TestRemoteStorage_ListGroups_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "BAD_REQUEST", "message": "server error"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListGroups(context.Background())
	assert.Error(t, err)
}

// --- ListGroupsPage ---

func TestRemoteStorage_ListGroupsPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/groups/page", r.URL.Path)
		assert.Equal(t, "0", r.URL.Query().Get("offset"))
		assert.Equal(t, "10", r.URL.Query().Get("limit"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"groups": []interface{}{
				minimalGroupWire(1, "admins"),
			},
			"total": float64(1),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	groups, total, err := rs.ListGroupsPage(context.Background(), 0, 10)
	require.NoError(t, err)
	assert.Len(t, groups, 1)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, "admins", groups[0].Name)
}

// --- AddUserToGroup ---

func TestRemoteStorage_AddUserToGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/groups/5/members", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	// AddUserToGroup(ctx, userID, groupID, projectID)
	err = rs.AddUserToGroup(context.Background(), 1, 5, 0)
	require.NoError(t, err)
}

func TestRemoteStorage_AddUserToGroup_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "CONFLICT", "message": "already member"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.AddUserToGroup(context.Background(), 1, 5, 0)
	assert.Error(t, err)
}

// --- RemoveUserFromGroup ---

func TestRemoteStorage_RemoveUserFromGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		// projectID=0 → path includes ?project_id=0
		assert.Equal(t, "/api/v1/system/groups/5/members/1", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	// RemoveUserFromGroup(ctx, userID, groupID, projectID)
	err = rs.RemoveUserFromGroup(context.Background(), 1, 5, 0)
	require.NoError(t, err)
}

// --- ListGroupMembers ---

func TestRemoteStorage_ListGroupMembers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/groups/5/members", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"members": []interface{}{
				minimalUserWire(1, "alice", "alice@example.com"),
				minimalUserWire(2, "bob", "bob@example.com"),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	members, err := rs.ListGroupMembers(context.Background(), 5)
	require.NoError(t, err)
	assert.Len(t, members, 2)
	assert.Equal(t, "alice", members[0].Username)
	assert.Equal(t, "bob", members[1].Username)
}

func TestRemoteStorage_ListGroupMembers_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "NOT_FOUND", "message": "group not found"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListGroupMembers(context.Background(), 999)
	assert.Error(t, err)
}

// --- ListGroupMembersByGroupIDs ---

func TestRemoteStorage_ListGroupMembersByGroupIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/groups/members-by-ids", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"1": []interface{}{
				minimalUserWire(10, "alice", "alice@example.com"),
			},
			"2": []interface{}{
				minimalUserWire(11, "bob", "bob@example.com"),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.ListGroupMembersByGroupIDs(context.Background(), []uint{1, 2})
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Len(t, result[1], 1)
	assert.Equal(t, "alice", result[1][0].Username)
	assert.Len(t, result[2], 1)
	assert.Equal(t, "bob", result[2][0].Username)
}

func TestRemoteStorage_ListGroupMembersByGroupIDs_Empty(t *testing.T) {
	// No HTTP server needed — the function short-circuits on empty input.
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19999"))
	require.NoError(t, err)

	result, err := rs.ListGroupMembersByGroupIDs(context.Background(), []uint{})
	require.NoError(t, err)
	assert.Empty(t, result)
}

// --- Password history stubs ---
//
// G80 158-method classification pass (docs/adr-087-remote-storage-deletion-pass.md):
// these three used to silently no-op (claiming success / returning an empty
// result with no error) — confirmed DEAD (no live caller under
// storage.type: remote; the only reaching entries, CreateUser and friends,
// are behind a NewRemoteClient() guard), converted to explicit stubs.

func TestRemoteStorage_PasswordHistoryStubs_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19999"))
	require.NoError(t, err)
	ctx := context.Background()

	err = rs.AddPasswordHistory(ctx, 1, "hashvalue", time.Now())
	assert.True(t, errors.Is(err, store.ErrRemoteUnsupported), "expected ErrRemoteUnsupported, got %v", err)

	hashes, err := rs.RecentPasswordHashes(ctx, 1, 5)
	assert.True(t, errors.Is(err, store.ErrRemoteUnsupported), "expected ErrRemoteUnsupported, got %v", err)
	assert.Nil(t, hashes)

	err = rs.PrunePasswordHistory(ctx, 1, 10)
	assert.True(t, errors.Is(err, store.ErrRemoteUnsupported), "expected ErrRemoteUnsupported, got %v", err)
}
