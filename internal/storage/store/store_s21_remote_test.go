// store_s21_remote_test.go — remote coverage sweep for s21 gaps.
//
// Targets (remote_users.go — CreateUserWithRoleGrants branches):
//   - line 658: errors.As(err, &httpErr) && httpErr.ErrorType == duplicateEmailProxyCode
//     -> storage.ErrDuplicateEmail sentinel (DUPLICATE_EMAIL wire code)
//   - line 661: generic HTTP error fallthrough (non-DUPLICATE_EMAIL code)
//   - line 663: !resp.Success branch (2xx with success:false)
package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// s21FlatError returns the flat server-error JSON body that the remote client
// parses into an *HTTPError with ErrorType == code and Message == msg.
func s21FlatError(code, msg string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"success": false,
		"error":   code,
		"message": msg,
	})
	return b
}

// s21Grants returns a minimal slice of RoleGrant values for use in test calls.
func s21Grants() []corestorage.RoleGrant {
	return []corestorage.RoleGrant{
		{RoleID: 2, Scope: corestorage.Scope{ProjectID: 1, EnvironmentID: 0}},
	}
}

// ---------------------------------------------------------------------------
// CreateUserWithRoleGrants — DUPLICATE_EMAIL error (line 658)
//
// When the server returns a 4xx response whose "error" field is
// "DUPLICATE_EMAIL", the client returns an *HTTPError whose ErrorType matches
// duplicateEmailProxyCode. CreateUserWithRoleGrants must wrap that into
// storage.ErrDuplicateEmail so core.CreateUserWithAssignments' errors.Is check
// is preserved across the HTTP hop.
// ---------------------------------------------------------------------------

func TestCreateUserWithRoleGrants_S21_DuplicateEmail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/users/with-role-grants", r.URL.Path)
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write(s21FlatError("DUPLICATE_EMAIL", "a user with this email already exists"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateUserWithRoleGrants(context.Background(), &models.User{
		Username:     "alice",
		Email:        "alice@example.com",
		DisplayName:  "Alice",
		IsActive:     true,
		AccountState: "active",
	}, s21Grants())

	require.Error(t, err)
	assert.True(t, errors.Is(err, corestorage.ErrDuplicateEmail),
		"expected ErrDuplicateEmail to be wrapped, got: %v", err)
}

// ---------------------------------------------------------------------------
// CreateUserWithRoleGrants — generic HTTP error fallthrough (line 661)
//
// When the server returns a 4xx/5xx response whose "error" field is NOT
// "DUPLICATE_EMAIL", the method must return a plain error that does NOT wrap
// storage.ErrDuplicateEmail.
// ---------------------------------------------------------------------------

func TestCreateUserWithRoleGrants_S21_GenericHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(s21FlatError("INTERNAL_ERROR", "something went wrong"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateUserWithRoleGrants(context.Background(), &models.User{
		Username:     "bob",
		Email:        "bob@example.com",
		AccountState: "active",
	}, s21Grants())

	require.Error(t, err)
	assert.False(t, errors.Is(err, corestorage.ErrDuplicateEmail),
		"generic HTTP error must not be ErrDuplicateEmail")
	assert.Contains(t, err.Error(), "failed to create user with role grants")
}

// ---------------------------------------------------------------------------
// CreateUserWithRoleGrants — !resp.Success branch (line 663)
//
// When the server returns a 200 with {"success":false,...}, makeRequest parses
// it as an APIResponse (not an HTTPError), so rs.client.Post returns
// (resp, nil) with resp.Success == false. CreateUserWithRoleGrants must
// surface an error from that branch.
// ---------------------------------------------------------------------------

func TestCreateUserWithRoleGrants_S21_SuccessFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		b, _ := json.Marshal(map[string]interface{}{
			"success": false,
			"error": map[string]interface{}{
				"code":    "VALIDATION_ERROR",
				"message": "invalid role grant",
			},
		})
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateUserWithRoleGrants(context.Background(), &models.User{
		Username:     "carol",
		Email:        "carol@example.com",
		AccountState: "active",
	}, s21Grants())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "create user with role grants failed")
}
