// remote_coverage_test.go — error-path coverage for remote storage functions
// that have success tests but no !resp.Success (or network error) branch tested,
// leaving the error-return branch uncovered.
//
// Coverage targets (in priority order):
//   - remote_stats.go:GetStats (66.7%)
//   - remote_sod.go:CreateSoDPolicy/ListSoDPolicies (66.7%), GetSoDPolicy (70.0%)
//   - remote_webauthn.go:AdvanceWebAuthnCredentialCounter (66.7%)
//   - remote_sharing.go:CheckSharePermission/DeleteExpiredShareRecords (70.0%)
//   - remote_sso.go:CreateSSOLoginState/ConsumeSSOLoginState (70.0%)
//   - remote_audit.go:GetAuditLogs/GetRBACAuditLogs (70.0%)
//   - remote_webauthn.go:CreateWebAuthnCredential/CreateWebAuthnSession (70.0%)
//   - remote_users.go:toModel/decodeUserResponse (75.0%) via DeletedAt branch
//
// The !resp.Success branches in every remote_*.go method are reached only when
// the upstream returns HTTP 200 with {"success":false,...}. A 4xx/5xx response
// is consumed entirely by the HTTP client layer (which returns an error directly
// from makeRequest, before the caller ever sees resp), so error-path tests MUST
// use HTTP 200 + success:false to exercise the !resp.Success branches.
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

// apiNotOK returns an HTTP 200 body with success:false and a populated error
// object. This is the ONLY way to exercise the `!resp.Success` branches in
// remote_*.go: a 4xx/5xx upstream response is consumed entirely by the HTTP
// client layer (HTTPError path), which means the function's own error wrap
// (`fmt.Errorf("failed to get stats: %w", err)`) fires but the `resp.Error`
// branch does not. The actual Keyorix server never returns 200+success:false
// in steady state, but this wire format IS valid per APIResponse's schema.
func apiNotOK(code, message string) []byte {
	b, _ := json.Marshal(map[string]any{
		"success": false,
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
	return b
}

// ─── remote_stats.go ────────────────────────────────────────────────────────

// TestRemoteCov_GetStats_Unsupported: #1511/G80 deletion pass — no matching
// route, server-only caller; see docs/adr-087-remote-storage-deletion-pass.md.
func TestRemoteCov_GetStats_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetStats(context.Background())
	assert.True(t, errors.Is(err, store.ErrRemoteUnsupported),
		"expected ErrRemoteUnsupported, got %v", err)
}

// ─── remote_sod.go ──────────────────────────────────────────────────────────

func TestRemoteCov_CreateSoDPolicy_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/sod-policies", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]any{
			"id":           float64(1),
			"name":         "no-admin-and-billing",
			"permission_a": "admin",
			"permission_b": "billing",
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	p := &models.SoDPolicy{
		Name:        "no-admin-and-billing",
		PermissionA: "admin",
		PermissionB: "billing",
	}
	result, err := rs.CreateSoDPolicy(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
	assert.Equal(t, "no-admin-and-billing", result.Name)
}

func TestRemoteCov_CreateSoDPolicy_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("CONFLICT", "policy already exists"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateSoDPolicy(context.Background(), &models.SoDPolicy{Name: "dup"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create SoD policy failed")
}

func TestRemoteCov_GetSoDPolicy_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/sod-policies/5", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]any{
			"id":           float64(5),
			"name":         "no-admin-and-deploy",
			"permission_a": "admin",
			"permission_b": "deploy",
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.GetSoDPolicy(context.Background(), 5)
	require.NoError(t, err)
	assert.Equal(t, uint(5), result.ID)
	assert.Equal(t, "no-admin-and-deploy", result.Name)
}

func TestRemoteCov_GetSoDPolicy_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "policy not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetSoDPolicy(context.Background(), 999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get SoD policy failed")
}

func TestRemoteCov_ListSoDPolicies_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/sod-policies", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]any{
			"policies": []map[string]any{
				{
					"id":           float64(1),
					"name":         "no-admin-and-billing",
					"permission_a": "admin",
					"permission_b": "billing",
				},
				{
					"id":           float64(2),
					"name":         "no-audit-and-deploy",
					"permission_a": "audit",
					"permission_b": "deploy",
				},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	policies, err := rs.ListSoDPolicies(context.Background())
	require.NoError(t, err)
	assert.Len(t, policies, 2)
	assert.Equal(t, "no-admin-and-billing", policies[0].Name)
}

func TestRemoteCov_ListSoDPolicies_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "db error"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListSoDPolicies(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list SoD policies failed")
}

func TestRemoteCov_DeleteSoDPolicy_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "policy not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteSoDPolicy(context.Background(), 999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delete SoD policy failed")
}

// ─── remote_sso.go ──────────────────────────────────────────────────────────

func TestRemoteCov_CreateSSOLoginState_Success(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/sso-state", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]any{
			"id":         float64(10),
			"state":      "csrf-state-abc",
			"nonce":      "nonce-xyz",
			"provider":   "oidc",
			"return_to":  "/dashboard",
			"expires_at": now.Add(5 * time.Minute),
			"created_at": now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	s := &models.SSOLoginState{
		State:     "csrf-state-abc",
		Nonce:     "nonce-xyz",
		Provider:  "oidc",
		ReturnTo:  "/dashboard",
		ExpiresAt: now.Add(5 * time.Minute),
	}
	err = rs.CreateSSOLoginState(context.Background(), s)
	require.NoError(t, err)
	// The method copies the upstream-assigned ID back into s.
	assert.Equal(t, uint(10), s.ID)
}

func TestRemoteCov_CreateSSOLoginState_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "db write failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	s := &models.SSOLoginState{State: "state-x", Provider: "oidc"}
	err = rs.CreateSSOLoginState(context.Background(), s)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create SSO login state failed")
}

func TestRemoteCov_ConsumeSSOLoginState_Success(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/sso-state/consume", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]any{
			"id":         float64(10),
			"state":      "csrf-state-abc",
			"nonce":      "nonce-xyz",
			"provider":   "oidc",
			"return_to":  "/dashboard",
			"expires_at": now.Add(5 * time.Minute),
			"created_at": now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.ConsumeSSOLoginState(context.Background(), "csrf-state-abc")
	require.NoError(t, err)
	assert.Equal(t, uint(10), result.ID)
	assert.Equal(t, "oidc", result.Provider)
	assert.Equal(t, "nonce-xyz", result.Nonce)
}

func TestRemoteCov_ConsumeSSOLoginState_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "state not found or already consumed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ConsumeSSOLoginState(context.Background(), "no-such-state")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "consume SSO login state failed")
}

// ─── remote_audit.go ────────────────────────────────────────────────────────

func TestRemoteCov_GetAuditLogs_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "db error"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	action := "secret.read"
	filter := &corestorage.AuditFilter{
		Action:   &action,
		Page:     1,
		PageSize: 10,
	}
	_, _, err = rs.GetAuditLogs(context.Background(), filter)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get audit logs failed")
}

func TestRemoteCov_GetRBACAuditLogs_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "db error"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	action := "role.assign"
	filter := &corestorage.RBACAuditFilter{
		Action:   &action,
		Page:     1,
		PageSize: 10,
	}
	_, _, err = rs.GetRBACAuditLogs(context.Background(), filter)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get RBAC audit logs failed")
}

// ─── remote_webauthn.go ─────────────────────────────────────────────────────

func TestRemoteCov_AdvanceWebAuthnCredentialCounter_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("CONFLICT", "counter already advanced"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	advanced, err := rs.AdvanceWebAuthnCredentialCounter(
		context.Background(),
		[]byte{0xBE, 0xEF},
		7,
		[]byte(`{"signCount":10}`),
		10,
		time.Now(),
	)
	assert.Error(t, err)
	assert.False(t, advanced)
	assert.Contains(t, err.Error(), "advance webauthn credential counter failed")
}

func TestRemoteCov_CreateWebAuthnSession_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "db write failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	s := &models.WebAuthnSession{
		UserID:    7,
		TokenHash: "session-hash",
		Purpose:   "register",
		Data:      []byte(`{}`),
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	err = rs.CreateWebAuthnSession(context.Background(), s)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create webauthn session failed")
}

// ─── remote_sharing.go ──────────────────────────────────────────────────────

// CheckSharePermission is a permanent stub as of the #1511/G80 deletion pass
// — see TestRemoteStorage_CheckSharePermission_Unsupported (remote_sharing_test.go).

func TestRemoteCov_DeleteExpiredShareRecords_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "db error"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.DeleteExpiredShareRecords(context.Background(), time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "purge expired share records failed")
}

// ─── remote_users.go: toModel / decodeUserResponse ──────────────────────────
// These helpers are exercised through GetUser. The toModel DeletedAt branch
// (the `if w.DeletedAt != nil` path, line ~200) is only reachable when the
// wire response carries a non-nil deleted_at timestamp, which no existing test
// provides.

func TestRemoteCov_GetUser_WithDeletedAt(t *testing.T) {
	deletedAt := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/users/42", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]any{
			"id":                    float64(42),
			"username":              "former-user",
			"email":                 "former@example.com",
			"display_name":          "Former User",
			"active":                false,
			"account_state":         "deleted",
			"external_id":           "",
			"mfa_enabled":           false,
			"created_at":            time.Now().Add(-100 * 24 * time.Hour).UTC().Format(time.RFC3339),
			"updated_at":            time.Now().UTC().Format(time.RFC3339),
			"last_login_at":         nil,
			"deleted_at":            deletedAt.Format(time.RFC3339),
			"failed_login_attempts": 0,
			"login_lockout_count":   0,
			"last_failed_login_at":  nil,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	user, err := rs.GetUser(context.Background(), 42)
	require.NoError(t, err)
	assert.Equal(t, uint(42), user.ID)
	assert.Equal(t, "former-user", user.Username)
	// DeletedAt should be set (non-zero Valid flag).
	assert.True(t, user.DeletedAt.Valid, "expected DeletedAt.Valid=true for a soft-deleted user")
	assert.WithinDuration(t, deletedAt, user.DeletedAt.Time, time.Second)
}

// TestRemoteCov_decodeUserResponse_BadJSON exercises the json.Unmarshal error
// path in decodeUserResponse. We provoke it by returning a valid 200 envelope
// but with data = a JSON string (not an object), causing the struct decode of
// userWireResponse to fail.
func TestRemoteCov_decodeUserResponse_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Return a valid envelope but with data = a JSON string (not an object).
		_, _ = w.Write([]byte(`{"success":true,"data":"this-is-not-a-user-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetUser(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// ─── Additional error paths for existing sharing functions ──────────────────

// CreateShareRecord/GetShareRecord are permanent stubs as of the #1511/G80
// deletion pass — see TestRemoteStorage_CreateShareRecord_Unsupported/
// TestRemoteStorage_GetShareRecord_Unsupported (remote_sharing_test.go).

func TestRemoteCov_UpdateShareRecord_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "share not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.UpdateShareRecord(context.Background(), &models.ShareRecord{ID: 999, SecretID: 1})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "update share record failed")
}

func TestRemoteCov_ListSharesBySecret_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "secret not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListSharesBySecret(context.Background(), 999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list shares by secret failed")
}

func TestRemoteCov_ListSharesByUser_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "user not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListSharesByUser(context.Background(), 999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list shares by user failed")
}

func TestRemoteCov_ListSharesByOwner_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "owner not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListSharesByOwner(context.Background(), 999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list shares by owner failed")
}

func TestRemoteCov_ListSharesByGroup_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "group not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListSharesByGroup(context.Background(), 999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list shares by group failed")
}

// ListSharedSecrets is a permanent stub as of the #1511/G80 deletion pass —
// see TestRemoteStorage_ListSharedSecrets_Unsupported (remote_sharing_test.go).

// ─── LogAuditEvent error path ─────────────────────────────────────────────

func TestRemoteCov_LogAuditEvent_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "db write failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.LogAuditEvent(context.Background(), &models.AuditEvent{EventType: "test.event"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "log audit event failed")
}

// ─── WebAuthn additional error paths ──────────────────────────────────────

func TestRemoteCov_ListWebAuthnCredentials_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "db error"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListWebAuthnCredentials(context.Background(), 7)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list webauthn credentials failed")
}

func TestRemoteCov_GetWebAuthnCredentialByCredID_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "credential not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetWebAuthnCredentialByCredID(context.Background(), []byte{0x01}, 7)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get webauthn credential failed")
}

func TestRemoteCov_UpdateWebAuthnCredential_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "credential not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.UpdateWebAuthnCredential(context.Background(), &models.WebAuthnCredential{ID: 999})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "update webauthn credential failed")
}

func TestRemoteCov_CountWebAuthnCredentials_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "db error"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountWebAuthnCredentials(context.Background(), 7)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "count webauthn credentials failed")
}
