package store_test

import (
	"context"
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

// ============================================================
// remote_access_activity.go
// ============================================================

func TestRemoteStorage_LastUserSecretActivity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/access-activity/secret", r.URL.Path)
		assert.Equal(t, "42", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"activity": map[string]interface{}{
				"1": time.Now().UTC().Format(time.RFC3339),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.LastUserSecretActivity(context.Background(), 42)
	require.NoError(t, err)
	assert.NotNil(t, result)
	_, ok := result[1]
	assert.True(t, ok)
}

func TestRemoteStorage_LastUserRoleManagementActivity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/access-activity/role-management", r.URL.Path)
		assert.Equal(t, "7", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"activity": map[string]interface{}{
				"3": time.Now().UTC().Format(time.RFC3339),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.LastUserRoleManagementActivity(context.Background(), 7)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestRemoteStorage_LastUserSecretDeletionActivity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/access-activity/secret-deletion", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"activity": map[string]interface{}{}}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.LastUserSecretDeletionActivity(context.Background(), 1)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result, 0)
}

func TestRemoteStorage_LastUserSecretReadActivity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/access-activity/secret-read", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"activity": map[string]interface{}{}}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.LastUserSecretReadActivity(context.Background(), 1)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestRemoteStorage_LastUserSecretWriteActivity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/access-activity/secret-write", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"activity": map[string]interface{}{}}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.LastUserSecretWriteActivity(context.Background(), 1)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ============================================================
// remote_audit_checkpoint_lock.go
// ============================================================

func TestRemoteStorage_WithAuditCheckpointLock_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19996"))
	require.NoError(t, err)
	err = rs.WithAuditCheckpointLock(context.Background(), func() error { return nil })
	assert.Error(t, err)
}

// ============================================================
// remote_break_glass.go
// ============================================================

func TestRemoteStorage_CreateBreakGlassActivation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/break-glass", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":            10,
			"project_id":    5,
			"user_id":       2,
			"role_id":       3,
			"role_name":     "emergency-admin",
			"justification": "incident response",
			"state":         "active",
			"created_at":    now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	act, err := rs.CreateBreakGlassActivation(context.Background(), &models.BreakGlassActivation{
		ProjectID:     5,
		UserID:        2,
		RoleID:        3,
		RoleName:      "emergency-admin",
		Justification: "incident response",
		State:         "active",
	})
	require.NoError(t, err)
	assert.Equal(t, uint(10), act.ID)
	assert.Equal(t, "active", act.State)
	assert.Equal(t, "emergency-admin", act.RoleName)
}

func TestRemoteStorage_CreateBreakGlassActivation_AlreadyActive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"BREAK_GLASS_ALREADY_ACTIVE","message":"already active"}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateBreakGlassActivation(context.Background(), &models.BreakGlassActivation{State: "active"})
	require.Error(t, err)
	assert.ErrorIs(t, err, corestorage.ErrBreakGlassAlreadyActive)
}

func TestRemoteStorage_GetBreakGlassActivation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/break-glass/7", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":            7,
			"project_id":    5,
			"user_id":       2,
			"role_id":       3,
			"role_name":     "emergency-admin",
			"justification": "fire drill",
			"state":         "active",
			"created_at":    now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	act, err := rs.GetBreakGlassActivation(context.Background(), 7)
	require.NoError(t, err)
	assert.Equal(t, uint(7), act.ID)
	assert.Equal(t, "active", act.State)
}

func TestRemoteStorage_ListBreakGlassActivations(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/break-glass", r.URL.Path)
		assert.Equal(t, "5", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"activations": []map[string]interface{}{
				{
					"id":            1,
					"project_id":    5,
					"user_id":       2,
					"role_id":       3,
					"role_name":     "emergency-admin",
					"justification": "outage",
					"state":         "revoked",
					"created_at":    now,
				},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListBreakGlassActivations(context.Background(), 5)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, uint(1), list[0].ID)
	assert.Equal(t, "revoked", list[0].State)
}

func TestRemoteStorage_UpdateBreakGlassActivation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/system/break-glass/9", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.UpdateBreakGlassActivation(context.Background(), &models.BreakGlassActivation{
		ID:        9,
		ProjectID: 5,
		UserID:    2,
		RoleID:    3,
		State:     "expired",
		CreatedAt: now,
	})
	assert.NoError(t, err)
}

func TestRemoteStorage_RevokeBreakGlassActivation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/break-glass/9/revoke", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RevokeBreakGlassActivation(context.Background(), 9, 1, now)
	assert.NoError(t, err)
}

func TestRemoteStorage_RevokeBreakGlassActivation_NotActive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"BREAK_GLASS_NOT_ACTIVE","message":"not active"}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RevokeBreakGlassActivation(context.Background(), 9, 1, time.Now())
	require.Error(t, err)
	assert.ErrorIs(t, err, corestorage.ErrBreakGlassNotActive)
}

// ============================================================
// remote_legal_hold.go
// ============================================================

func TestRemoteStorage_CreateLegalHold(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/legal-hold", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":       3,
			"reason":   "litigation hold",
			"placed_by": 1,
			"placed_at": now,
			"released":  false,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	hold, err := rs.CreateLegalHold(context.Background(), &models.LegalHold{
		Reason:   "litigation hold",
		PlacedBy: 1,
		PlacedAt: now,
	})
	require.NoError(t, err)
	assert.Equal(t, uint(3), hold.ID)
	assert.Equal(t, "litigation hold", hold.Reason)
	assert.False(t, hold.Released)
}

func TestRemoteStorage_CreateLegalHold_AlreadyActive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"LEGAL_HOLD_ALREADY_ACTIVE","message":"already active"}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateLegalHold(context.Background(), &models.LegalHold{Reason: "dup"})
	require.Error(t, err)
	assert.ErrorIs(t, err, corestorage.ErrLegalHoldAlreadyActive)
}

func TestRemoteStorage_GetActiveLegalHold_Active(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/legal-hold/active", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"active": true,
			"hold": map[string]interface{}{
				"id":        2,
				"reason":    "eDiscovery",
				"placed_by": 1,
				"placed_at": now,
				"released":  false,
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	hold, err := rs.GetActiveLegalHold(context.Background())
	require.NoError(t, err)
	require.NotNil(t, hold)
	assert.Equal(t, uint(2), hold.ID)
	assert.Equal(t, "eDiscovery", hold.Reason)
}

func TestRemoteStorage_GetActiveLegalHold_None(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{"active": false}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	hold, err := rs.GetActiveLegalHold(context.Background())
	require.NoError(t, err)
	assert.Nil(t, hold)
}

func TestRemoteStorage_UpdateLegalHold(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/system/legal-hold/4", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.UpdateLegalHold(context.Background(), &models.LegalHold{
		ID:       4,
		Reason:   "eDiscovery",
		PlacedBy: 1,
		PlacedAt: now,
		Released: true,
	})
	assert.NoError(t, err)
}

// ============================================================
// remote_login_attempts.go
// ============================================================

func TestRemoteStorage_RecordLoginAttempt(t *testing.T) {
	now := time.Now().UTC()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/login-attempts", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RecordLoginAttempt(context.Background(), "192.168.1.1", now)
	assert.NoError(t, err)
}

func TestRemoteStorage_CountRecentLoginAttempts(t *testing.T) {
	since := time.Now().UTC().Add(-10 * time.Minute)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/login-attempts/count", r.URL.Path)
		assert.Equal(t, "10.0.0.1", r.URL.Query().Get("ip"))
		assert.NotEmpty(t, r.URL.Query().Get("since"))
		_, _ = w.Write(apiOK(map[string]interface{}{"count": 3}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	count, err := rs.CountRecentLoginAttempts(context.Background(), "10.0.0.1", since)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestRemoteStorage_PruneLoginAttempts(t *testing.T) {
	before := time.Now().UTC().Add(-24 * time.Hour)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/login-attempts/prune", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"deleted": 12}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	deleted, err := rs.PruneLoginAttempts(context.Background(), before)
	require.NoError(t, err)
	assert.Equal(t, int64(12), deleted)
}

// ============================================================
// remote_login_verify.go
// ============================================================

func TestRemoteStorage_VerifyLoginCredentials_NoMFA(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(24 * time.Hour)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/users/verify-credentials", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":               7,
			"username":         "alice",
			"email":            "alice@example.com",
			"display_name":     "Alice",
			"account_state":    "active",
			"mfa_enabled":      false,
			"webauthn_enabled": false,
			"session": map[string]interface{}{
				"id":         99,
				"token":      "tok-abc",
				"family_id":  "fam-1",
				"created_at": now,
				"expires_at": expires,
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	user, session, err := rs.VerifyLoginCredentials(context.Background(), "alice", "s3cr3t", "Mozilla/5.0", "10.0.0.1")
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, uint(7), user.ID)
	assert.Equal(t, "alice", user.Username)
	require.NotNil(t, session)
	assert.Equal(t, uint(99), session.ID)
	assert.Equal(t, "tok-abc", session.SessionToken)
	assert.Equal(t, "10.0.0.1", session.IPAddress)
}

func TestRemoteStorage_VerifyLoginCredentials_MFARequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":               8,
			"username":         "bob",
			"email":            "bob@example.com",
			"display_name":     "Bob",
			"account_state":    "active",
			"mfa_enabled":      true,
			"webauthn_enabled": false,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	user, session, err := rs.VerifyLoginCredentials(context.Background(), "bob", "pass", "UA", "127.0.0.1")
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, uint(8), user.ID)
	assert.True(t, user.MFAEnabled)
	assert.Nil(t, session, "session must be nil when MFA is required")
}

func TestRemoteStorage_VerifyLoginCredentials_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"INVALID_CREDENTIALS","message":"wrong password"}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, _, err = rs.VerifyLoginCredentials(context.Background(), "alice", "wrong", "UA", "127.0.0.1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid credentials")
}

// ============================================================
// remote_risk_exceptions.go
// ============================================================

func TestRemoteStorage_CreateRiskException(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	exp := now.Add(30 * 24 * time.Hour)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/risk-exceptions", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":            5,
			"title":         "MFA waiver",
			"category":      "mfa",
			"justification": "vendor constraint",
			"created_by":    1,
			"created_at":    now,
			"expires_at":    exp,
			"revoked":       false,
			"approved":      false,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	exc, err := rs.CreateRiskException(context.Background(), &models.RiskException{
		Title:         "MFA waiver",
		Category:      "mfa",
		Justification: "vendor constraint",
		CreatedBy:     1,
		ExpiresAt:     exp,
	})
	require.NoError(t, err)
	assert.Equal(t, uint(5), exc.ID)
	assert.Equal(t, "MFA waiver", exc.Title)
}

func TestRemoteStorage_ListRiskExceptions(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	exp := now.Add(30 * 24 * time.Hour)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/risk-exceptions", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"exceptions": []map[string]interface{}{
				{
					"id":            1,
					"title":         "SoD exception",
					"category":      "sod",
					"justification": "small team",
					"created_by":    1,
					"created_at":    now,
					"expires_at":    exp,
					"revoked":       false,
					"approved":      true,
				},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListRiskExceptions(context.Background(), false)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "SoD exception", list[0].Title)
	assert.True(t, list[0].Approved)
}

func TestRemoteStorage_ListRiskExceptions_ActiveOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "true", r.URL.Query().Get("active_only"))
		_, _ = w.Write(apiOK(map[string]interface{}{"exceptions": []interface{}{}}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListRiskExceptions(context.Background(), true)
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestRemoteStorage_GetRiskException(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	exp := now.Add(10 * 24 * time.Hour)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/risk-exceptions/3", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":            3,
			"title":         "Rotation skip",
			"category":      "rotation",
			"justification": "legacy system",
			"created_by":    2,
			"created_at":    now,
			"expires_at":    exp,
			"revoked":       false,
			"approved":      false,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	exc, err := rs.GetRiskException(context.Background(), 3)
	require.NoError(t, err)
	assert.Equal(t, uint(3), exc.ID)
	assert.Equal(t, "Rotation skip", exc.Title)
}

func TestRemoteStorage_UpdateRiskException(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	exp := now.Add(30 * 24 * time.Hour)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/system/risk-exceptions/6", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.UpdateRiskException(context.Background(), &models.RiskException{
		ID:            6,
		Title:         "updated",
		Category:      "mfa",
		Justification: "still needed",
		CreatedBy:     1,
		CreatedAt:     now,
		ExpiresAt:     exp,
		Revoked:       true,
	})
	assert.NoError(t, err)
}

// ============================================================
// remote_rotation_policies.go
// ============================================================

func TestRemoteStorage_CreateRotationPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/rotation-policies", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"ID":        1,
			"ProjectID": 10,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	pid := uint(10)
	p := &models.RotationPolicy{ProjectID: &pid}
	err = rs.CreateRotationPolicy(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, uint(1), p.ID)
}

func TestRemoteStorage_GetRotationPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/rotation-policies/4", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"ID":        4,
			"ProjectID": 10,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	p, err := rs.GetRotationPolicy(context.Background(), 4)
	require.NoError(t, err)
	assert.Equal(t, uint(4), p.ID)
}

func TestRemoteStorage_ListRotationPolicies(t *testing.T) {
	pid := uint(10)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/rotation-policies", r.URL.Path)
		assert.Equal(t, "10", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK([]interface{}{
			map[string]interface{}{"ID": 1, "ProjectID": 10},
			map[string]interface{}{"ID": 2, "ProjectID": 10},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListRotationPolicies(context.Background(), &pid, nil)
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestRemoteStorage_UpdateRotationPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/rotation-policies/3", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"ID": 3, "ProjectID": 10}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	pid := uint(10)
	p := &models.RotationPolicy{ID: 3, ProjectID: &pid}
	err = rs.UpdateRotationPolicy(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, uint(3), p.ID)
}

func TestRemoteStorage_DeleteRotationPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/rotation-policies/5", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteRotationPolicy(context.Background(), 5)
	assert.NoError(t, err)
}

// ============================================================
// remote_scheduler_lock.go
// ============================================================

func TestRemoteStorage_TryAcquireSchedulerLock_Acquired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/scheduler-lock/acquire", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"acquired": true}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	acquired, err := rs.TryAcquireSchedulerLock(context.Background(), 42, "holder-token", 45*time.Second)
	require.NoError(t, err)
	assert.True(t, acquired)
}

func TestRemoteStorage_TryAcquireSchedulerLock_NotAcquired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{"acquired": false}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	acquired, err := rs.TryAcquireSchedulerLock(context.Background(), 42, "holder-token", 45*time.Second)
	require.NoError(t, err)
	assert.False(t, acquired)
}

func TestRemoteStorage_ReleaseSchedulerLock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/scheduler-lock/release", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.ReleaseSchedulerLock(context.Background(), 42, "holder-token")
	assert.NoError(t, err)
}

func TestRemoteStorage_WithSchedulerLock_AcquiredAndRuns(t *testing.T) {
	var callCount int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/system/scheduler-lock/acquire":
			callCount++
			_, _ = w.Write(apiOK(map[string]interface{}{"acquired": true}))
		case "/api/v1/system/scheduler-lock/release":
			_, _ = w.Write(apiOK(nil))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	ran := false
	acquired, err := rs.WithSchedulerLock(context.Background(), 1, func() error {
		ran = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, acquired)
	assert.True(t, ran)
}

func TestRemoteStorage_WithSchedulerLock_NotAcquired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{"acquired": false}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	ran := false
	acquired, err := rs.WithSchedulerLock(context.Background(), 1, func() error {
		ran = true
		return nil
	})
	require.NoError(t, err)
	assert.False(t, acquired)
	assert.False(t, ran)
}

// ============================================================
// remote_secret_dependencies.go
// ============================================================

func TestRemoteStorage_CreateSecretDependency(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/secret-dependencies", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":                   10,
			"project_id":           5,
			"dependent_secret_id":  1,
			"depends_on_secret_id": 2,
			"note":                 "db password",
			"created_at":           now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	dep, err := rs.CreateSecretDependency(context.Background(), &models.SecretDependency{
		ProjectID:         5,
		DependentSecretID: 1,
		DependsOnSecretID: 2,
		Note:              "db password",
	})
	require.NoError(t, err)
	assert.Equal(t, uint(10), dep.ID)
	assert.Equal(t, "db password", dep.Note)
}

func TestRemoteStorage_GetSecretDependency(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/secret-dependencies/10", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":                   10,
			"project_id":           5,
			"dependent_secret_id":  1,
			"depends_on_secret_id": 2,
			"created_at":           now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	dep, err := rs.GetSecretDependency(context.Background(), 10)
	require.NoError(t, err)
	assert.Equal(t, uint(10), dep.ID)
	assert.Equal(t, uint(1), dep.DependentSecretID)
}

func TestRemoteStorage_ListSecretDependenciesForProject(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/secret-dependencies", r.URL.Path)
		assert.Equal(t, "5", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"dependencies": []map[string]interface{}{
				{
					"id":                   10,
					"project_id":           5,
					"dependent_secret_id":  1,
					"depends_on_secret_id": 2,
					"created_at":           now,
				},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListSecretDependenciesForProject(context.Background(), 5)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, uint(10), list[0].ID)
}

func TestRemoteStorage_ListSecretDependenciesForProjectForUpdate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/secret-dependencies/for-update", r.URL.Path)
		assert.Equal(t, "5", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"dependencies": []map[string]interface{}{
				{
					"id":                   11,
					"project_id":           5,
					"dependent_secret_id":  3,
					"depends_on_secret_id": 4,
					"created_at":           now,
				},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListSecretDependenciesForProjectForUpdate(context.Background(), 5)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, uint(11), list[0].ID)
}

func TestRemoteStorage_DeleteSecretDependency(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/system/secret-dependencies/7", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteSecretDependency(context.Background(), 7)
	assert.NoError(t, err)
}

func TestRemoteStorage_CreateSecretDependencyExclusive(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/secret-dependencies/exclusive", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":                   20,
			"project_id":           5,
			"dependent_secret_id":  1,
			"depends_on_secret_id": 2,
			"created_at":           now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	dep, err := rs.CreateSecretDependencyExclusive(context.Background(), &models.SecretDependency{
		ProjectID:         5,
		DependentSecretID: 1,
		DependsOnSecretID: 2,
	})
	require.NoError(t, err)
	assert.Equal(t, uint(20), dep.ID)
}

func TestRemoteStorage_CreateSecretDependencyExclusive_Duplicate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"DUPLICATE_SECRET_DEPENDENCY","message":"already exists"}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateSecretDependencyExclusive(context.Background(), &models.SecretDependency{
		ProjectID:         5,
		DependentSecretID: 1,
		DependsOnSecretID: 2,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, corestorage.ErrDuplicateSecretDependency)
}

func TestRemoteStorage_CreateSecretDependencyExclusive_Cycle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"SECRET_DEPENDENCY_CYCLE","message":"would create cycle"}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateSecretDependencyExclusive(context.Background(), &models.SecretDependency{
		ProjectID:         5,
		DependentSecretID: 2,
		DependsOnSecretID: 1,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, corestorage.ErrSecretDependencyCycle)
}

// ============================================================
// remote_sod.go
// ============================================================

func TestRemoteStorage_CreateSoDPolicy(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/sod-policies", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":           3,
			"name":         "no-assign-delete",
			"permission_a": "roles.assign",
			"permission_b": "secrets.delete",
			"created_by":   1,
			"created_at":   now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	p, err := rs.CreateSoDPolicy(context.Background(), &models.SoDPolicy{
		Name:        "no-assign-delete",
		PermissionA: "roles.assign",
		PermissionB: "secrets.delete",
		CreatedBy:   1,
	})
	require.NoError(t, err)
	assert.Equal(t, uint(3), p.ID)
	assert.Equal(t, "no-assign-delete", p.Name)
}

func TestRemoteStorage_GetSoDPolicy(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/sod-policies/3", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":           3,
			"name":         "no-assign-delete",
			"permission_a": "roles.assign",
			"permission_b": "secrets.delete",
			"created_by":   1,
			"created_at":   now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	p, err := rs.GetSoDPolicy(context.Background(), 3)
	require.NoError(t, err)
	assert.Equal(t, uint(3), p.ID)
}

func TestRemoteStorage_ListSoDPolicies(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/sod-policies", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"policies": []map[string]interface{}{
				{
					"id":           1,
					"name":         "policy-a",
					"permission_a": "roles.assign",
					"permission_b": "secrets.delete",
					"created_by":   1,
					"created_at":   now,
				},
				{
					"id":           2,
					"name":         "policy-b",
					"permission_a": "users.write",
					"permission_b": "audit.read",
					"created_by":   1,
					"created_at":   now,
				},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListSoDPolicies(context.Background())
	require.NoError(t, err)
	assert.Len(t, list, 2)
	assert.Equal(t, "policy-a", list[0].Name)
}

func TestRemoteStorage_DeleteSoDPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/system/sod-policies/3", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteSoDPolicy(context.Background(), 3)
	assert.NoError(t, err)
}

// ============================================================
// remote_sso.go
// ============================================================

func TestRemoteStorage_CreateSSOLoginState(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/sso-state", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":         55,
			"state":      "csrf-token-abc",
			"nonce":      "nonce-xyz",
			"provider":   "google",
			"return_to":  "/dashboard",
			"expires_at": now.Add(5 * time.Minute),
			"created_at": now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	s := &models.SSOLoginState{
		State:     "csrf-token-abc",
		Nonce:     "nonce-xyz",
		Provider:  "google",
		ReturnTo:  "/dashboard",
		ExpiresAt: now.Add(5 * time.Minute),
		CreatedAt: now,
	}
	err = rs.CreateSSOLoginState(context.Background(), s)
	require.NoError(t, err)
	assert.Equal(t, uint(55), s.ID, "ID should be updated in place from the server response")
}

func TestRemoteStorage_ConsumeSSOLoginState(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/sso-state/consume", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":         55,
			"state":      "csrf-token-abc",
			"nonce":      "nonce-xyz",
			"provider":   "google",
			"return_to":  "/dashboard",
			"expires_at": now.Add(5 * time.Minute),
			"created_at": now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	s, err := rs.ConsumeSSOLoginState(context.Background(), "csrf-token-abc")
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.Equal(t, uint(55), s.ID)
	assert.Equal(t, "csrf-token-abc", s.State)
	assert.Equal(t, "nonce-xyz", s.Nonce)
	assert.Equal(t, "google", s.Provider)
}

// ============================================================
// remote_stats.go
// ============================================================

func TestRemoteStorage_GetStats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/stats", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"total_secrets":    5,
			"total_users":      3,
			"total_roles":      2,
			"total_sessions":   1,
			"total_audit_logs": 100,
			"database_size_bytes": 4096,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	stats, err := rs.GetStats(context.Background())
	require.NoError(t, err)
	require.NotNil(t, stats)
	assert.Equal(t, int64(5), stats.TotalSecrets)
	assert.Equal(t, int64(3), stats.TotalUsers)
	assert.Equal(t, int64(2), stats.TotalRoles)
}

func TestRemoteStorage_SaveStatsSnapshot_NoOp(t *testing.T) {
	// SaveStatsSnapshot is a no-op in remote mode — no HTTP call is made.
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19997"))
	require.NoError(t, err)

	err = rs.SaveStatsSnapshot(context.Background(), &models.StatsSnapshot{})
	assert.NoError(t, err)
}

func TestRemoteStorage_GetPreviousStatsSnapshot_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19997"))
	require.NoError(t, err)

	snap, err := rs.GetPreviousStatsSnapshot(context.Background(), 1)
	assert.Error(t, err)
	assert.Nil(t, snap)
	assert.Contains(t, err.Error(), "remote mode")
}

func TestRemoteStorage_HealthCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/health", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]string{"status": "healthy"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.HealthCheck(context.Background())
	assert.NoError(t, err)
}

// ============================================================
// remote_transaction.go
// ============================================================

func TestRemoteStorage_WithTransaction_RunsFn(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19998"))
	require.NoError(t, err)

	ran := false
	err = rs.WithTransaction(context.Background(), func(tx corestorage.Storage) error {
		assert.Same(t, rs, tx, "WithTransaction must pass the same RemoteStorage to fn")
		ran = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, ran)
}

func TestRemoteStorage_WithTransaction_PropagatesError(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19998"))
	require.NoError(t, err)

	wantErr := assert.AnError
	err = rs.WithTransaction(context.Background(), func(_ corestorage.Storage) error {
		return wantErr
	})
	assert.ErrorIs(t, err, wantErr)
}
