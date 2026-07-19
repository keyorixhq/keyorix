// remote_coverage_policies_memberships_auth_test.go — targeted coverage for
// !resp.Success and network-error branches in remote_break_glass.go,
// remote_memberships.go, remote_rotation_policies.go, remote_risk_exceptions.go,
// remote_auth.go, remote_login_attempts.go, remote_scheduler_lock.go,
// remote_secret_dependencies.go, remote_access_activity.go, and
// remote_legal_hold.go.
//
// Strategy: for each method that has a !resp.Success branch, add a test that
// returns HTTP 200 with {"success":false,"error":{...}} to exercise that branch.
// For methods that only had success-path tests, add error-path tests. For
// helpers tested indirectly (decodeXxx, newSchedulerLockHolderToken), exercise
// them through their caller or via a server that returns the decode shape.
package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// remote_break_glass.go — !resp.Success branches
// ============================================================

func TestRemoteCov_CreateBreakGlassActivation_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "server failure"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateBreakGlassActivation(context.Background(), &models.BreakGlassActivation{State: "active"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create break-glass activation failed")
}

func TestRemoteCov_GetBreakGlassActivation_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetBreakGlassActivation(context.Background(), 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get break-glass activation failed")
}

func TestRemoteCov_UpdateBreakGlassActivation_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "update failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.UpdateBreakGlassActivation(context.Background(), &models.BreakGlassActivation{ID: 5})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update break-glass activation failed")
}

// decodeBreakGlassActivationResponse is exercised by GetBreakGlassActivation.
// Test that a bad JSON body returns an error from the decode helper.
func TestRemoteCov_DecodeBreakGlassActivation_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return success:true but with unparseable data so the decode helper fails.
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetBreakGlassActivation(context.Background(), 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// ============================================================
// remote_memberships.go — !resp.Success branches
// ============================================================

func TestRemoteCov_CreateProjectMembership_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "membership creation failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateProjectMembership(context.Background(), &models.ProjectMembership{ProjectID: 1, UserID: 2})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create membership failed")
}

func TestRemoteCov_GetProjectMembership_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "membership not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetProjectMembership(context.Background(), 42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get membership failed")
}

func TestRemoteCov_UpdateProjectMembership_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "update failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.UpdateProjectMembership(context.Background(), &models.ProjectMembership{ID: 7, ProjectID: 1, UserID: 2})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update membership failed")
}

func TestRemoteCov_ListProjectMemberships_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "list failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListProjectMemberships(context.Background(), 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list memberships failed")
}

func TestRemoteCov_ListStaleInvitedMemberships_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "stale list failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListStaleInvitedMemberships(context.Background(), time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list stale invited memberships failed")
}

func TestRemoteCov_ListUserProjectMemberships_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "user not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListUserProjectMemberships(context.Background(), 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list user memberships failed")
}

// decodeMembershipResponse is exercised by GetProjectMembership.
// Test that a bad JSON body returns an error from the decode helper.
func TestRemoteCov_DecodeMembershipResponse_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetProjectMembership(context.Background(), 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// ============================================================
// remote_rotation_policies.go — !resp.Success branches
// ============================================================

func TestRemoteCov_GetRotationPolicy_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "policy not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetRotationPolicy(context.Background(), 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get rotation policy failed")
}

func TestRemoteCov_DeleteRotationPolicy_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "policy not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteRotationPolicy(context.Background(), 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete rotation policy failed")
}

func TestRemoteCov_CreateRotationPolicy_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "create failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	p := &models.RotationPolicy{Name: "daily", IntervalDays: 1, CreatedBy: "admin"}
	err = rs.CreateRotationPolicy(context.Background(), p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create rotation policy failed")
}

func TestRemoteCov_UpdateRotationPolicy_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "update failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	p := &models.RotationPolicy{ID: 3, Name: "weekly", IntervalDays: 7, CreatedBy: "admin"}
	err = rs.UpdateRotationPolicy(context.Background(), p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update rotation policy failed")
}

func TestRemoteCov_ListRotationPolicies_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "list failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	pid := uint(10)
	_, err = rs.ListRotationPolicies(context.Background(), &pid, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list rotation policies failed")
}

// Exercise the success path for GetRotationPolicy to cover the json.Unmarshal branch.
func TestRemoteCov_GetRotationPolicy_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/rotation-policies/2", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]any{
			"ID":           2,
			"Name":         "daily-rotation",
			"IntervalDays": 1,
			"CreatedBy":    "admin",
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	p, err := rs.GetRotationPolicy(context.Background(), 2)
	require.NoError(t, err)
	assert.Equal(t, uint(2), p.ID)
}

// Exercise the success path for CreateRotationPolicy to cover the json.Unmarshal+assign branch.
func TestRemoteCov_CreateRotationPolicy_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/rotation-policies", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]any{
			"ID":           7,
			"Name":         "weekly",
			"IntervalDays": 7,
			"CreatedBy":    "admin",
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	p := &models.RotationPolicy{Name: "weekly", IntervalDays: 7, CreatedBy: "admin"}
	err = rs.CreateRotationPolicy(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, uint(7), p.ID)
}

// Exercise the success path for UpdateRotationPolicy to cover the json.Unmarshal+assign branch.
func TestRemoteCov_UpdateRotationPolicy_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		_, _ = w.Write(apiOK(map[string]any{
			"ID":           3,
			"Name":         "monthly",
			"IntervalDays": 30,
			"CreatedBy":    "admin",
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	p := &models.RotationPolicy{ID: 3, Name: "monthly", IntervalDays: 30, CreatedBy: "admin"}
	err = rs.UpdateRotationPolicy(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, uint(3), p.ID)
}

// ============================================================
// remote_risk_exceptions.go — !resp.Success branches
// ============================================================

func TestRemoteCov_CreateRiskException_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "create failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateRiskException(context.Background(), &models.RiskException{
		Title: "test", Category: "mfa", Justification: "needed", CreatedBy: 1,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create risk exception failed")
}

func TestRemoteCov_GetRiskException_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "exception not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetRiskException(context.Background(), 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get risk exception failed")
}

func TestRemoteCov_UpdateRiskException_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "update failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.UpdateRiskException(context.Background(), &models.RiskException{
		ID: 6, Title: "test", Category: "sod", Justification: "still needed", CreatedBy: 1,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update risk exception failed")
}

// decodeRiskExceptionResponse is exercised by GetRiskException.
// Test that a bad JSON body returns an error from the decode helper.
func TestRemoteCov_DecodeRiskExceptionResponse_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetRiskException(context.Background(), 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// ============================================================
// remote_auth.go — !resp.Success branches
// ============================================================

func TestRemoteCov_CleanupExpiredSessions_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/sessions/cleanup", r.URL.Path)
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "cleanup failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.CleanupExpiredSessions(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cleanup expired sessions failed")
}

func TestRemoteCov_CleanupExpiredSessions_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/sessions/cleanup", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.CleanupExpiredSessions(context.Background())
	require.NoError(t, err)
}

// decodeSetupTokenResponse: exercise by CreateSetupToken returning a valid body.
func TestRemoteCov_DecodeSetupTokenResponse_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return success:true with unparseable data so the decode helper fails.
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	// GetSetupTokenByHash calls decodeSetupTokenResponse
	_, err = rs.GetSetupTokenByHash(context.Background(), "abc123hash")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// ============================================================
// remote_login_attempts.go — !resp.Success branches
// ============================================================

func TestRemoteCov_PruneLoginAttempts_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/login-attempts/prune", r.URL.Path)
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "prune failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.PruneLoginAttempts(context.Background(), time.Now().Add(-24*time.Hour))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prune login attempts failed")
}

func TestRemoteCov_RecordLoginAttempt_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/login-attempts", r.URL.Path)
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "record failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RecordLoginAttempt(context.Background(), "10.0.0.2", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "record login attempt failed")
}

func TestRemoteCov_CountRecentLoginAttempts_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "count failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountRecentLoginAttempts(context.Background(), "10.0.0.2", time.Now().Add(-time.Hour))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "count login attempts failed")
}

// ============================================================
// remote_scheduler_lock.go — !resp.Success branches
// ============================================================

func TestRemoteCov_TryAcquireSchedulerLock_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/scheduler-lock/acquire", r.URL.Path)
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "acquire failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.TryAcquireSchedulerLock(context.Background(), 42, "holder-token", 30*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acquire scheduler lock failed")
}

func TestRemoteCov_ReleaseSchedulerLock_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/scheduler-lock/release", r.URL.Path)
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "release failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.ReleaseSchedulerLock(context.Background(), 42, "holder-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "release scheduler lock failed")
}

// newSchedulerLockHolderToken is exercised by WithSchedulerLock internally.
// Test TryAcquireSchedulerLock success path (which parses the "acquired" field)
// to cover the json.Unmarshal branch and the function's return path.
func TestRemoteCov_TryAcquireSchedulerLock_Success_Acquired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/scheduler-lock/acquire", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]any{"acquired": true}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	acquired, err := rs.TryAcquireSchedulerLock(context.Background(), 1, "test-holder", 45*time.Second)
	require.NoError(t, err)
	assert.True(t, acquired)
}

func TestRemoteCov_TryAcquireSchedulerLock_Success_NotAcquired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]any{"acquired": false}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	acquired, err := rs.TryAcquireSchedulerLock(context.Background(), 1, "test-holder", 45*time.Second)
	require.NoError(t, err)
	assert.False(t, acquired)
}

// Test WithSchedulerLock to exercise newSchedulerLockHolderToken indirectly
// and cover the acquire-failed-to-acquire (lock contended) branch.
func TestRemoteCov_WithSchedulerLock_NotAcquired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Lock is held by someone else — return acquired:false.
		_, _ = w.Write(apiOK(map[string]any{"acquired": false}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	ran := false
	got, err := rs.WithSchedulerLock(context.Background(), 7, func() error {
		ran = true
		return nil
	})
	require.NoError(t, err)
	assert.False(t, got, "should report lock not acquired")
	assert.False(t, ran, "fn must not run when lock was not acquired")
}

// ============================================================
// remote_secret_dependencies.go — !resp.Success branches
// ============================================================

func TestRemoteCov_CreateSecretDependency_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/secret-dependencies", r.URL.Path)
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "create failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateSecretDependency(context.Background(), &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 2, DependsOnSecretID: 3,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create secret dependency failed")
}

func TestRemoteCov_GetSecretDependency_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		_, _ = w.Write(apiNotOK("NOT_FOUND", "dependency not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetSecretDependency(context.Background(), 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get secret dependency failed")
}

func TestRemoteCov_DeleteSecretDependency_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		_, _ = w.Write(apiNotOK("NOT_FOUND", "dependency not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteSecretDependency(context.Background(), 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete secret dependency failed")
}

// decodeSecretDependencyResponse is exercised by GetSecretDependency.
// Test that a bad JSON body returns an error from the decode helper.
func TestRemoteCov_DecodeSecretDependencyResponse_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetSecretDependency(context.Background(), 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// ============================================================
// remote_access_activity.go — !resp.Success branch (getAccessActivity)
// ============================================================

func TestRemoteCov_GetAccessActivity_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "activity query failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	// LastUserSecretActivity calls getAccessActivity("secret", projectID)
	_, err = rs.LastUserSecretActivity(context.Background(), 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get secret activity failed")
}

// ============================================================
// remote_legal_hold.go — !resp.Success branches
// ============================================================

func TestRemoteCov_CreateLegalHold_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/legal-hold", r.URL.Path)
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "create failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateLegalHold(context.Background(), &models.LegalHold{Reason: "test", PlacedBy: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create legal hold failed")
}

func TestRemoteCov_GetActiveLegalHold_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/legal-hold/active", r.URL.Path)
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "get failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetActiveLegalHold(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get active legal hold failed")
}

func TestRemoteCov_UpdateLegalHold_NotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "update failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.UpdateLegalHold(context.Background(), &models.LegalHold{
		ID: 2, Reason: "test", PlacedBy: 1, PlacedAt: time.Now().UTC(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update legal hold failed")
}
