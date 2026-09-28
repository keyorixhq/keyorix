// alert_operator_permission_test.go — F1's behavioral proof (ADR-110 follow-up,
// Andrei 2026-09-28): a user holding ONLY the alert_operator role (alerts.write)
// can manage notification channels, escalation policies, and every on-demand
// alert/reminder job trigger, and gets 403 on every route that remains gated on
// system.write. This is the behavioral counterpart to alerts_write_scope_test.go
// and system_write_scope_test.go's structural allowlist sweeps: those prove
// every gate site is reviewed and accounted for; this proves the split actually
// behaves as a narrower persona at the HTTP layer.
package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createAlertOperatorToken creates a user holding ONLY the alert_operator role
// (global scope) — no system_viewer baseline stacked on top, since
// CreateUserWithAssignments uses the given systemRole in place of the default,
// not in addition to it — and returns a session token.
func createAlertOperatorToken(t *testing.T, c *core.KeyorixCore) string {
	t.Helper()
	ctx := context.Background()
	_, err := c.CreateUserWithAssignments(ctx, &core.CreateUserRequest{
		Username: "alert_operator_user", Email: "alert_operator_user@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	}, "alert_operator", nil, 0, false)
	require.NoError(t, err)
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "alert_operator_user", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	return sess.SessionToken
}

func TestAlertOperator_PermissionTiers(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	testCore := newFullSchemaTestCore(t)
	router, err := NewRouter(&config.Config{}, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	createTestToken(t, testCore) // bootstraps the system (seeds alert_operator among defaultRoles)
	alertOpToken := createAlertOperatorToken(t, testCore)

	client := &http.Client{Timeout: 10 * time.Second}
	do := func(token, method, path string) *http.Response {
		req, err := http.NewRequest(method, server.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		return resp
	}

	// alert_operator MUST succeed on the alerts.write surface: notification
	// channels, escalation policies (list, needs no body/fixture), and every
	// on-demand job trigger F1 moved to alerts.write (none require a body).
	allowedRoutes := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/notification-channels"},
		{http.MethodGet, "/api/v1/alert-escalation-policies"},
		{http.MethodPost, "/api/v1/admin/jobs/anomaly-alerts"},
		{http.MethodPost, "/api/v1/admin/jobs/rotation-reminders"},
		{http.MethodPost, "/api/v1/admin/jobs/expiry-reminders"},
		{http.MethodPost, "/api/v1/admin/jobs/compliance-digest"},
		{http.MethodPost, "/api/v1/admin/jobs/role-expiry-check"},
		{http.MethodPost, "/api/v1/admin/jobs/check-read-quotas"},
		{http.MethodPost, "/api/v1/admin/jobs/run-alert-escalation"},
		{http.MethodPost, "/api/v1/admin/jobs/token-expiry-check"},
	}
	for _, r := range allowedRoutes {
		t.Run("allowed_"+r.method+"_"+r.path, func(t *testing.T) {
			resp := do(alertOpToken, r.method, r.path)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusOK, resp.StatusCode,
				"alert_operator (alerts.write only) must be allowed on %s %s", r.method, r.path)
		})
	}

	// alert_operator MUST be denied (403) on every route that remains gated on
	// system.write — the full systemWriteScopeAllowlist surface (16 sites as of
	// this test; see system_write_scope_test.go). Permission middleware runs
	// before the handler body/path-param validation, so a placeholder {id} and
	// an empty body are sufficient to prove the denial happens at the gate, not
	// downstream.
	deniedRoutes := []struct {
		method, path string
	}{
		{http.MethodPost, "/api/v1/audit/checkpoint"},
		{http.MethodPost, "/api/v1/audit/migrate-chain-encoding"},
		{http.MethodPost, "/api/v1/audit/anomalies/1/acknowledge"},
		{http.MethodGet, "/api/v1/admin/scheduler-metrics"},
		{http.MethodPost, "/api/v1/compliance/snapshots"},
		{http.MethodPost, "/api/v1/legal-hold"},
		{http.MethodDelete, "/api/v1/legal-hold"},
		{http.MethodPost, "/api/v1/risk-exceptions"},
		{http.MethodPost, "/api/v1/risk-exceptions/1/approve"},
		{http.MethodDelete, "/api/v1/risk-exceptions/1"},
		{http.MethodPost, "/api/v1/sod/policies"},
		{http.MethodDelete, "/api/v1/sod/policies/1"},
		{http.MethodPost, "/api/v1/admin/jobs/record-hygiene-snapshot"},
		{http.MethodPost, "/api/v1/admin/jobs/suspend-inactive-users"},
		{http.MethodPost, "/api/v1/admin/jobs/purge-audit-logs"},
		{http.MethodPut, "/api/v1/admin/anomaly-config"},
	}
	for _, r := range deniedRoutes {
		t.Run("denied_"+r.method+"_"+r.path, func(t *testing.T) {
			resp := do(alertOpToken, r.method, r.path)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusForbidden, resp.StatusCode,
				"alert_operator (alerts.write only) must be denied on system.write-only route %s %s", r.method, r.path)
		})
	}
}
