// crypto_inventory_rbac_test.go — RD-CBOM-1: GET /api/v1/compliance/crypto-inventory
// is an admin/auditor read. Driven through the real router with real sessions: a
// global admin and a system_auditor (audit.read) get the inventory in both formats;
// a system_viewer (no audit.read) and an unauthenticated caller do not.
package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

func createRoleToken(t *testing.T, c *core.KeyorixCore, username, role string) string {
	t.Helper()
	ctx := context.Background()
	const pw = "Qr7#Kp2$Lm5@Vn9!"
	_, err := c.CreateUserWithAssignments(ctx, &core.CreateUserRequest{
		Username: username, Email: username + "@example.com", Password: pw,
	}, role, nil, 0, false)
	require.NoError(t, err)
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: username, Password: pw})
	require.NoError(t, err)
	return sess.SessionToken
}

func TestCryptoInventory_OnlyAdminAndAuditorMayRead(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	testCore := newFullSchemaTestCore(t)
	router, err := NewRouter(&config.Config{}, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	adminToken := createTestToken(t, testCore)
	auditorToken := createRoleToken(t, testCore, "cbom_auditor", "system_auditor")
	viewerToken := createRoleToken(t, testCore, "cbom_viewer", "system_viewer")

	client := &http.Client{Timeout: 10 * time.Second}
	get := func(token, query string) (int, string) {
		t.Helper()
		req, rerr := http.NewRequest(http.MethodGet, server.URL+"/api/v1/compliance/crypto-inventory"+query, nil)
		require.NoError(t, rerr)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, derr := client.Do(req)
		require.NoError(t, derr)
		defer func() { _ = resp.Body.Close() }()
		b, rerr := io.ReadAll(resp.Body)
		require.NoError(t, rerr)
		return resp.StatusCode, string(b)
	}

	for _, q := range []string{"", "?format=cbom"} {
		status, body := get(adminToken, q)
		assert.Equal(t, http.StatusOK, status, "admin %q: %s", q, body)
		status, body = get(auditorToken, q)
		assert.Equal(t, http.StatusOK, status, "auditor %q: %s", q, body)

		status, body = get(viewerToken, q)
		assert.Equal(t, http.StatusForbidden, status, "a system_viewer must not read the inventory %q: %s", q, body)
		assert.NotContains(t, body, "assets")
		status, _ = get("", q)
		assert.Equal(t, http.StatusUnauthorized, status, "unauthenticated %q", q)
	}
}
