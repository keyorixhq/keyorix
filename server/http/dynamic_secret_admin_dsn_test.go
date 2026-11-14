// dynamic_secret_admin_dsn_test.go — DYNAMIC-ADMIN-DSN-1 item 1, REST:
// PATCH /api/v1/dynamic-secrets/configs/{id}/admin-dsn replaces the stored DSN
// under create's checks, against a real router.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/identity"
)

const httpADSNSecret = "http-adsn-S3cr3t-93be"

// projectWriterToken logs in a user holding secrets.read+write (no admin
// authority) on the fixture config's own project.
func (f *dynSecret403Fixture) projectWriterToken(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	cfg, err := f.core.GetDynamicSecretConfig(ctx, f.configID)
	require.NoError(t, err)
	perms, err := f.core.ListPermissions(ctx)
	require.NoError(t, err)
	admin, err := f.core.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	name, err := identity.NewFoldedName("adsn-project-writer")
	require.NoError(t, err)
	role, err := f.core.Storage().CreateRole(ctx, name, "writer")
	require.NoError(t, err)
	for _, p := range perms {
		if p.Name == "secrets.read" || p.Name == "secrets.write" {
			require.NoError(t, f.core.AssignPermissionToRole(ctx, admin.ID, role.ID, p.ID, false))
		}
	}
	u, err := f.core.CreateUser(ctx, &core.CreateUserRequest{Username: "adsnwriter", Email: "adsnwriter@example.com", Password: "Xk9#mQ7zLp2!vR4u"})
	require.NoError(t, err)
	require.NoError(t, f.core.Storage().AssignRole(ctx, u.ID, role.ID, core.Scope{ProjectID: cfg.ProjectID}))
	session, _, err := f.core.Login(ctx, &core.LoginRequest{Username: "adsnwriter", Password: "Xk9#mQ7zLp2!vR4u"})
	require.NoError(t, err)
	return session.SessionToken
}

func (f *dynSecret403Fixture) patchAdminDSN(t *testing.T, token string, adminDSN string) (int, string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"admin_dsn": adminDSN})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%s/api/v1/dynamic-secrets/configs/%d/admin-dsn", f.serverURL, f.configID), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String()
}

func (f *dynSecret403Fixture) storedAdminDSNEnc(t *testing.T) []byte {
	t.Helper()
	cfg, err := f.core.GetDynamicSecretConfig(context.Background(), f.configID)
	require.NoError(t, err)
	return cfg.AdminDSNEnc
}

func TestDynamicSecretUpdateAdminDSN_REST(t *testing.T) {
	f := newDynSecret403Fixture(t)
	writer := f.projectWriterToken(t)
	before := f.storedAdminDSNEnc(t)
	check := func(t *testing.T, wantStatus int, status int, body string) {
		t.Helper()
		require.Equal(t, wantStatus, status, body)
		assert.NotContains(t, body, httpADSNSecret, "the DSN reached the client")
	}

	t.Run("refused option", func(t *testing.T) {
		status, body := f.patchAdminDSN(t, f.adminToken, "postgres://admin:"+httpADSNSecret+"@203.0.113.10/app?sslrootcert=/etc/keyorix/ca.pem")
		check(t, http.StatusBadRequest, status, body)
		assert.Contains(t, body, "sslrootcert", "name the refused option")
		assert.Equal(t, before, f.storedAdminDSNEnc(t))
	})
	t.Run("private host", func(t *testing.T) {
		status, body := f.patchAdminDSN(t, f.adminToken, "postgres://admin:"+httpADSNSecret+"@10.0.0.5/app")
		check(t, http.StatusBadRequest, status, body)
		assert.Contains(t, body, "dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets")
		assert.Equal(t, before, f.storedAdminDSNEnc(t))
	})
	t.Run("project writer without admin authority", func(t *testing.T) {
		status, body := f.patchAdminDSN(t, writer, "postgres://admin:"+httpADSNSecret+"@203.0.113.10/app")
		check(t, http.StatusForbidden, status, body)
		assert.Equal(t, before, f.storedAdminDSNEnc(t))
	})
	t.Run("caller with no access to the config", func(t *testing.T) {
		status, body := f.patchAdminDSN(t, f.limitedToken, "postgres://admin:"+httpADSNSecret+"@203.0.113.10/app")
		check(t, http.StatusForbidden, status, body)
		assert.Equal(t, before, f.storedAdminDSNEnc(t))
	})
	t.Run("accepted", func(t *testing.T) {
		status, body := f.patchAdminDSN(t, f.adminToken, "postgres://admin:"+httpADSNSecret+"@203.0.113.10/app")
		check(t, http.StatusOK, status, body)
		assert.NotContains(t, body, "admin_dsn", "the DSN is never returned")
		// This fixture runs with encryption off (passthrough); encryption at rest is
		// covered by internal/core TestDynamicSecrets_UpdateAdminDSN_DSNNeverLeaves.
		assert.NotEqual(t, before, f.storedAdminDSNEnc(t), "the stored DSN changed")
	})
}

func (f *dynSecret403Fixture) getRefused(t *testing.T, token string, projectID uint) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/dynamic-secrets/configs/refused-admin-dsn?project_id=%d", f.serverURL, projectID), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String()
}

// TestDynamicSecretRefusedAdminDSNList_REST (item 2): a config stored with a
// refused option is listed by name and option names, and gone once its DSN is
// replaced; only an admin on the project gets the list.
func TestDynamicSecretRefusedAdminDSNList_REST(t *testing.T) {
	f := newDynSecret403Fixture(t)
	writer := f.projectWriterToken(t)
	ctx := context.Background()
	cfg, err := f.core.GetDynamicSecretConfig(ctx, f.configID)
	require.NoError(t, err)
	// Store a pre-#3952 DSN directly (encryption is off in this fixture).
	legacy := "postgres://admin:" + httpADSNSecret + "@203.0.113.10/app?sslrootcert=/etc/keyorix/ca.pem&sslkey=/etc/keyorix/k.pem"
	require.NoError(t, f.core.Storage().SetDynamicSecretConfigAdminDSN(ctx, cfg.ID, []byte(legacy), nil))

	status, body := f.getRefused(t, f.adminToken, cfg.ProjectID)
	require.Equal(t, http.StatusOK, status, body)
	assert.NotContains(t, body, httpADSNSecret)
	assert.NotContains(t, body, "/etc/keyorix", "option names only")
	var got struct {
		Data struct {
			Configs []struct {
				ID             uint     `json:"id"`
				Name           string   `json:"name"`
				RefusedOptions []string `json:"refused_options"`
			} `json:"configs"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &got))
	require.Len(t, got.Data.Configs, 1, body)
	assert.Equal(t, cfg.ID, got.Data.Configs[0].ID)
	assert.Equal(t, cfg.Name, got.Data.Configs[0].Name)
	assert.Equal(t, []string{"sslrootcert", "sslkey"}, got.Data.Configs[0].RefusedOptions)

	for name, token := range map[string]string{"project writer": writer, "other project": f.limitedToken} {
		status, body := f.getRefused(t, token, cfg.ProjectID)
		require.Equal(t, http.StatusForbidden, status, "%s: %s", name, body)
		assert.NotContains(t, body, cfg.Name)
	}
	status, _ = f.getRefused(t, f.adminToken, 0)
	require.Equal(t, http.StatusBadRequest, status)

	status, body = f.patchAdminDSN(t, f.adminToken, "postgres://admin:"+httpADSNSecret+"@203.0.113.10/app")
	require.Equal(t, http.StatusOK, status, body)
	status, body = f.getRefused(t, f.adminToken, cfg.ProjectID)
	require.Equal(t, http.StatusOK, status, body)
	require.NoError(t, json.Unmarshal([]byte(body), &got))
	assert.Empty(t, got.Data.Configs, "nothing left to fix: %s", body)
}
