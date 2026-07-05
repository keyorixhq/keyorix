package http

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoteStorage_GetSecretByName_RealServerRoundTrip proves the fix for #497:
// RemoteStorage.GetSecretByName targeted /api/v1/secrets/by-name/{name}, a route
// server/http/router.go never registered, so every call 404'd against a real
// production server regardless of whether the secret actually existed.
//
// The fix adds GET /api/v1/secrets/by-name (query-parameter scoped, mirroring
// ListSecrets' project_id/environment_id convention rather than a path segment)
// and points RemoteStorage.GetSecretByName's client-side URL construction at it.
//
// Like TestRemoteStorage_SuccessFieldFix_RealServerRoundTrip, this drives the
// method through a REAL running server (NewRouter) via a REAL RemoteStorage
// client over real HTTP — not a hand-rolled mock — so the test would have failed
// against the pre-fix code with a 404, not just against a synthetic stand-in of
// the route.
func TestRemoteStorage_GetSecretByName_RealServerRoundTrip(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	// --- upstream: a real Keyorix server ---
	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	defer upstreamSrv.Close()

	ctx := context.Background()

	adminUser, err := upstreamCore.Storage().GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)

	project, err := upstreamCore.CreateProject(ctx, "e2e-get-by-name-project", "seeded for the GetSecretByName route fix e2e test (#497)")
	require.NoError(t, err)
	envs, err := upstreamCore.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs, "CreateProject must seed default environments")
	envID := envs[0].ID

	secret, err := upstreamCore.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          "e2e-get-by-name-secret",
		Value:         []byte("s3cr3t-value"),
		ProjectID:     project.ID,
		EnvironmentID: envID,
		Type:          "generic",
		CreatedBy:     adminUser.Username,
		OwnerID:       adminUser.ID,
	})
	require.NoError(t, err)

	// --- downstream: storage.type: remote, pointed at the upstream ---
	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         upstreamToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)

	// --- the secret genuinely exists: must be found, not 404 ---
	got, err := rs.GetSecretByName(ctx, secret.Name, project.ID, envID)
	require.NoError(t, err, "GetSecretByName must reach the real /api/v1/secrets/by-name route and succeed for a secret that genuinely exists (#497)")
	require.NotNil(t, got)
	assert.Equal(t, secret.ID, got.ID)
	assert.Equal(t, secret.Name, got.Name)
	assert.Equal(t, project.ID, got.ProjectID)
	assert.Equal(t, envID, got.EnvironmentID)

	// --- the secret genuinely does NOT exist: must be a real not-found, not a
	// routing 404 confused with "found nothing" ---
	_, err = rs.GetSecretByName(ctx, "does-not-exist-at-all", project.ID, envID)
	require.Error(t, err, "a name that genuinely doesn't exist must still return an error")

	// --- a name that IS registered, but scoped to the wrong project/environment,
	// must also fail closed rather than leaking across scope ---
	otherProject, err := upstreamCore.CreateProject(ctx, "e2e-get-by-name-other-project", "a second project the secret does not belong to")
	require.NoError(t, err)
	otherEnvs, err := upstreamCore.ListEnvironmentsByProject(ctx, otherProject.ID)
	require.NoError(t, err)
	require.NotEmpty(t, otherEnvs)

	_, err = rs.GetSecretByName(ctx, secret.Name, otherProject.ID, otherEnvs[0].ID)
	require.Error(t, err, "the same secret name must not resolve under a different project/environment scope")
}
