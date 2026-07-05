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
	"github.com/stretchr/testify/require"
)

// TestRemoteStorage_DeleteUserAndDeleteSecret_204NoContent_RealServerRoundTrip
// pins the fix for #498: RemoteStorage.DeleteUser/DeleteSecret gate on
// resp.Success, which internal/storage/remote/client.go's makeRequest derives
// from JSON-unmarshaling the response body. The REAL handlers
// (server/http/handlers/users_crud.go's DeleteUser, secrets_crud.go's
// DeleteSecret) return 204 No Content with a genuinely empty body — the
// idiomatic REST shape for a successful delete with nothing to return.
//
// Before the fix: json.Unmarshal on the zero-byte body errored with "unexpected
// end of JSON input", and makeRequest's parse-error branch synthesized
// APIResponse{Success: false, Error: {Code: "HTTP_204", ...}} — so a delete that
// genuinely succeeded server-side (confirmed via a direct read against the
// upstream's own storage) was reported back to the caller as a failure.
//
// This test builds a real upstream Keyorix server via NewRouter and a real
// store.RemoteStorage client pointed at it over HTTP — not a hand-rolled mock
// that could mask the bug by returning Success: true directly.
func TestRemoteStorage_DeleteUserAndDeleteSecret_204NoContent_RealServerRoundTrip(t *testing.T) {
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

	// A second, non-admin user to delete — DeleteUser refuses to delete the
	// last install administrator, so the seeded bootstrap admin can't be used
	// for this test.
	victimUser, err := upstreamCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "delete-me",
		Email:    "delete-me@example.com",
		Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	adminUser, err := upstreamCore.Storage().GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)

	project, err := upstreamCore.CreateProject(ctx, "e2e-delete-204-project", "seeded for the #498 delete/204 e2e test")
	require.NoError(t, err)
	envs, err := upstreamCore.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs, "CreateProject must seed default environments")
	envID := envs[0].ID

	secret, err := upstreamCore.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          "e2e-delete-204-secret",
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

	// --- DeleteUser: the real handler returns 204 No Content, empty body ---
	err = rs.DeleteUser(ctx, victimUser.ID)
	require.NoError(t, err, "DeleteUser must not be misreported as a failure for a genuine 204 No Content success")

	// Confirm the delete genuinely landed server-side, not just "the call
	// didn't error".
	_, err = upstreamCore.Storage().GetUserByEmail(ctx, "delete-me@example.com")
	require.Error(t, err, "the user must actually be gone from the upstream's own storage")

	// --- DeleteSecret: same 204/empty-body shape ---
	err = rs.DeleteSecret(ctx, secret.ID)
	require.NoError(t, err, "DeleteSecret must not be misreported as a failure for a genuine 204 No Content success")

	_, err = upstreamCore.Storage().GetSecret(ctx, secret.ID)
	require.Error(t, err, "the secret must actually be gone (soft-deleted) from the upstream's own storage")
}
