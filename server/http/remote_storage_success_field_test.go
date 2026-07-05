package http

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoteStorage_SuccessFieldFix_RealServerRoundTrip proves the fix for the
// missing "success" key in the shared HTTP success envelope (server/http/handlers/
// helpers.go's sendSuccess, plus the three per-handler duplicates in
// secrets_handler.go/rotation_policies_handler.go/shares_handler.go) end-to-end
// against a REAL, production server — not a hand-rolled mock.
//
// Before the fix: internal/storage/remote.APIResponse.Success (the field every
// internal/storage/store/remote_*.go method branches on to decide success/failure)
// silently defaulted to Go's zero value, false, for EVERY genuinely successful 2xx
// response from a real server, because sendSuccess never wrote a "success" key into
// the JSON body at all. That made storage.type: remote non-functional against a
// real upstream: every read and write was misreported as a failure, even though it
// had genuinely succeeded server-side.
//
// This test builds two independent *core.KeyorixCore instances, each with its own
// SQLite-backed storage:
//
//   - "upstream": a normal Keyorix server, exercised through the ACTUAL
//     NewRouter(...)/handlers this package registers (the real production code
//     path, not a synthetic stand-in of the wire protocol).
//   - "downstream": a store.RemoteStorage pointed at "upstream" over real HTTP —
//     exactly the storage.type: remote deployment mode (ADR-049) describes.
//
// It drives several distinct real operations (single-resource GET, filtered
// LIST, and a mutating PUT) through the downstream RemoteStorage client and
// asserts each one is read back as success (not misreported as an error) AND
// that the data returned is the real data that lives in the upstream's own
// storage — proving the round trip, not just "the call didn't error".
func TestRemoteStorage_SuccessFieldFix_RealServerRoundTrip(t *testing.T) {
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

	// Seed real data directly against the upstream's own core (bypassing the wire
	// entirely for setup, so the test's assertions are only about the read/write
	// paths this fix touches, not about unrelated wire-DTO shape mismatches between
	// RemoteStorage's raw-model POST bodies and the REST handlers' own request DTOs).
	adminUser, err := upstreamCore.Storage().GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)

	project, err := upstreamCore.CreateProject(ctx, "e2e-success-field-project", "seeded for the sendSuccess fix e2e test")
	require.NoError(t, err)
	envs, err := upstreamCore.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs, "CreateProject must seed default environments")
	envID := envs[0].ID

	secret, err := upstreamCore.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          "e2e-success-field-secret",
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

	// --- GET a single user ---
	// Before the fix, GET /api/v1/users/{id} genuinely returns 200 with the real
	// user, but RemoteStorage.GetUser saw Success==false (the zero value) and
	// returned an error instead — the read that DID succeed server-side was
	// reported as a failure to the caller.
	gotUser, err := rs.GetUser(ctx, adminUser.ID)
	require.NoError(t, err, "GetUser must not be misreported as a failure for a genuinely successful upstream response")
	assert.Equal(t, adminUser.Username, gotUser.Username)
	assert.Equal(t, adminUser.Email, gotUser.Email)

	// --- LIST users (filtered) ---
	users, total, err := rs.ListUsers(ctx, &coreStorage.UserFilter{Page: 1, PageSize: 50})
	require.NoError(t, err, "ListUsers must not be misreported as a failure for a genuinely successful upstream response")
	assert.GreaterOrEqual(t, total, int64(1))
	found := false
	for _, u := range users {
		if u.ID == adminUser.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "the seeded admin user must be present in the real upstream's own ListUsers result")

	// --- GET a single secret ---
	gotSecret, err := rs.GetSecret(ctx, secret.ID)
	require.NoError(t, err, "GetSecret must not be misreported as a failure for a genuinely successful upstream response")
	assert.Equal(t, secret.Name, gotSecret.Name)
	assert.Equal(t, secret.ProjectID, gotSecret.ProjectID)

	// NOTE: GetSecretByName is deliberately not exercised here — it targets
	// /api/v1/secrets/by-name/{name}, a route that server/http/router.go never
	// registers at all (confirmed: no "by-name" route exists), so it 404s for an
	// unrelated, pre-existing reason having nothing to do with this fix. Left as a
	// separate follow-up finding rather than folded into this fix's scope.

	// --- LIST secrets (filtered by project) ---
	secrets, secTotal, err := rs.ListSecrets(ctx, &coreStorage.SecretFilter{ProjectID: &project.ID, Page: 1, PageSize: 50})
	require.NoError(t, err, "ListSecrets must not be misreported as a failure for a genuinely successful upstream response")
	assert.Equal(t, int64(1), secTotal)
	require.Len(t, secrets, 1)
	assert.Equal(t, secret.ID, secrets[0].ID)

	// --- a genuine mutating write (PUT) ---
	// Exercises the mutating-response path (not just GET), which goes through the
	// exact same sendSuccess helper. Before the fix this also always looked like a
	// failure even though the upstream had genuinely applied the update and
	// returned 200.
	//
	// NOTE: models.SecretNode carries no JSON tags (its fields serialize as plain
	// Go field names, e.g. "MaxReads"), while UpdateSecret's handler decodes a
	// snake_case DTO (e.g. "max_reads") — a separate, pre-existing wire-shape
	// mismatch (same class of issue as CreateUser's DisplayName/display_name
	// mismatch found during investigation) that silently no-ops any field-level
	// change sent this way. That's out of this fix's scope, so this step proves
	// the PUT round-trip genuinely reached and re-persisted the row server-side —
	// via UpdatedAt, which core.UpdateSecret always bumps — rather than asserting
	// a specific field value changed.
	beforeUpdatedAt := secret.UpdatedAt
	newMaxReads := 7
	updated, err := rs.UpdateSecret(ctx, &models.SecretNode{ID: secret.ID, MaxReads: &newMaxReads})
	require.NoError(t, err, "UpdateSecret must not be misreported as a failure for a genuinely successful upstream response")
	require.NotNil(t, updated)

	// Confirm the write genuinely landed by reading it back directly from the
	// upstream's OWN storage (not just "the client call didn't error").
	directRead, err := upstreamCore.Storage().GetSecret(ctx, secret.ID)
	require.NoError(t, err)
	assert.True(t, directRead.UpdatedAt.After(beforeUpdatedAt),
		"the downstream's forwarded PUT must be a real row-level write reaching the upstream's own secret_nodes table, not a call that merely didn't error")
}
