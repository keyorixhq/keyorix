// remote_storage_plaintext_channel_test.go — end-to-end regression coverage for
// #499: storage.Storage.CreateUser/CreateSecret had no field or argument at all
// to carry the plaintext password/secret value, so — even after #496's wire-DTO
// field-name fix — RemoteStorage.CreateUser/CreateSecret could never fully
// succeed against a real upstream server; they'd always fail the handler's
// "password"/"value is required" check. #496's own test file
// (remote_storage_field_mismatch_test.go) proves exactly that residual failure
// mode. This file proves the fix: with the plaintext threaded through
// storage.Storage.CreateUser/CreateSecret's new optional variadic argument, both
// calls now genuinely succeed end-to-end — not just "the wire shape is
// correct", but the account is created with a real, usable password and the
// secret is created with its real value, both durably landing in the
// upstream's own storage — driven through the full core.CreateUser/
// core.CreateSecret business logic (core.NewKeyorixCore(rs) as the downstream,
// exactly as a real storage.type: remote deployment would run it), against a
// REAL upstream server (NewRouter), not a hand-rolled mock.
package http

import (
	"bytes"
	"context"
	"log"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// captureLog redirects the standard library "log" package's global output to a
// buffer for the duration of fn, then restores it — used to prove a plaintext
// credential/value never reaches any log line anywhere along the call path
// (client, HTTP transport, real handler, real core), not just that it isn't
// deliberately logged in the one function we happen to be reading.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prevOutput := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(prevOutput)
		log.SetFlags(prevFlags)
	}()
	fn()
	return buf.String()
}

// TestRemoteStorage_PlaintextChannel_CreateUser_RealServerRoundTrip proves the
// #499 fix at the storage.Storage.CreateUser layer: RemoteStorage.CreateUser,
// given the new optional plaintextPassword argument, genuinely creates a
// user — with a real, working password — against a real upstream server.
// Before the fix this call always failed the upstream's "password is required"
// check (see TestRemoteStorage_FieldMismatchFix_CreateUser_WireShapeAndValidation);
// this proves it now succeeds, and that the password supplied is the ACTUAL
// password the account uses (verified by a real login against the upstream —
// not just that the client call didn't error).
//
// This drives RemoteStorage.CreateUser directly (mirroring the #496
// field-mismatch test's own scoping), not the full core.CreateUser business
// flow: core.CreateUser's shared buildUserForCreate helper ALSO pre-checks
// storage.GetUserByEmail before ever reaching CreateUser, and — independent of
// #499 and unlike GetUserByUsername (cleanly stubbed with ErrUnsupportedByBackend,
// see the buildUserForCreate skip-and-defer-to-upstream comment in
// internal/core/users.go) — RemoteStorage.GetUserByEmail targets
// "/api/v1/users/by-email/{email}", a route this server never registers at all,
// so every call to it 404s unconditionally against a real server. That is a
// separate, pre-existing, and notably WIDER bug (GetUserByEmail also backs
// several RBAC/SSO/SCIM lookups elsewhere in internal/core, not just this one
// pre-check) that needs its own dedicated fix — adding a new authenticated
// by-email HTTP surface deserves its own security review (permission gating,
// email-enumeration risk) rather than being folded into this round. Filed as a
// new finding rather than forced here; see the PR description.
func TestRemoteStorage_PlaintextChannel_CreateUser_RealServerRoundTrip(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"}}}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	defer upstreamSrv.Close()

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: upstreamSrv.URL, APIKey: upstreamToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	ctx := context.Background()
	const plaintextPassword = "Tr8#Qm2$Zx9!Fv6@"
	active := true

	var created *models.User
	logOutput := captureLog(t, func() {
		created, err = rs.CreateUser(ctx, &models.User{
			Username: "e2e-plaintext-newuser", Email: "e2e-plaintext-newuser@example.com",
			DisplayName: "E2E Plaintext User", IsActive: active,
		}, plaintextPassword)
	})
	require.NoError(t, err, "#499: RemoteStorage.CreateUser must genuinely succeed against a real server when given a plaintextPassword")
	require.NotNil(t, created)
	assert.NotZero(t, created.ID)

	// The plaintext password must never appear in any log line produced anywhere
	// along the call path (client, transport, real handler, real core).
	assert.NotContains(t, logOutput, plaintextPassword,
		"the plaintext password must never be logged anywhere along the CreateUser call path")

	// --- confirm it genuinely landed server-side with a REAL, usable password —
	// not just that the client call didn't error ---
	direct, err := upstreamCore.Storage().GetUser(ctx, created.ID)
	require.NoError(t, err, "the user must be a real row in the upstream's own users table")
	assert.Equal(t, "e2e-plaintext-newuser", direct.Username)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(direct.PasswordHash), []byte(plaintextPassword)),
		"#499: the upstream must have hashed the SAME plaintext password supplied, not an empty/garbage value")

	// The strongest possible proof: log in against the upstream with exactly the
	// password we supplied through RemoteStorage.CreateUser.
	session, loggedInUser, err := upstreamCore.Login(ctx, &core.LoginRequest{
		Username: "e2e-plaintext-newuser", Password: plaintextPassword,
	})
	require.NoError(t, err, "#499: the password conveyed through RemoteStorage.CreateUser must be genuinely usable to log in")
	assert.NotNil(t, session)
	assert.Equal(t, created.ID, loggedInUser.ID)
}

// TestRemoteStorage_PlaintextChannel_CreateSecret_RealServerRoundTrip proves the
// #499 fix for RemoteStorage.CreateSecret: a downstream core.KeyorixCore backed
// by RemoteStorage can genuinely create a secret — with its real value — against
// a real upstream server. Before the fix this call always failed the upstream's
// "value is required" check (see TestRemoteStorage_FieldMismatchFix_
// CreateSecret_WireShapeAndValidation); this proves it now succeeds and that the
// value read back from the upstream's own storage is the exact plaintext that
// was supplied — not just that the client call didn't error.
func TestRemoteStorage_PlaintextChannel_CreateSecret_RealServerRoundTrip(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"}}}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	defer upstreamSrv.Close()

	ctx := context.Background()

	// Seed a real project/environment directly against the upstream's own core
	// (bypassing the wire for setup, mirroring the #496/#794 e2e tests' own
	// pattern) — CreateSecret needs a real environment to validate against.
	project, err := upstreamCore.CreateProject(ctx, "e2e-plaintext-project", "seeded for #499's e2e test")
	require.NoError(t, err)
	envs, err := upstreamCore.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	envID := envs[0].ID

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: upstreamSrv.URL, APIKey: upstreamToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)
	downstream := core.NewKeyorixCore(rs)

	const plaintextValue = "s3cr3t-plaintext-payload-#499"

	var createdSecret *models.SecretNode
	logOutput := captureLog(t, func() {
		createdSecret, err = downstream.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: "e2e-plaintext-secret", Value: []byte(plaintextValue),
			ProjectID: project.ID, EnvironmentID: envID, Type: "generic", CreatedBy: "e2e-tester",
		})
	})
	require.NoError(t, err, "#499: CreateSecret via storage.type: remote must genuinely succeed against a real server")
	require.NotNil(t, createdSecret)
	assert.NotZero(t, createdSecret.ID)

	// The plaintext value must never appear in any log line produced anywhere
	// along the call path (client, transport, real handler, real core).
	assert.NotContains(t, logOutput, plaintextValue,
		"the plaintext secret value must never be logged anywhere along the CreateSecret call path")
	// Belt-and-braces: nothing resembling the value's distinguishing substring
	// should leak into logs either.
	assert.False(t, strings.Contains(logOutput, "s3cr3t-plaintext-payload"),
		"the plaintext secret value must never be logged, even partially")

	// --- confirm it genuinely landed server-side with the REAL value — not just
	// that the client call didn't error ---
	direct, err := upstreamCore.Storage().GetSecret(ctx, createdSecret.ID)
	require.NoError(t, err, "the secret must be a real row in the upstream's own secret_nodes table")
	assert.Equal(t, "e2e-plaintext-secret", direct.Name)

	value, err := upstreamCore.GetSecretValue(ctx, createdSecret.ID)
	require.NoError(t, err, "#499: version 1 must have been created atomically upstream — no separate CreateSecretVersion call should have been needed (or attempted)")
	assert.Equal(t, plaintextValue, string(value),
		"#499: the value read back from the upstream's own storage must be the exact plaintext supplied through RemoteStorage.CreateSecret")
}
