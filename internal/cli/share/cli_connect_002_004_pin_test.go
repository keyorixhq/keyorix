// cli_connect_002_004_pin_test.go — permanent regression coverage for two
// distinct HIGH findings in this package, both previously verified only with
// scratch tests that were deleted afterward:
//
//   - cli-connect-002: create.go's runCreate had no common.NewRemoteClient()
//     guard (unlike every sibling command), so a `keyorix connect`-configured
//     operator running `share create` from a directory that ALSO has a local
//     keyorix.yaml would silently create the ShareRecord in the local embedded
//     DB while claiming success, never touching the actual remote server.
//     Fixed in 76dbc529 (PR #1395): runCreate now checks
//     common.NewRemoteClient() before any embedded-mode code runs.
//
//   - cli-connect-004: create.go, update.go, and revoke.go passed a literal 1
//     as SharedBy/UpdatedBy/revokedBy instead of the real acting actor,
//     defeating internal/core/sharing.go's ownership gate
//     (requireLiveOwnerAuthority/secretOwnedBy) — any actor could mutate or
//     revoke shares owned by whoever happens to hold user ID 1. Fixed in
//     93c4a13e (PR #1433): these call sites now use common.ResolveActorID()
//     (see the "#G67" comments in create.go/update.go/revoke.go).
package share

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliConnect002_ShareCreate_RoutesToRemoteWhenConfigured pins cli-connect-002:
// when KEYORIX_SERVER/KEYORIX_TOKEN (or ~/.keyorix/cli.yaml — here we use the env
// vars, which common.ResolveRemote consults first) resolve a remote server,
// `share create` must route the request there, NOT silently fall through to the
// local embedded DB.
//
// The local keyorix.yaml in this test's working directory points at an EMPTY,
// unseeded embedded SQLite DB. If the remote guard were ever bypassed (the
// pre-#1395 shape), the embedded fallthrough would try to look up a secret that
// does not exist in that DB and fail loudly with a "not found"-shaped error —
// it could never quietly "succeed" for the wrong reason. Combined with the
// direct assertion that the fake remote server received the POST, this proves
// the routing decision itself, not just the absence of a crash.
func TestCliConnect002_ShareCreate_RoutesToRemoteWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir) // points local storage at "<dir>/share_test.db" — never seeded in this test
	t.Chdir(dir)

	var (
		gotRequest bool
		gotMethod  string
		gotPath    string
		gotBody    struct {
			RecipientID uint   `json:"recipient_id"`
			IsGroup     bool   `json:"is_group"`
			Permission  string `json:"permission"`
		}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequest = true
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"ID":99,"SecretID":42,"OwnerID":1,"RecipientID":7,"IsGroup":false,"Permission":"read","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":null}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origSecretID, origRecipientID, origPerm, origIsGroup, origExpires, origTTL :=
		createSecretID, createRecipientID, createPermission, createIsGroup, createExpires, createTTL
	defer func() {
		createSecretID = origSecretID
		createRecipientID = origRecipientID
		createPermission = origPerm
		createIsGroup = origIsGroup
		createExpires = origExpires
		createTTL = origTTL
	}()
	createSecretID = 42
	createRecipientID = 7
	createPermission = "read"
	createIsGroup = false
	createExpires = ""
	createTTL = ""

	err := runCreate(nil, nil)
	require.NoError(t, err, "runCreate must succeed via the remote path when a remote server is configured")

	require.True(t, gotRequest, "the fake remote server never received a request — the embedded (local DB) path ran instead of the remote one")
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/api/v1/secrets/42/share", gotPath)
	assert.Equal(t, uint(7), gotBody.RecipientID)
	assert.Equal(t, "read", gotBody.Permission)

	// Belt and suspenders: the local embedded DB (which was never seeded) must
	// contain zero ShareRecord rows — confirming the create genuinely did not
	// fall through to it.
	st, err := storage.NewStorageFactory().CreateStorage(mustLoadLocalConfig(t))
	require.NoError(t, err)
	shares, err := st.ListSharesBySecret(context.Background(), 42)
	require.NoError(t, err)
	assert.Empty(t, shares, "the local embedded DB must not have received the share — it should have been created on the remote server only")
}

// newTestUser builds a models.User with UsernameFolded/EmailFolded populated
// exactly the way every real CreateUser caller (users.go, scim.go, sso.go)
// does — the raw model has no BeforeSave hook that derives these from
// Username/Email, so a caller going straight to storage.CreateUser (as this
// test does, bypassing the core-layer wrapper) must set them explicitly or
// every such user collides on the partial unique index on an empty folded
// value.
func newTestUser(t *testing.T, username, email string) *models.User {
	t.Helper()
	foldedUsername, err := identity.NewFoldedName(username)
	require.NoError(t, err)
	foldedEmail, err := identity.NewFoldedName(email)
	require.NoError(t, err)
	return &models.User{
		Username:       username,
		UsernameFolded: foldedUsername.Folded(),
		Email:          email,
		EmailFolded:    foldedEmail.Folded(),
		IsActive:       true,
	}
}

// mustLoadLocalConfig re-loads the keyorix.yaml written by writeShareTestConfig
// in the current directory, for direct inspection of the (should-be-untouched)
// local embedded DB.
func mustLoadLocalConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.NoError(t, i18n.Initialize(cfg))
	return cfg
}

// TestCliConnect004_ShareCreateAndRevoke_UseRealActorNotHardcodedOne pins
// cli-connect-004. It reproduces the finding's exact scenario: a bootstrap
// owner is (as bootstrap always does for the first user in a fresh DB) user ID
// 1, and a second, distinct "attacker" user tries to create and revoke shares
// they do not own by asserting their OWN real actor ID via KEYORIX_CLI_ACTOR.
//
// Pre-fix, create.go/revoke.go passed a literal 1 as SharedBy/revokedBy
// regardless of KEYORIX_CLI_ACTOR — since the real owner happens to be ID 1,
// that hardcoded value always satisfied internal/core/sharing.go's ownership
// gate (requireLiveOwnerAuthority), no matter which actor actually invoked the
// command. Post-fix, the real asserted actor ID is threaded through, so the
// attacker (a different, real ID) is correctly denied, and the real owner
// (asserting their own ID) still succeeds.
func TestCliConnect004_ShareCreateAndRevoke_UseRealActorNotHardcodedOne(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	svc := openShareCore(t)
	ctx := context.Background()

	svc.SetBootstrapToken("cli-connect-004-token")
	_, err := svc.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "owner", Email: "owner@example.com",
		Password: "BootstrapPass123!", DisplayName: "Owner",
		Token: "cli-connect-004-token",
	})
	require.NoError(t, err)
	owner, err := svc.GetUserByEmail(ctx, "owner@example.com")
	require.NoError(t, err)
	// This is the exact scenario the finding describes: a hardcoded literal 1
	// silently coincides with whichever user actually holds ID 1. If bootstrap
	// ever stops allocating ID 1 to the first user, this assertion fails loudly
	// here rather than the test silently exercising a different, non-reproducing
	// scenario further down.
	require.Equal(t, uint(1), owner.ID, "test assumes the bootstrap owner is user ID 1, matching the original finding's scenario")

	proj, err := svc.CreateProject(ctx, "cli-connect-004-proj", "")
	require.NoError(t, err)
	require.NoError(t, svc.AddProjectMember(ctx, owner.ID, proj.ID, owner.ID, "project_admin", false))

	envs, err := svc.Storage().ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	secret, err := svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "cli-connect-004-secret", Value: []byte("s3cret"), Type: "password",
		ProjectID: proj.ID, EnvironmentID: envs[0].ID,
		CreatedBy: "owner", OwnerID: owner.ID,
	})
	require.NoError(t, err)

	attacker, err := svc.Storage().CreateUser(ctx, newTestUser(t, "attacker", "attacker@example.com"))
	require.NoError(t, err)
	require.NotEqual(t, owner.ID, attacker.ID, "attacker must be a distinct real actor, not coincidentally ID 1")
	// The attacker is a live member of the project too (a real Keyorix user with
	// some legitimate access) — the point being tested is the OWNERSHIP gate,
	// not project membership, so membership alone must not be enough.
	require.NoError(t, svc.AddProjectMember(ctx, owner.ID, proj.ID, attacker.ID, "project_viewer", false))

	recipient, err := svc.Storage().CreateUser(ctx, newTestUser(t, "recipient", "recipient@example.com"))
	require.NoError(t, err)
	require.NoError(t, svc.AddProjectMember(ctx, owner.ID, proj.ID, recipient.ID, "project_viewer", false))

	origSecretID, origRecipientID, origPerm, origIsGroup, origExpires, origTTL :=
		createSecretID, createRecipientID, createPermission, createIsGroup, createExpires, createTTL
	origRevokeShareID := revokeShareID
	defer func() {
		createSecretID = origSecretID
		createRecipientID = origRecipientID
		createPermission = origPerm
		createIsGroup = origIsGroup
		createExpires = origExpires
		createTTL = origTTL
		revokeShareID = origRevokeShareID
	}()
	createSecretID = secret.ID
	createRecipientID = recipient.ID
	createPermission = "read"
	createIsGroup = false
	createExpires = ""
	createTTL = ""

	// --- Part 1: attacker attempts to create a share for a secret they do not own ---
	t.Setenv("KEYORIX_CLI_ACTOR", fmt.Sprintf("%d", attacker.ID))
	err = runCreate(nil, nil)
	require.Error(t, err, "an attacker who does not own the secret must be denied when creating a share, not silently succeed via a hardcoded actor")

	sharesAfterAttackerCreate, lerr := svc.Storage().ListSharesBySecret(ctx, secret.ID)
	require.NoError(t, lerr)
	assert.Empty(t, sharesAfterAttackerCreate, "the attacker's denied create must not have persisted a ShareRecord")

	// --- Part 2: the real owner creates the share (must succeed) ---
	t.Setenv("KEYORIX_CLI_ACTOR", fmt.Sprintf("%d", owner.ID))
	require.NoError(t, runCreate(nil, nil), "the real owner asserting their own actor ID must be able to create the share")

	sharesAfterOwnerCreate, lerr := svc.Storage().ListSharesBySecret(ctx, secret.ID)
	require.NoError(t, lerr)
	require.Len(t, sharesAfterOwnerCreate, 1, "the owner's create must have persisted exactly one ShareRecord")
	shareID := sharesAfterOwnerCreate[0].ID

	// --- Part 3: attacker attempts to revoke a share they do not own ---
	revokeShareID = shareID
	t.Setenv("KEYORIX_CLI_ACTOR", fmt.Sprintf("%d", attacker.ID))
	err = runRevoke(nil, nil)
	require.Error(t, err, "an attacker who does not own the secret must be denied when revoking its share, not silently succeed via a hardcoded actor")

	sharesAfterAttackerRevoke, lerr := svc.Storage().ListSharesBySecret(ctx, secret.ID)
	require.NoError(t, lerr)
	require.Len(t, sharesAfterAttackerRevoke, 1, "the attacker's denied revoke must not have deleted the share — zero rows changed")

	// --- Part 4: the real owner revokes the share (must succeed) ---
	t.Setenv("KEYORIX_CLI_ACTOR", fmt.Sprintf("%d", owner.ID))
	require.NoError(t, runRevoke(nil, nil), "the real owner asserting their own actor ID must be able to revoke the share")

	sharesAfterOwnerRevoke, lerr := svc.Storage().ListSharesBySecret(ctx, secret.ID)
	require.NoError(t, lerr)
	assert.Empty(t, sharesAfterOwnerRevoke, "the owner's revoke must have deleted the share")
}
