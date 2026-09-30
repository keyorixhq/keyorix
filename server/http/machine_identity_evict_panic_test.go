// machine_identity_evict_panic_test.go — regression test for the fail-open cache
// eviction gap FuzzStorageFaultOperations found in TransitionMachineIdentity
// (internal/core/machine_identities.go): a PANIC (not a returned error) from
// ListMachineIdentityCredentials during the post-commit, best-effort credential-cache
// eviction step used to propagate past an ALREADY-COMMITTED suspend/revoke, get caught
// by the outer HTTP Recovery middleware, and misreport the transition as a 500 —
// oracle (a). Crashing input ff58003231 (server/faultops/testdata/fuzz/
// FuzzStorageFaultOperations/0134bc8cffdd0cfe) is the permanent fuzz-corpus regression
// for that outward symptom; THIS test proves the security property the fix actually
// has to hold, which the fuzz oracle alone does not check: after a panic (or a
// persistent error) during eviction, the machine identity's OLD credential must be
// refused on the very NEXT request, not after validTokenTTL. See
// evictMachineIdentityCacheOrFlush's own doc comment (internal/core/machine_identities.go)
// for the full fail-closed design (flush every machine-token cache entry when the exact
// hashes can't be determined).
package http

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/require"
)

// miepAuthedRequest issues an authenticated request against srv with token and reports
// the response status code.
func miepAuthedRequest(srv *httptest.Server, method, path, token string, body []byte) int {
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, srv.URL+path, reader)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// TestTransitionMachineIdentity_EvictionPanicStillRevokesAndFailsClosed is the
// deterministic regression test for the eviction-panic bug: it arms an
// internal/faultstorage panic on ListMachineIdentityCredentials's first call (mirroring
// the fuzz-found crasher exactly, not a synthetic stand-in), triggers a revoke through
// the real HTTP handler, and asserts BOTH halves of the fix:
//  1. The transition itself must still be reported as successful (200) — the panic
//     happens strictly after the state-transition transaction has already committed, so
//     the caller must not be told it failed.
//  2. The machine token, warm in the auth cache from a positive-control request BEFORE
//     the revoke, must be refused on the VERY NEXT request after the revoke — not after
//     validTokenTTL. This is the property evictMachineIdentityCacheOrFlush's fail-closed
//     design exists for: it can't determine which hash to evict individually (the lookup
//     that would tell it panicked), so it must flush every machine-token cache entry
//     rather than silently leaving this one live.
func TestTransitionMachineIdentity_EvictionPanicStillRevokesAndFailsClosed(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "local",
			Database: config.DatabaseConfig{
				Path: uniqueMemDSN("&_timeout=30000&_journal_mode=WAL"),
			},
		},
	}
	real, err := appstorage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	faulty := faultstorage.NewFaultyStorage(real, nil) // unarmed: setup runs fault-free

	c := core.NewKeyorixCore(faulty)
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	c.SetMachineTokenCacheFlusher(customMiddleware.InvalidateAllMachineTokenCache)
	ctx := context.Background()

	c.SetBootstrapToken("miep-bootstrap-token")
	_, err = c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "miepadmin", Email: "miepadmin@example.com",
		Password: "TestPassword123!", Token: "miep-bootstrap-token",
	})
	require.NoError(t, err)
	admin, err := c.GetUserByEmail(ctx, "miepadmin@example.com")
	require.NoError(t, err)
	adminSess, _, err := c.Login(ctx, &core.LoginRequest{Username: "miepadmin", Password: "TestPassword123!"})
	require.NoError(t, err)

	projects, err := c.ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	proj := projects[0]
	envs, err := c.ListEnvironments(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	env := envs[0]

	secret, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "miep-probe-secret", Value: []byte("v1"),
		ProjectID: proj.ID, EnvironmentID: env.ID, Type: "generic",
		CreatedBy: admin.Username, OwnerID: admin.ID,
	})
	require.NoError(t, err)

	mi, err := c.CreateMachineIdentity(ctx, proj.ID, "miep-runner", "ci", "", "", admin.ID, 0)
	require.NoError(t, err)
	tok, err := c.IssueMachineToken(ctx, proj.ID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "miep-token"})
	require.NoError(t, err)
	token := tok.PlainToken

	roles, err := c.Storage().ListRoles(ctx)
	require.NoError(t, err)
	var roleID uint
	for _, r := range roles {
		if r.Name == "project_developer" {
			roleID = r.ID
			break
		}
	}
	require.NotZero(t, roleID, "builtin role project_developer must exist")
	require.NoError(t, c.AssignMachineRole(ctx, mi.ID, roleID, core.Scope{ProjectID: proj.ID}, admin.ID, false))

	router, err := NewRouter(&config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	probePath := "/api/v1/secrets/" + strconv.FormatUint(uint64(secret.ID), 10) + "/versions"

	// Positive control: prime the auth cache with a genuine positive entry for token,
	// via a real authenticated, permission-checked request (an unverified token would
	// make the later "still authenticated" observation vacuous).
	if got := miepAuthedRequest(srv, http.MethodGet, probePath, token, nil); got != http.StatusOK {
		t.Fatalf("positive control: fresh machine token did not authenticate (got %d)", got)
	}

	// Arm the exact fault the fuzz crasher found: the FIRST call to
	// ListMachineIdentityCredentials panics. This fires inside
	// evictMachineIdentityCacheOrFlush's post-commit MachineTokenHashes call, strictly
	// after TransitionMachineIdentity's own WithTransaction has already committed the
	// state change.
	faulty.Arm(&faultstorage.FaultSpec{
		Method:  "ListMachineIdentityCredentials",
		NthCall: 1,
		Kind:    faultstorage.KindPanic,
		Err:     errors.New("fault-fuzz injected failure"),
	})

	revokePath := "/api/v1/projects/" + strconv.FormatUint(uint64(proj.ID), 10) + "/machine-identities/" + strconv.FormatUint(uint64(mi.ID), 10)
	status := miepAuthedRequest(srv, http.MethodPut, revokePath, adminSess.SessionToken, []byte(`{"action":"revoke"}`))

	// Half 1: the already-committed transition must NOT be reported as a failure. The
	// panic happens strictly after commit; the caller must see success.
	if status != http.StatusOK {
		t.Errorf("expected 200 (transition already committed before the eviction panic), got %d", status)
	}

	// Half 2 (THE ASSERTION): the machine token, warm in cache from the positive control
	// above, must be refused on the VERY NEXT request. RED on the unfixed code (no
	// recover(), no fail-closed flush): the panic would have crashed this test outright
	// via the *first* half's HTTP round-trip (no Recovery-caught 500 to even observe) —
	// or, if only the recover() half of the fix were present without the fail-closed
	// flush, this next line would still authenticate, since nothing ever told the cache
	// this credential's hash to evict.
	if got := miepAuthedRequest(srv, http.MethodGet, probePath, token, nil); got == http.StatusOK {
		t.Error("revoked machine token still authenticated on the request immediately after revoke — eviction-panic fail-closed flush did not fire")
	}
}
