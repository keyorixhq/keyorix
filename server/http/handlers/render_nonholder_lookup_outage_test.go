package handlers

// render_nonholder_lookup_outage_test.go -- SEC-PG-TAILS-1 item 4 (AUTHZ-OUTAGE-TAILS-1 /
// #3948 leftover): the template-render route answers a caller who does NOT hold
// secrets.read at global scope with 503 + Retry-After (never 404, never 403) when the
// permission lookup behind the ADR-096 global-scope probe is failing, for BOTH
// references the route folds into core.ErrSecretRefNotFound:
//
//   - a secret that does not exist, and
//   - a secret that exists but the caller cannot read.
//
// ADR-096 makes those two indistinguishable to a non-holder (403 for both). During an
// outage the probe cannot tell whether the caller is a holder, so answering 403 would
// pass for "you hold nothing" and 404 would hand the existence oracle to anyone who can
// trigger an outage. A holder still gets the normal answer once the lookup works.
//
// The injected outage is faultstorage's one-shot fault on ResolveUserPermissionAt, armed
// on the LAST permission lookup the healthy request makes: that is the global-scope probe
// (the per-secret check of an existing secret runs before it). Arming it by the count a
// healthy request makes, not a hard-coded 1 or 2, keeps the test on the probe if core adds
// or removes a lookup in front of it.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const (
	renderOutageMissing    = "${secret:ec-env/no-such-secret}"
	renderOutageUnreadable = "${secret:ec-env/ec-secret}" // exists; secretsPlainID cannot read it
)

type renderOutageFixture struct {
	h      *SecretHandler
	faulty *faultstorage.FaultyStorage
	fx     secretsFixture
}

// newRenderOutageFixture is the secrets fixture (global admin secretsAdminID, a plain
// user secretsPlainID who holds nothing) with a readable value on ec-secret.
func newRenderOutageFixture(t *testing.T) *renderOutageFixture {
	t.Helper()
	_, db := freshCoreS12WithAdmin(t)
	fx := seedSecretsFixture(t, db)
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", fx.secretID).Update("is_secret", true).Error)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: fx.secretID, VersionNumber: 1, EncryptedValue: []byte("s3cr3t")}).Error)

	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	h, err := NewSecretHandler(core.NewKeyorixCore(faulty))
	require.NoError(t, err)
	return &renderOutageFixture{h: h, faulty: faulty, fx: fx}
}

func (f *renderOutageFixture) render(actor uint, template string) *httptest.ResponseRecorder {
	return secretsDo(f.h.RenderTemplate, http.MethodPost, fmt.Sprintf(`{"template":%q}`, template), strconv.FormatUint(uint64(f.fx.projectID), 10), actor)
}

// healthyRender renders once and returns how many permission lookups it made.
func (f *renderOutageFixture) healthyRender(actor uint, template string) (*httptest.ResponseRecorder, int) {
	before := len(f.faulty.Calls())
	w := f.render(actor, template)
	n := 0
	for _, c := range f.faulty.Calls()[before:] {
		if c.Method == "ResolveUserPermissionAt" {
			n++
		}
	}
	return w, n
}

// failLookup fails the nth permission lookup from now on (once).
func (f *renderOutageFixture) failLookup(nth int) {
	f.faulty.Arm(&faultstorage.FaultSpec{Method: "ResolveUserPermissionAt", NthCall: nth, Kind: faultstorage.KindError,
		Err: fmt.Errorf("injected: dial tcp: %w", syscall.ECONNREFUSED)})
}

func TestRenderTemplate_NonHolderGets503WhenPermissionLookupFails(t *testing.T) {
	for _, tc := range []struct{ name, template string }{
		{"missing secret", renderOutageMissing},
		{"existing but unreadable secret", renderOutageUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRenderOutageFixture(t)

			// Healthy: the non-holder gets the uniform ADR-096 403 for both references.
			w, lookups := f.healthyRender(secretsPlainID, tc.template)
			require.Equal(t, http.StatusForbidden, w.Code, "healthy baseline, body: %s", w.Body.String())
			require.Positive(t, lookups, "the render must make permission lookups, or there is nothing to fail")

			// Outage on the last lookup of that same request: the global-scope probe.
			f.failLookup(lookups)
			w = f.render(secretsPlainID, tc.template)
			require.True(t, f.faulty.Fired(), "the render must reach lookup #%d (the global-scope probe)", lookups)
			f.faulty.Arm(nil)

			assert.Equal(t, http.StatusServiceUnavailable, w.Code, "not 403 (reads as 'you hold nothing'), not 404 (existence oracle); body: %s", w.Body.String())
			assert.Equal(t, "2", w.Header().Get("Retry-After"))
			assert.Contains(t, w.Body.String(), "authorization temporarily unavailable, please retry")
			assert.NotContains(t, w.Body.String(), "injected", "the storage error text never reaches the client")

			// Nothing is cached: the verdict is the same uniform 403 once the lookup works.
			assert.Equal(t, http.StatusForbidden, f.render(secretsPlainID, tc.template).Code)
		})
	}
}

// A global holder is not degraded: with the lookup working it gets the real answer for
// each reference (404 for a missing secret, the rendered value for a readable one). The
// probe cannot tell a holder from a non-holder during an outage, so the holder is 503
// too, and recovers to the same answer afterwards.
func TestRenderTemplate_HolderGetsNormalAnswerWhenPermissionLookupWorks(t *testing.T) {
	f := newRenderOutageFixture(t)

	w, lookups := f.healthyRender(secretsAdminID, renderOutageMissing)
	require.Positive(t, lookups)
	assert.Equal(t, http.StatusNotFound, w.Code, "a global holder learns the real 404; body: %s", w.Body.String())

	w = f.render(secretsAdminID, renderOutageUnreadable)
	assert.Equal(t, http.StatusOK, w.Code, "a global holder reads the secret; body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "s3cr3t")

	f.failLookup(lookups)
	w = f.render(secretsAdminID, renderOutageMissing)
	require.True(t, f.faulty.Fired())
	f.faulty.Arm(nil)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, http.StatusNotFound, f.render(secretsAdminID, renderOutageMissing).Code)
}
