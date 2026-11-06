package handlers

// secrets_render_outage_oracle_test.go -- CORE-FAULT-TAILS-1 item 2: the render's
// per-reference permission-check fault (item 1) only happens for a secret that EXISTS,
// so it must not become an existence oracle for a caller who may not tell "missing"
// from "forbidden". During a permission-lookup outage such a caller gets the same 503
// (status, Retry-After, body) for a missing and for an unreadable reference.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// sustainedOutage returns real behind depth fault layers that each fail the first call
// of method reaching them: the first depth calls of method fail, as in an outage
// (a FaultyStorage fires once). fired reports how many of those calls happened.
func sustainedOutage(real corestorage.Storage, method string, depth int) (s corestorage.Storage, fired func() int) {
	s = real
	var layers []*faultstorage.FaultyStorage
	for i := range depth {
		l := faultstorage.NewFaultyStorage(s, &faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError,
			Err: fmt.Errorf("injected outage %d: dial tcp: %w", i, syscall.ECONNREFUSED)})
		layers = append(layers, l)
		s = l
	}
	return s, func() int {
		n := 0
		for _, l := range layers {
			if l.Fired() {
				n++
			}
		}
		return n
	}
}

// Item 2: during a permission-lookup outage a caller without global secrets.read gets
// the identical 503 for a missing and for an existing-but-unreadable reference.
func TestRenderTemplate_PermissionLookupOutageIsNoExistenceOracle(t *testing.T) {
	const depth = 4
	render := func(t *testing.T, ref string) (*httptest.ResponseRecorder, int) {
		_, db, fx := newSecretsHandlerWithDB(t, "en")
		st, fired := sustainedOutage(store.NewLocalStorage(db), "ResolveUserPermissionAt", depth)
		fh, err := NewSecretHandler(core.NewKeyorixCore(st))
		require.NoError(t, err)
		w := renderRef(fh, fx, ref, secretsPlainID)
		return w, fired()
	}
	missing, missingFaults := render(t, "${secret:ec-env/no-such-secret}")
	unreadable, unreadableFaults := render(t, "${secret:ec-env/ec-secret}") // exists, owned by the admin
	// A missing reference meets the outage only in the handler's global-scope probe; an
	// unreadable one first in the per-secret check's RBAC lookup, then in the probe.
	assert.Equal(t, 1, missingFaults)
	assert.Equal(t, 2, unreadableFaults)
	require.Less(t, unreadableFaults, depth, "the outage must outlast every lookup the request makes")

	assert.Equal(t, http.StatusServiceUnavailable, missing.Code, "body: %s", missing.Body.String())
	assert.Equal(t, http.StatusServiceUnavailable, unreadable.Code, "body: %s", unreadable.Body.String())
	assert.Equal(t, missing.Header().Get("Retry-After"), unreadable.Header().Get("Retry-After"))
	assert.Equal(t, missing.Body.String(), unreadable.Body.String(), "the outage answer must not tell the two apart")
	assert.NotContains(t, unreadable.Body.String(), "injected")

	// Out of the outage the same caller still gets the identical 403 for both.
	_, db, fx := newSecretsHandlerWithDB(t, "en")
	h, err := NewSecretHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)
	m, u := renderRef(h, fx, "${secret:ec-env/no-such-secret}", secretsPlainID), renderRef(h, fx, "${secret:ec-env/ec-secret}", secretsPlainID)
	assert.Equal(t, http.StatusForbidden, m.Code)
	assert.Equal(t, m.Code, u.Code)
	assert.Equal(t, m.Body.String(), u.Body.String())
}
