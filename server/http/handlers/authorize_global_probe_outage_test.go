package handlers

// authorize_global_probe_outage_test.go -- AUTHZ-OUTAGE-TAILS-1 item 3: the two
// handler call sites that probed a permission at global scope through
// middleware.AuthorizedAtGlobalScope, which folds a failed lookup into "not
// authorized".
//
//   - template render (a referenced secret that does not exist): the probe decides
//     404 versus 403, a refusal, so a storage outage of the probe is the shared 503
//     (+ Retry-After), not the 403 that reads as "you hold nothing".
//   - system info (canSystemWrite): the probe only toggles optional admin-only
//     fields, so an outage keeps omitting them (fail closed), still answers 200, and
//     logs a warning with the error.
//
// The outage is injected on the permission lookup itself (ResolveUserPermissionAt).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestRenderTemplate_GlobalProbeOutageIs503(t *testing.T) {
	_, db, fx := newSecretsHandlerWithDB(t, "en")
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	fh, err := NewSecretHandler(core.NewKeyorixCore(faulty))
	require.NoError(t, err)
	missing := fmt.Sprintf(`{"template":%q}`, "${secret:ec-env/no-such-secret}")
	render := func(actor uint) *httptest.ResponseRecorder {
		return secretsDo(fh.RenderTemplate, http.MethodPost, missing, fmt.Sprint(fx.projectID), actor)
	}

	// The probe is the only permission lookup a missing reference reaches here; the
	// fault must fire on it and be answered 503, never 403/404.
	faulty.Arm(&faultstorage.FaultSpec{Method: "ResolveUserPermissionAt", NthCall: 1, Kind: faultstorage.KindError,
		Err: fmt.Errorf("injected: dial tcp: %w", syscall.ECONNREFUSED)})
	w := render(secretsAdminID)
	require.True(t, faulty.Fired(), "the render must reach the global-scope probe")
	faulty.Arm(nil)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "2", w.Header().Get("Retry-After"))
	assert.Contains(t, w.Body.String(), "authorization temporarily unavailable, please retry")
	assert.NotContains(t, w.Body.String(), "injected", "the storage error text never reaches the client")

	// Nothing is cached and the verdicts are unchanged once the fault clears.
	assert.Equal(t, http.StatusNotFound, render(secretsAdminID).Code, "a global holder still gets the real 404")
	assert.Equal(t, http.StatusForbidden, render(secretsPlainID).Code, "a caller without the permission still gets the 403")
}

func TestSystemInfo_GlobalProbeOutageOmitsAdminFieldsAndWarns(t *testing.T) {
	_, db := freshCoreS12WithAdmin(t)
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	fcs := core.NewKeyorixCore(faulty)
	call := func() map[string]any {
		req := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil))
		rr := httptest.NewRecorder()
		MakeSystemInfoHandler(&config.Config{}, fcs)(rr, req)
		require.Equal(t, http.StatusOK, rr.Code, "a cosmetic flag is never a 503: %s", rr.Body.String())
		var resp map[string]any
		require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
		return resp["data"].(map[string]any)["security"].(map[string]any)
	}

	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	faulty.Arm(&faultstorage.FaultSpec{Method: "ResolveUserPermissionAt", NthCall: 1, Kind: faultstorage.KindError,
		Err: fmt.Errorf("injected: dial tcp: %w", syscall.ECONNREFUSED)})
	security := call()
	require.True(t, faulty.Fired(), "the handler must reach the system.write lookup")
	faulty.Arm(nil)
	assert.NotContains(t, security, "recovery_key", "an outage must not reveal admin-only fields")
	assert.Contains(t, logs.String(), "system.write lookup failed", "the outage is logged at warn")
	assert.Contains(t, logs.String(), "injected")

	assert.Contains(t, call(), "recovery_key", "once the fault clears the admin sees the field again")
}
