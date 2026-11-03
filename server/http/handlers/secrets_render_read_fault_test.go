package handlers

// secrets_render_read_fault_test.go — STORAGE-ERR-CLASS-4 item 6: the template
// renderer's by-name lookup of a referenced secret folded a storage fault into
// ErrSecretRefNotFound (404 for a global holder, 403 for others). A fault is storage-wide,
// not a verdict on the reference, so it is the shared 503; a true miss is unchanged.

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestRenderTemplate_ReferencedSecretReadFaultIs503(t *testing.T) {
	_, db, fx := newSecretsHandlerWithDB(t, "en")
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	fh, err := NewSecretHandler(core.NewKeyorixCore(faulty))
	require.NoError(t, err)
	render := func(tmpl string) int {
		w := secretsDo(fh.RenderTemplate, http.MethodPost, fmt.Sprintf(`{"template":%q}`, tmpl), fmt.Sprint(fx.projectID), secretsAdminID)
		return w.Code
	}
	ref := "${secret:ec-env/ec-secret}"

	faulty.Arm(&faultstorage.FaultSpec{Method: "GetSecretByName", NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
	w := secretsDo(fh.RenderTemplate, http.MethodPost, fmt.Sprintf(`{"template":%q}`, ref), fmt.Sprint(fx.projectID), secretsAdminID)
	require.True(t, faulty.Fired(), "the render must reach GetSecretByName")
	faulty.Arm(nil)
	requireStorageUnavailable503(t, w)

	assert.Equal(t, http.StatusNotFound, render("${secret:ec-env/no-such-secret}"), "a true miss keeps its 404 for a global holder")
	assert.NotEqual(t, http.StatusServiceUnavailable, render(ref), "once the fault clears the lookup is past the by-name read (the fixture secret has no value version)")
}
