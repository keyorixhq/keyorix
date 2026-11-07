package handlers

// secrets_render_check_fault_test.go -- CORE-FAULT-TAILS-1 item 1: the template
// renderer folded a storage fault in the per-reference permission check into
// ErrSecretRefNotFound, so a global secrets.read holder got 404 "no such secret" for a
// secret that exists. The holder now gets the shared 503. (Everyone else keeps the
// uniform refusal: secrets_render_outage_oracle_test.go.)

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func renderRef(h *SecretHandler, fx secretsFixture, ref string, actor uint) *httptest.ResponseRecorder {
	return secretsDo(h.RenderTemplate, http.MethodPost, fmt.Sprintf(`{"template":%q}`, ref), fmt.Sprint(fx.projectID), actor)
}

// Item 1: a holder whose read of the referenced secret goes through the check (not
// ownership) gets 503 when the check cannot be evaluated, not 404.
func TestRenderTemplate_PermissionCheckFaultIs503ForGlobalHolder(t *testing.T) {
	_, db, fx := newSecretsHandlerWithDB(t, "en")
	// Owned by the plain user, so the admin's read is decided by shares/ACL/RBAC.
	notMine := &models.SecretNode{Name: "not-mine", ProjectID: fx.projectID, EnvironmentID: fx.envID,
		OwnerID: secretsPlainID, Type: "static"}
	require.NoError(t, db.Create(notMine).Error)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: notMine.ID, VersionNumber: 1, EncryptedValue: []byte("v1")}).Error)
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	fh, err := NewSecretHandler(core.NewKeyorixCore(faulty))
	require.NoError(t, err)
	const ref = "${secret:ec-env/not-mine}"

	for _, spec := range []*faultstorage.FaultSpec{
		{Method: "ListSharesBySecret", NthCall: 1, Kind: faultstorage.KindError,
			Err: fmt.Errorf("injected: share read: %w", syscall.ECONNRESET)},
		{Method: "ResolveUserPermissionAt", NthCall: 1, Kind: faultstorage.KindError,
			Err: fmt.Errorf("injected: role lookup: %w", syscall.ECONNREFUSED)},
	} {
		t.Run(spec.Method, func(t *testing.T) {
			faulty.Arm(spec)
			w := renderRef(fh, fx, ref, secretsAdminID)
			require.True(t, faulty.Fired(), "the check must reach %s", spec.Method)
			faulty.Arm(nil)
			requireStorageUnavailable503(t, w)
			assert.NotContains(t, w.Body.String(), "injected")
		})
	}

	assert.Equal(t, http.StatusNotFound, renderRef(fh, fx, "${secret:ec-env/no-such-secret}", secretsAdminID).Code,
		"a true miss keeps its 404 for a global holder")
	w := renderRef(fh, fx, ref, secretsAdminID)
	assert.Equal(t, http.StatusOK, w.Code, "once the fault clears the holder reads the secret: %s", w.Body.String())
}
