package core

// secret_render_check_fault_test.go -- CORE-FAULT-TAILS-1 item 1: stageRenderRef folded
// ANY error of the per-secret permission check into ErrSecretRefNotFound, so a storage
// fault in that check read as "no such secret" (404 to a global holder) and its denial
// row said forbidden. The fault now stays ErrSecretRefNotFound to every caller that does
// not ask (the #181 oracle stays closed: the text is byte-identical), carries the fault
// for the one caller entitled to it (SecretRefCheckFault), and is audited internal_error.

import (
	"context"
	"fmt"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// Fault-injected sibling of TestRenderSecretTemplate_UniformResponseForNotFoundVsForbidden.
func TestRenderSecretTemplate_PermissionCheckFaultIsNotAVerdict(t *testing.T) {
	ctx := context.Background()
	_, db, projectID, secretID := newRenderFixture(t)
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	c := &KeyorixCore{storage: faulty, now: time.Now}
	const ref = "${secret:production/db-password}"
	render := func(userID uint) error {
		_, err := c.RenderSecretTemplate(ctx, ref, projectID, userID, "viewer", "10.0.0.1", "ua")
		require.Error(t, err)
		return err
	}

	// Forbidden: user 2 holds no grant on the existing secret. A verdict, no fault.
	forbiddenErr := render(2)
	require.ErrorIs(t, forbiddenErr, ErrSecretRefNotFound)
	assert.Nil(t, SecretRefCheckFault(forbiddenErr), "a real denial is not a fault")

	faults := map[string]*faultstorage.FaultSpec{
		// a storage read inside the check (the share lookup) fails
		"share read": {Method: "ListSharesBySecret", NthCall: 1, Kind: faultstorage.KindError,
			Err: fmt.Errorf("injected: share read: %w", syscall.ECONNRESET)},
		// the RBAC fallback's lookup fails; the check folds it into "insufficient permissions"
		"rbac lookup": {Method: "ResolveUserPermissionAt", NthCall: 1, Kind: faultstorage.KindError,
			Err: fmt.Errorf("injected: role lookup: %w", syscall.ECONNREFUSED)},
	}
	faultErrs := map[string]error{}
	for name, spec := range faults {
		faulty.Arm(spec)
		err := render(2)
		require.True(t, faulty.Fired(), "%s: the check must reach %s", name, spec.Method)
		faulty.Arm(nil)

		require.ErrorIs(t, err, ErrSecretRefNotFound, "%s: still the uniform refusal for every mapper that does not ask", name)
		assert.False(t, IsStorageReadUnavailable(err), "%s: never the generic 503 sentinel (that would be an existence oracle)", name)
		assert.Equal(t, forbiddenErr.Error(), err.Error(), "%s: byte-identical to the forbidden answer", name)
		fault := SecretRefCheckFault(err)
		require.Error(t, fault, "%s: the fault is there for a caller entitled to it", name)
		assert.True(t, IsStorageReadUnavailable(fault), name)
		assert.Contains(t, StorageReadFaultDetail(fault), "injected", "%s: the cause is kept for the server log", name)
		faultErrs[name] = err
	}

	// Not found: the same reference once the secret is gone stays byte-identical too.
	require.NoError(t, c.DeleteSecret(ctx, secretID))
	notFoundErr := render(2)
	require.ErrorIs(t, notFoundErr, ErrSecretRefNotFound)
	assert.Nil(t, SecretRefCheckFault(notFoundErr))
	assert.Equal(t, notFoundErr.Error(), forbiddenErr.Error(), "#181: missing and forbidden stay byte-identical")
	for name, err := range faultErrs {
		assert.Equal(t, notFoundErr.Error(), err.Error(), "%s: byte-identical to the missing answer", name)
	}

	// The denial rows tell the outage from the verdicts: forbidden, then the faults as
	// internal_error (the second one, same principal/reason/target, is aggregated into
	// the first by the denial aggregator), then not_found.
	var rows []models.AuditEvent
	require.NoError(t, db.Where("event_type = ? AND success = ?", "secret.read", false).Order("id").Find(&rows).Error)
	var reasons []string
	for _, r := range rows {
		reasons = append(reasons, refusedReadDiff(t, r).Reason)
	}
	assert.Equal(t, []string{"forbidden", "internal_error", "not_found"}, reasons)
}
