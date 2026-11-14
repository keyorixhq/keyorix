package admin

// #2914: the SSO-only-administrator WARN tells the operator what to do (create
// a local break-glass administrator, generate a recovery key) and says so more
// loudly when no recovery key exists, the state in which only the IdP itself
// can give the install back its administrators. Still a WARN in both arms: it
// never changes the posture exit code.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// idpAdminPostureReport seeds one global administrator per spec, plus a
// recovery-key record when withRecoveryKey, and runs only the SSO-only check.
func idpAdminPostureReport(t *testing.T, withRecoveryKey bool, specs ...adminSpec) *postureReport {
	t.Helper()
	cfg := writeSecureBaselineConfig(t)
	report := &postureReport{}
	err := withUsableStorage(cfg, func(store corestorage.Storage) error {
		ctx := context.Background()
		roleName, err := identity.NewFoldedName("admin")
		if err != nil {
			return err
		}
		role, err := store.CreateRole(ctx, roleName, "install administrator")
		if err != nil {
			return err
		}
		if err := store.SetRoleBypassesPermissionChecks(ctx, role.ID, true); err != nil {
			return err
		}
		for _, s := range specs {
			u, err := store.CreateUser(ctx, &models.User{
				Username: s.name, UsernameFolded: s.name, Email: s.name + "@x.io", EmailFolded: s.name + "@x.io",
				IsActive: true, AccountState: core.AccountActive, ExternalID: s.externalID,
			})
			if err != nil {
				return err
			}
			if err := store.AssignRole(ctx, u.ID, role.ID, corestorage.Scope{}); err != nil {
				return err
			}
		}
		if withRecoveryKey {
			if err := store.SetRecoveryKeyRecord(ctx, &models.RecoveryKeyRecord{KeyHash: "test-verifier", KeyVersion: 1}); err != nil {
				return err
			}
		}
		return collectSSOOnlyAdminPosture(ctx, core.NewKeyorixCore(store), report)
	})
	require.NoError(t, err)
	return report
}

const (
	breakGlassRemedy  = "create a local break-glass administrator"
	noRecoveryKeyLine = "no recovery key has been generated"
	recoveryKeyRotate = "keyorix-server admin recovery-key rotate"
)

func TestSSOOnlyAdminPosture_RemedyAndRecoveryKeyArm(t *testing.T) {
	t.Run("SSO-only admin with a recovery key: WARN with the break-glass remedy", func(t *testing.T) {
		report := idpAdminPostureReport(t, true, adminSpec{"sso-root", "sso:okta:abc"})
		require.Len(t, report.warnings, 1)
		w := report.warnings[0]
		assert.Contains(t, w, breakGlassRemedy)
		assert.Contains(t, w, "keyorix user create")
		assert.Contains(t, w, "keyorix rbac assign-role")
		assert.Contains(t, w, "keyorix-server admin recover-admin")
		assert.NotContains(t, w, noRecoveryKeyLine)
		assert.Empty(t, report.deviations)
	})
	t.Run("SSO-only admin and no recovery key: escalated WARN", func(t *testing.T) {
		report := idpAdminPostureReport(t, false, adminSpec{"sso-root", "sso:okta:abc"})
		require.Len(t, report.warnings, 1)
		w := report.warnings[0]
		assert.Contains(t, w, breakGlassRemedy)
		assert.Contains(t, w, noRecoveryKeyLine)
		assert.Contains(t, w, recoveryKeyRotate)
		assert.Empty(t, report.deviations, "still a WARN: the exit code is unchanged")
	})
	t.Run("an SSO admin plus a local admin stays silent, with or without a recovery key", func(t *testing.T) {
		for _, withKey := range []bool{true, false} {
			report := idpAdminPostureReport(t, withKey, adminSpec{"local-root", ""}, adminSpec{"sso-root", "sso:okta:abc"})
			assert.Empty(t, report.warnings)
			assert.Empty(t, report.deviations)
		}
	})
}
