package faultops

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestSSOFaultOps_ReconcileBranchIsReached guards the PREMISE #2910 rests on:
// that the two SSO ops actually drive group/role reconcile, including a
// revocation, in a fault-free run. A green fuzz run over these ops says nothing
// about reconcile under faults unless reconcile ran. Before #2910 it could not:
// the SAML world had no GroupSync and a nil GroupRoleMap, so both reconcile
// branches were skipped and TestOpCatalog_SucceedsWithNoFaultArmed stayed green
// all the same. This test fails the moment either op stops reaching the
// reconcile writes, for example if a provider's GroupSync/GroupRoleMap is
// dropped or the asserted groups stop matching the seeded native ones.
func TestSSOFaultOps_ReconcileBranchIsReached(t *testing.T) {
	opByKey := func(key string) operation {
		for _, op := range opCatalog {
			if op.Key == key {
				return op
			}
		}
		t.Fatalf("op %q not in opCatalog", key)
		return operation{}
	}
	userByExternalPrefix := func(t *testing.T, w *faultWorld, prefix string) models.User {
		t.Helper()
		var u models.User
		if err := w.db.Where("external_id LIKE ?", prefix+"%").First(&u).Error; err != nil {
			t.Fatalf("no SSO user with external_id %s*: %v", prefix, err)
		}
		return u
	}
	inGroup := func(t *testing.T, w *faultWorld, userID uint, group string) bool {
		t.Helper()
		var n int64
		if err := w.db.Table("user_groups").Joins("JOIN groups ON groups.id = user_groups.group_id").
			Where("user_groups.user_id = ? AND groups.name = ?", userID, group).Count(&n).Error; err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	holdsRole := func(t *testing.T, w *faultWorld, userID uint, role string) bool {
		t.Helper()
		var n int64
		if err := w.db.Table("user_roles").Joins("JOIN roles ON roles.id = user_roles.role_id").
			Where("user_roles.user_id = ? AND roles.name = ?", userID, role).Count(&n).Error; err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	run := func(t *testing.T, key string) *faultWorld {
		t.Helper()
		w := newFaultWorld(t, nil)
		res, err := runOp(context.Background(), w, opByKey(key))
		if err != nil || !res.Success {
			t.Fatalf("fault-free run failed: err=%v detail=%s", err, res.Detail)
		}
		drainAllBackgroundGoroutines()
		return w
	}

	t.Run("SAML ACS: JIT account, group add, role grant, baseline role revoked", func(t *testing.T) {
		w := run(t, "REST POST /auth/saml/{provider}/acs")
		u := userByExternalPrefix(t, w, "sso:"+fuzzSAMLProviderName+":")
		if !inGroup(t, w, u.ID, fuzzSAMLGroupEngineers) {
			t.Errorf("group add did not run: not a member of %s", fuzzSAMLGroupEngineers)
		}
		if !holdsRole(t, w, u.ID, fuzzSAMLRoleEngineer) {
			t.Errorf("mapped role grant did not run: does not hold %s", fuzzSAMLRoleEngineer)
		}
		if holdsRole(t, w, u.ID, "system_viewer") {
			t.Errorf("revocation did not run: still holds the JIT baseline system_viewer that %s maps", fuzzSAMLGroupViewers)
		}
	})

	t.Run("OIDC callback: existing account, group add+remove, role grant+revoke", func(t *testing.T) {
		w := run(t, "REST GET /auth/sso/{provider}/callback")
		u := userByExternalPrefix(t, w, "sso:"+fuzzOIDCProviderName+":")
		if !inGroup(t, w, u.ID, fuzzOIDCGroupEngineers) {
			t.Errorf("group add did not run")
		}
		if inGroup(t, w, u.ID, fuzzOIDCGroupContractors) {
			t.Errorf("group REMOVAL did not run: still a member of %s", fuzzOIDCGroupContractors)
		}
		if !holdsRole(t, w, u.ID, fuzzOIDCRoleEngineer) {
			t.Errorf("mapped role grant did not run")
		}
		if holdsRole(t, w, u.ID, fuzzOIDCRoleContractor) {
			t.Errorf("role REVOCATION did not run: still holds %s", fuzzOIDCRoleContractor)
		}
	})
}
