// sso_escalation_guard_lookup_test.go — found by the #2910 fault sweep
// (server/faultops TestSSOReconcileFaultSweep). SSO reconcile asks an
// escalation guard before every ADD: may an IdP assertion confer this group
// (scimGroupConfersAdmin) or this mapped role (idpAutoGrantOfRoleIsEscalation)?
// Both predicates fail closed, so a lookup ERROR answers "yes, escalation".
// Reconcile then counted it as a deliberately blocked escalation. A blocked
// escalation is not an error, so the login went on to mint a session with the
// IdP's grant silently not applied. The audit event also said the group or
// role had been "refused" as admin-conferring when nothing of the kind had been
// decided.
//
// Condition 1 (#2839) is "any error in reconcile means no session". A guard
// whose lookup FAILED has not decided anything, so it is an error, not a block.
// Not granting is still the outcome (fail closed for the privilege), and the
// login is refused on top of that. A genuine escalation verdict stays a
// counted block that does not refuse the login.
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/ports"
)

// RED before the fix: no error, a session was minted, and the event said
// "1 admin-conferring group(s) refused".
func TestCompleteSAML_GroupEscalationGuardLookupFailureRefusesTheLogin(t *testing.T) {
	f := newSAMLReconcileFixture(t, &ports.SAMLAssertion{Subject: "corp|123", Groups: []string{"engineers"}, GroupsPresent: true}, nil)
	f.group(41, "engineers")
	f.fault.failGetGroupRoles = true

	session, err := f.login()

	f.assertRefusedWithoutSession(session, err, SSOMsgGroupReconcileRefused)
	assert.False(t, f.memberOf(41), "an unverified group is still not added (fail closed for the privilege)")
	refused := f.events(EventSSOReconcileRefused)
	require.Len(t, refused, 1)
	assert.Contains(t, refused[0].Description, `check whether group 41 "engineers" confers admin`)
	assert.NotContains(t, refused[0].Description, "admin-conferring group(s) refused",
		"a lookup failure is not a decided escalation and must not be reported as one")
}

// The role-mapping counterpart (GetRolePermissions is the roles.assign check).
func TestCompleteSSO_RoleEscalationGuardLookupFailureRefusesTheLogin(t *testing.T) {
	f := newOIDCReconcileFixture(t, []string{"g-a"}, map[string]string{"g-a": "role_a"})
	f.role(51, "role_a", false)
	f.fault.failGetRolePermissions = true

	session, err := f.login()

	f.assertRefusedWithoutSession(session, err, SSOMsgRoleReconcileRefused)
	assert.False(t, f.holds(51))
	refused := f.events(EventSSOReconcileRefused)
	require.Len(t, refused, 1)
	assert.Contains(t, refused[0].Description, `check whether role "role_a" is an admin-tier grant`)
}

// Calibration: a DECIDED escalation (the mapped role really is admin-tier) is
// still a counted block that does not refuse the login. Otherwise the fix above
// could be met by refusing every guarded add.
func TestCompleteSSO_DecidedRoleEscalationIsStillABlockNotARefusal(t *testing.T) {
	f := newOIDCReconcileFixture(t, []string{"g-a"}, map[string]string{"g-a": "admin"})
	f.role(60, "admin", true)

	session, err := f.login()

	require.NoError(t, err)
	require.NotNil(t, session)
	assert.False(t, f.holds(60), "an IdP mapping can never grant an admin-tier role")
	synced := f.events(EventSSORolesSynced)
	require.Len(t, synced, 1)
	assert.Contains(t, synced[0].Description, "1 admin-tier role grant(s) refused")
}
