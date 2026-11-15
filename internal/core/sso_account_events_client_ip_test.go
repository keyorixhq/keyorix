// sso_account_events_client_ip_test.go — SSO-AUDIT-TAILS-NOV-1 item 1: the
// account-change events an SSO login writes (auth.sso_jit_provisioned, the
// group/role reconcile events) name the client address the login came from, as
// #4263 made auth.sso_login and auth.sso_login_session_failed do
// (INV-CORE-sso-login-audit-names-session-client).
//
// RED on main: these events were written with an empty IP, so an incident
// responder pivoting from the login row to "what did this login change" lost the
// address on every row but the login's own.
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// One SAML login that JIT-provisions, adds a group and grants a mapped role:
// every event it writes carries the login's client address.
func TestCompleteSAML_JITAndReconcileEventsNameTheClientIP(t *testing.T) {
	w := newJITMintWorld(t)

	session, err := w.acs()
	require.NoError(t, err)
	require.NotNil(t, session)

	for _, ev := range []string{EventSSOLogin, EventSSOJITProvision, EventSSOGroupsSynced, EventSSORolesSynced} {
		rows := w.events(ev)
		require.Len(t, rows, 1, "%s: one row per login", ev)
		assert.Equal(t, jitMintIP, rows[0].IPAddress, "%s must name the client the login came from", ev)
	}
}

func TestCompleteSAML_ReconcileRefusalEventsNameTheClientIP(t *testing.T) {
	t.Run("group refusal", func(t *testing.T) {
		f := newSAMLReconcileFixture(t, &ports.SAMLAssertion{Subject: "corp|123", Groups: []string{"engineers"}, GroupsPresent: true}, nil)
		f.group(41, "engineers")
		f.group(42, "idp-admins")
		f.member(samlReconcileUserID, 41)
		f.member(samlReconcileUserID, 42)
		f.fault.failRemoveGroup[42] = true

		_, err := f.login()
		require.ErrorIs(t, err, ErrSSOReconcileIncomplete)

		rows := f.events(EventSSOReconcileRefused)
		require.Len(t, rows, 1)
		assert.Equal(t, "1.2.3.4", rows[0].IPAddress)
	})
	t.Run("last admin refusal", func(t *testing.T) {
		f := newSAMLReconcileFixture(t, &ports.SAMLAssertion{Subject: "corp|123", Groups: []string{"engineers"}, GroupsPresent: true}, nil)
		f.group(41, "engineers")
		f.group(42, "idp-admins")
		f.role(60, "admin", true)
		f.groupGrant(42, 60)
		f.member(samlReconcileUserID, 41)
		f.member(samlReconcileUserID, 42)

		_, err := f.login()
		require.ErrorIs(t, err, storage.ErrWouldStrandLastAdmin)

		rows := f.events(EventSSOReconcileLastAdminRefused)
		require.Len(t, rows, 1)
		assert.Equal(t, "1.2.3.4", rows[0].IPAddress)
	})
}

func TestCompleteSSO_ReconcileEventsNameTheClientIP(t *testing.T) {
	t.Run("group sync", func(t *testing.T) {
		f := newOIDCReconcileFixture(t, []string{"engineers"}, nil)
		f.group(41, "engineers")

		_, err := f.login()
		require.NoError(t, err)

		rows := f.events(EventSSOGroupsSynced)
		require.Len(t, rows, 1)
		assert.Equal(t, "1.2.3.4", rows[0].IPAddress)
	})
	t.Run("role sync", func(t *testing.T) {
		f := newOIDCReconcileFixture(t, []string{"g-a"}, map[string]string{"g-a": "role_a"})
		f.role(51, "role_a", false)

		_, err := f.login()
		require.NoError(t, err)

		rows := f.events(EventSSORolesSynced)
		require.Len(t, rows, 1)
		assert.Equal(t, "1.2.3.4", rows[0].IPAddress)
	})
	t.Run("group refusal", func(t *testing.T) {
		f := newOIDCReconcileFixture(t, []string{"engineers"}, nil)
		f.group(41, "engineers")
		f.group(42, "idp-admins")
		f.member(samlReconcileUserID, 41)
		f.member(samlReconcileUserID, 42)
		f.fault.failRemoveGroup[42] = true

		_, err := f.login()
		require.ErrorIs(t, err, ErrSSOReconcileIncomplete)

		rows := f.events(EventSSOReconcileRefused)
		require.Len(t, rows, 1)
		assert.Equal(t, "1.2.3.4", rows[0].IPAddress)
	})
}
