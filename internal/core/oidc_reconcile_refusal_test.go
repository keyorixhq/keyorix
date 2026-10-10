// oidc_reconcile_refusal_test.go — #2907: the OIDC login (CompleteSSO) applies
// the same rule #2839/#2903 applied to SAML. A group/role reconcile that did not
// fully apply refuses the login. The error wraps ErrSSOReconcileIncomplete, the
// refusal is audited the same way, and the last-admin behaviour is the same.
//
// It reuses saml_reconcile_refusal_test.go's real-SQLite fixture. Only the
// login leg differs: a signed id_token from a test token endpoint instead of a
// SAML assertion.
package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type oidcReconcileFixture struct {
	*samlReconcileFixture
	key    *rsa.PrivateKey
	p      *SSOProvider
	groups any // the id_token's "groups" claim; nil = claim absent
}

// newOIDCReconcileFixture builds the same real-SQLite world as the SAML
// fixture, then swaps the provider for an OIDC one named "corp". The fixture
// user's external id (sso:corp:corp|123) resolves from the id_token's sub.
func newOIDCReconcileFixture(t *testing.T, groups any, groupRoleMap map[string]string) *oidcReconcileFixture {
	t.Helper()
	base := newSAMLReconcileFixture(t, &ports.SAMLAssertion{}, nil)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p := &SSOProvider{
		Name: "corp", Issuer: "https://idp.test", ClientID: "client-1",
		OAuth: &oauth2.Config{
			ClientID:    "client-1",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.test/authorize"},
			RedirectURL: "https://keyorix.test/auth/sso/corp/callback",
		},
		GroupSync: true, GroupRoleMap: groupRoleMap,
	}
	base.c.ssoProviders = map[string]*SSOProvider{"corp": p}
	base.c.ssoJWKS = staticResolver{kid: "kid-1", key: &key.PublicKey}
	return &oidcReconcileFixture{samlReconcileFixture: base, key: key, p: p, groups: groups}
}

func (f *oidcReconcileFixture) login() (*models.Session, error) {
	f.t.Helper()
	const nonce = "nonce-1"
	claims := jwt.MapClaims{
		"iss": "https://idp.test", "aud": "client-1", "sub": "corp|123",
		"email": "ada@x.io", "email_verified": true, "nonce": nonce,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	if f.groups != nil {
		claims["groups"] = f.groups
	}
	idToken := signToken(f.t, f.key, "kid-1", claims)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"at","token_type":"Bearer","id_token":%q}`, idToken)
	}))
	f.t.Cleanup(ts.Close)
	f.p.OAuth.Endpoint.TokenURL = ts.URL

	require.NoError(f.t, f.db.Create(&models.SSOLoginState{
		State: "state-1", Nonce: nonce, Provider: "corp", ReturnTo: "/home",
		ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
	}).Error)
	session, _, _, err := f.c.CompleteSSO(context.Background(), "corp", "code-1", "state-1", "ua", "1.2.3.4")
	return session, err
}

// TestCompleteSSO_FailedGroupRemovalRefusesTheLogin is #2907's headline: the
// IdP stopped asserting a group the user still holds, the removal fails, and
// the OIDC login must not reach CreateSession.
//
// RED before the fix: syncSSOGroups discarded the error (`_ =`), CompleteSSO
// minted a session, and the user kept the revoked membership for its lifetime.
func TestCompleteSSO_FailedGroupRemovalRefusesTheLogin(t *testing.T) {
	f := newOIDCReconcileFixture(t, []string{"engineers"}, nil)
	f.group(41, "engineers")
	f.group(42, "idp-admins")
	f.member(samlReconcileUserID, 41)
	f.member(samlReconcileUserID, 42)
	f.fault.failRemoveGroup[42] = true

	session, err := f.login()

	f.assertRefusedWithoutSession(session, err, SSOMsgGroupReconcileRefused)
	assert.True(t, f.memberOf(42))
	refused := f.events(EventSSOReconcileRefused)
	require.Len(t, refused, 1, "the OIDC refusal is audited exactly like the SAML one")
	assert.Contains(t, refused[0].Description, `remove group 42 "idp-admins"`)
}

// TestCompleteSSO_PartialRoleReconcile_TwoOfThreeApplied: the OIDC
// counterpart of the SAML 2-of-3 case. The two grants persist, the failed
// revocation refuses the login, and the event records +2/-0.
func TestCompleteSSO_PartialRoleReconcile_TwoOfThreeApplied(t *testing.T) {
	f := newOIDCReconcileFixture(t, []string{"g-a", "g-b"},
		map[string]string{"g-a": "role_a", "g-b": "role_b", "g-c": "role_c"})
	f.role(51, "role_a", false)
	f.role(52, "role_b", false)
	f.role(53, "role_c", false)
	f.grant(samlReconcileUserID, 53)
	f.fault.failRemoveRole[53] = true

	session, err := f.login()

	f.assertRefusedWithoutSession(session, err, SSOMsgRoleReconcileRefused)
	assert.True(t, f.holds(51))
	assert.True(t, f.holds(52))
	assert.True(t, f.holds(53))
	refused := f.events(EventSSOReconcileRefused)
	require.Len(t, refused, 1)
	assert.Contains(t, refused[0].Description, `revoke role "role_c"`)
	assert.Contains(t, refused[0].Description, "+2/-0")
}

// TestCompleteSSO_LastAdminGroupRemovalRefused: same last-admin behaviour as
// SAML (Andrei, 2026-10-10). The IdP's revocation wins, the login stays
// refused, and the distinct event names the ways back.
func TestCompleteSSO_LastAdminGroupRemovalRefused(t *testing.T) {
	f := newOIDCReconcileFixture(t, []string{"engineers"}, nil)
	f.group(41, "engineers")
	f.group(42, "idp-admins")
	f.role(60, "admin", true)
	f.groupGrant(42, 60)
	f.member(samlReconcileUserID, 41)
	f.member(samlReconcileUserID, 42)

	session, err := f.login()

	f.assertRefusedWithoutSession(session, err, SSOMsgLastAdminRemovalRefused)
	assert.ErrorIs(t, err, storage.ErrWouldStrandLastAdmin)
	assert.True(t, f.memberOf(42))
	ev := f.events(EventSSOReconcileLastAdminRefused)
	require.Len(t, ev, 1)
	assert.Contains(t, ev[0].Description, "recover-admin")
}

// TestCompleteSSO_EmptyGroupsClaimReconcilesToZero is a calibration. It held
// before #2907, because extractTokenStringList already distinguishes
// present-but-empty from absent. It stops the refusal tests above being
// satisfied by refusing every login: a clean reconcile that removes things
// still mints a session.
func TestCompleteSSO_EmptyGroupsClaimReconcilesToZero(t *testing.T) {
	f := newOIDCReconcileFixture(t, []string{}, map[string]string{"ops": "ops_role"})
	f.group(42, "ops")
	f.member(samlReconcileUserID, 42)
	f.role(51, "ops_role", false)
	f.grant(samlReconcileUserID, 51)

	session, err := f.login()

	require.NoError(t, err)
	require.NotNil(t, session)
	assert.False(t, f.memberOf(42))
	assert.False(t, f.holds(51))
	assert.Len(t, f.events(EventSSOLogin), 1)
}

// TestCompleteSSO_AbsentGroupsClaimLeavesMembershipsAlone is a calibration
// for the absent side: no claim means no group information, so nothing is
// touched and the login proceeds.
func TestCompleteSSO_AbsentGroupsClaimLeavesMembershipsAlone(t *testing.T) {
	f := newOIDCReconcileFixture(t, nil, map[string]string{"ops": "ops_role"})
	f.group(42, "ops")
	f.member(samlReconcileUserID, 42)
	f.role(51, "ops_role", false)
	f.grant(samlReconcileUserID, 51)

	session, err := f.login()

	require.NoError(t, err)
	require.NotNil(t, session)
	assert.True(t, f.memberOf(42))
	assert.True(t, f.holds(51))
}
