// scim_sso_first_login_test.go: a SCIM-provisioned account starts in
// pending_first_login with a random, discarded password. Its owner signs in
// through the IdP, so the first SSO login must clear that state; otherwise the
// session is confined to change-password, which needs a current password nobody
// knows (#3655). The clear is scoped to accounts whose credential the IdP owns:
// a local-password account keeps the restriction, and a suspended, deprovisioned
// or locked account stays blocked.
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
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// scimSSOHarness drives CompleteSSO against REAL storage (not the mock) so the
// account_state write is what the assertions read back.
type scimSSOHarness struct {
	t   *testing.T
	c   *KeyorixCore
	key *rsa.PrivateKey
	p   *SSOProvider
	idp *httptest.Server
	// idToken is what the fake token endpoint returns next.
	idToken string
}

func newSCIMSSOHarness(t *testing.T, c *KeyorixCore) *scimSSOHarness {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	h := &scimSSOHarness{t: t, c: c, key: key}
	h.idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"at","token_type":"Bearer","id_token":%q}`, h.idToken)
	}))
	t.Cleanup(h.idp.Close)
	h.p = &SSOProvider{
		Name: "okta", Issuer: "https://idp.test", ClientID: "client-1",
		OAuth: &oauth2.Config{
			ClientID:    "client-1",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.test/authorize", TokenURL: h.idp.URL},
			RedirectURL: "https://keyorix.test/auth/sso/okta/callback",
			Scopes:      []string{"openid", "email"},
		},
		CompleteURL: "https://keyorix.test/auth/sso/complete",
	}
	c.ssoJWKS = staticResolver{kid: "kid-1", key: &key.PublicKey}
	c.ssoProviders = map[string]*SSOProvider{"okta": h.p}
	return h
}

// login runs one full CompleteSSO round for an IdP identity asserting email.
func (h *scimSSOHarness) login(sub, email string) (*models.Session, *models.User, error) {
	h.t.Helper()
	ctx := context.Background()
	state := "state-" + sub
	nonce := "nonce-" + sub
	require.NoError(h.t, h.c.storage.CreateSSOLoginState(ctx, &models.SSOLoginState{
		State: state, Nonce: nonce, Provider: "okta", ReturnTo: "/",
		ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
	}))
	h.idToken = signToken(h.t, h.key, "kid-1", jwt.MapClaims{
		"iss": "https://idp.test", "aud": "client-1", "sub": sub,
		"email": email, "email_verified": true, "nonce": nonce,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	session, user, _, err := h.c.CompleteSSO(ctx, "okta", "auth-code", state, "ua", "1.2.3.4")
	return session, user, err
}

func accountStateOf(t *testing.T, c *KeyorixCore, id uint) string {
	t.Helper()
	u, err := c.storage.GetUser(context.Background(), id)
	require.NoError(t, err)
	return NormalizeAccountState(u.AccountState)
}

func countAuditEvents(t *testing.T, c *KeyorixCore, eventType string) int {
	t.Helper()
	events, _, err := c.storage.GetAuditLogs(context.Background(), &storage.AuditFilter{Action: &eventType, Page: 1, PageSize: 100})
	require.NoError(t, err)
	return len(events)
}

// runSCIMSSOFirstLoginSuite is the backend-independent body, run on SQLite and
// on PostgreSQL.
func runSCIMSSOFirstLoginSuite(t *testing.T, c *KeyorixCore) {
	seedDefaultCatalog(t, c)
	ctx := context.Background()
	h := newSCIMSSOHarness(t, c)

	t.Run("scim user first SSO login clears pending_first_login", func(t *testing.T) {
		u, err := c.ProvisionSCIMUser(ctx, 0, "ada", "Ada", "ada@x.io", "ext-ada", true)
		require.NoError(t, err)
		require.Equal(t, AccountPendingFirstLogin, accountStateOf(t, c, u.ID), "premise: SCIM provisions pending_first_login")

		session, user, err := h.login("okta|ada", "ada@x.io")
		require.NoError(t, err)
		require.NotNil(t, session)
		assert.Equal(t, u.ID, user.ID)
		assert.Equal(t, AccountActive, accountStateOf(t, c, u.ID), "no reactivate workaround needed")
		assert.False(t, AccountRestricted(user.AccountState), "the returned user must not drive a restricted session")
		assert.Equal(t, 1, countAuditEvents(t, c, EventSCIMFirstLoginCompleted), "the state change is audited")
	})

	t.Run("second SSO login is a no-op for the state and writes no second event", func(t *testing.T) {
		_, user, err := h.login("okta|ada", "ada@x.io")
		require.NoError(t, err)
		assert.Equal(t, AccountActive, accountStateOf(t, c, user.ID))
		assert.Equal(t, 1, countAuditEvents(t, c, EventSCIMFirstLoginCompleted))
	})

	t.Run("local account claimed by SSO keeps pending_first_login", func(t *testing.T) {
		u, err := c.CreateUser(ctx, &CreateUserRequest{
			Username: "local", Email: "local@x.io", Password: "Tr1ckyHorseStaple-9!Zq", DisplayName: "Local",
		})
		require.NoError(t, err)
		require.NoError(t, c.storage.SetAccountState(ctx, u.ID, AccountPendingFirstLogin, time.Now()))

		_, user, err := h.login("okta|local", "local@x.io")
		require.NoError(t, err)
		assert.Equal(t, u.ID, user.ID)
		assert.Equal(t, AccountPendingFirstLogin, accountStateOf(t, c, u.ID),
			"an SSO login must not let a local-password account skip first login")
	})

	t.Run("suspended scim user stays blocked", func(t *testing.T) {
		u, err := c.ProvisionSCIMUser(ctx, 0, "sus", "Sus", "sus@x.io", "ext-sus", true)
		require.NoError(t, err)
		// Storage write, not SuspendUser: this test has no admin actor to clear
		// SuspendUser's rank ceiling, and only the resulting state matters here.
		require.NoError(t, c.storage.SetAccountState(ctx, u.ID, AccountSuspended, time.Now()))

		session, _, err := h.login("okta|sus", "sus@x.io")
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, AccountSuspended, accountStateOf(t, c, u.ID))
	})

	t.Run("deprovisioned scim user stays blocked", func(t *testing.T) {
		u, err := c.ProvisionSCIMUser(ctx, 0, "gone", "Gone", "gone@x.io", "ext-gone", false)
		require.NoError(t, err)
		require.Equal(t, AccountDeprovisioned, accountStateOf(t, c, u.ID))

		session, _, err := h.login("okta|gone", "gone@x.io")
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, AccountDeprovisioned, accountStateOf(t, c, u.ID))
	})
}

func TestSCIMUserFirstSSOLogin_ClearsPendingFirstLogin(t *testing.T) {
	c := newPreFixOrderingCore(t)
	runSCIMSSOFirstLoginSuite(t, c)
}

func TestSCIMUserFirstSSOLogin_ClearsPendingFirstLogin_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	db := pgOpen(t, pgMigratedDatabaseDSN(t, base))
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	runSCIMSSOFirstLoginSuite(t, NewKeyorixCore(store.NewLocalStorage(db)))
}
