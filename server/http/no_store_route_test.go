package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoStore_ScopedToAPI confirms every API response carries Cache-Control: no-store
// (even an unauthenticated 401, since the middleware runs before auth), while non-API
// paths keep their own caching — secret values must never sit in a browser/proxy cache.
func TestNoStore_ScopedToAPI(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	router, err := NewRouter(&config.Config{}, newTestCore(t))
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	cacheCtl := func(path string) (int, string) {
		resp, err := client.Get(srv.URL + path)
		require.NoError(t, err)
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Cache-Control")
	}

	// An API response (here a 401 — no auth) is no-store.
	code, cc := cacheCtl("/api/v1/secrets")
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Equal(t, "no-store", cc, "API responses must be no-store")

	// A non-API path keeps its own cache policy, not no-store (health sets no-cache).
	_, cc = cacheCtl("/health")
	assert.NotEqual(t, "no-store", cc, "non-API responses keep their own cache headers")
}

// TestNoStore_CoversAuthAndTokenEndpoints proves the unauthenticated auth/token
// routes registered OUTSIDE the /api/v1 group (login, refresh, MFA/WebAuthn verify,
// system bootstrap, setup-link consumption, the SSO/SAML login+callback surface) also
// carry Cache-Control: no-store. Several of these responses mint or hand back a
// session token; without no-store a browser or intermediate cache could retain a
// response containing one.
func TestNoStore_CoversAuthAndTokenEndpoints(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	router, err := NewRouter(&config.Config{}, newTestCore(t))
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{
		// Don't follow the SSO/SAML redirects — inspect the redirect response itself.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	post := func(path string) string {
		resp, err := client.Post(srv.URL+path, "application/json", strings.NewReader("{}"))
		require.NoError(t, err, path)
		_ = resp.Body.Close()
		return resp.Header.Get("Cache-Control")
	}
	get := func(path string) string {
		resp, err := client.Get(srv.URL + path)
		require.NoError(t, err, path)
		_ = resp.Body.Close()
		return resp.Header.Get("Cache-Control")
	}

	for _, path := range []string{
		"/auth/login",
		"/auth/logout",
		"/auth/refresh",
		"/auth/password-reset",
		"/auth/mfa/verify",
		"/auth/webauthn/login/begin",
		"/auth/webauthn/login/finish",
		"/auth/webauthn/passwordless/begin",
		"/auth/webauthn/passwordless/finish",
		"/system/init",
		"/auth/setup/consume",
	} {
		assert.Equal(t, "no-store", post(path), "%s must be no-store", path)
	}

	for _, path := range []string{
		"/auth/setup/sometoken",
		"/auth/sso/providers",
		"/auth/sso/someprovider/login",
		"/auth/sso/someprovider/callback",
		"/auth/saml/someprovider/metadata",
		"/auth/saml/someprovider/login",
	} {
		assert.Equal(t, "no-store", get(path), "%s must be no-store", path)
	}
}
