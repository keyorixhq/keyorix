// saml_acs_traversal_limit_test.go drives the real ACS handler (POST
// /auth/saml/{provider}/acs) with a real saml.Provider and validly signed responses
// either side of goxmldsig v1.6.1's 1000-element traversal budget
// (GHSA-qhrp-hfff-vphr): at the budget the login completes; one element over it is
// refused with the ordinary error redirect, no panic reaching the request path.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	samlpkg "github.com/keyorixhq/keyorix/internal/saml"
	"github.com/keyorixhq/keyorix/internal/saml/samltest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestCompleteSAML_TraversalLimit(t *testing.T) {
	const idpEntityID = "https://idp.example/entity"
	const acsURL = "https://keyorix.internal/auth/saml/corp/acs"
	// goxmldsig's default NSContext budget; internal/saml pins it
	// (TestMaxResponseElements_MatchesGoxmldsigBudget).
	const budget = 1000

	fx, err := samltest.NewIdPFixture(idpEntityID)
	require.NoError(t, err)
	p, err := samlpkg.NewProvider(samlpkg.Config{
		Name: "corp", IDPMetadataXML: fx.MetadataXML,
		SPEntityID: "https://keyorix.internal/saml/corp/metadata", ACSURL: acsURL,
		AllowIDPInitiated: true, EmailAttr: "mail", GroupsAttr: "eduPersonAffiliation",
	})
	require.NoError(t, err)

	cs, db := freshCoreS12WithAdmin(t)
	seedSSODefaultRoleS13(t, cs)
	cs.SetSSOProviders(map[string]*core.SSOProvider{
		"corp": {Name: "corp", Type: "saml", SAML: p, CompleteURL: "https://app.example/auth/sso/complete", AutoProvision: true},
	}, nil)
	h := NewAuthHandler(cs, false)

	post := func(t *testing.T, relay string, elements int) (*httptest.ResponseRecorder, string) {
		t.Helper()
		require.NoError(t, db.Create(&models.SSOLoginState{
			State: relay, Nonce: "nonce-" + relay, Provider: "corp",
			ExpiresAt: time.Now().Add(10 * time.Minute), CreatedAt: time.Now(),
		}).Error)
		resp, err := samltest.SignedResponseWithElements(fx, idpEntityID, p.RawServiceProviderMetadata(), "limit-user@corp.example", elements, relay)
		require.NoError(t, err)
		body := url.Values{"RelayState": {relay}, "SAMLResponse": {resp}}.Encode()
		req := withChiParam(httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", strings.NewReader(body)), "provider", "corp")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		buf := captureLogBuf(t)
		require.NotPanics(t, func() { h.CompleteSAML(w, req) })
		return w, buf.String()
	}

	t.Run("at the budget logs in", func(t *testing.T) {
		w, _ := post(t, "relay-at-budget", budget)
		require.Equal(t, http.StatusFound, w.Code)
		assert.NotContains(t, w.Header().Get("Location"), "error=")
	})

	t.Run("one over the budget is refused cleanly", func(t *testing.T) {
		w, logged := post(t, "relay-over-budget", budget+1)
		require.Equal(t, http.StatusFound, w.Code)
		assert.Contains(t, w.Header().Get("Location"), "error=")
		assert.Contains(t, logged, "response has more than 1000 elements")
		assert.NotContains(t, logged, "panic")
	})
}
