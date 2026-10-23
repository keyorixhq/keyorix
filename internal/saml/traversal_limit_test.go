package saml

// traversal_limit_test.go pins the element-count bound ParseResponse inherits from
// goxmldsig v1.6.1 (GHSA-qhrp-hfff-vphr: etreeutils.NSDetatch now charges the whole
// detached subtree against the 1000-element traversal budget). A validly signed
// response one element over the budget must be refused by our own pre-check with a
// clean error, never by the library stack's recovered-panic path; one at the budget must
// still log in.

import (
	"bytes"
	"encoding/base64"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/keyorixhq/keyorix/internal/saml/samltest"
	"github.com/russellhaering/goxmldsig/etreeutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMaxResponseElements_MatchesGoxmldsigBudget guards the condition the pre-check
// rests on: goxmldsig's default traversal budget is exactly maxResponseElements and
// NSDetatch enforces it over a whole subtree. If upstream changes either, this fails
// and maxResponseElements must be re-derived.
func TestMaxResponseElements_MatchesGoxmldsigBudget(t *testing.T) {
	flat := func(elements int) *etree.Element {
		root := etree.NewDocument().CreateElement("root")
		for range elements - 1 {
			root.CreateElement("a")
		}
		return root
	}
	_, err := etreeutils.NSDetatch(etreeutils.NewDefaultNSContext(), flat(maxResponseElements))
	require.NoError(t, err, "a subtree of exactly maxResponseElements elements must fit the budget")
	_, err = etreeutils.NSDetatch(etreeutils.NewDefaultNSContext(), flat(maxResponseElements+1))
	require.ErrorIs(t, err, etreeutils.ErrTraversalLimit, "one element more must exceed the budget")
}

// signedResponseWithElements returns a validly signed response of exactly `elements`
// elements.
func signedResponseWithElements(t *testing.T, fx *samltest.IdPFixture, idpEntityID string, p *Provider, elements int) string {
	t.Helper()
	resp, err := samltest.SignedResponseWithElements(fx, idpEntityID, p.sp.Metadata(), "user@corp.example", elements, "rs")
	require.NoError(t, err)
	return resp
}

func postSAMLResponse(t *testing.T, acsURL, samlResponse string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(url.Values{"SAMLResponse": {samlResponse}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, r.ParseForm())
	return r
}

// captureLog redirects the standard logger (ParseResponse's server-side detail) for
// the duration of fn and returns what was written.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	fn()
	return buf.String()
}

func TestParseResponse_TraversalLimit(t *testing.T) {
	const idpEntityID = "https://idp.example/entity"
	const acsURL = "https://keyorix.internal/auth/saml/corp/acs"
	fx, err := samltest.NewIdPFixture(idpEntityID)
	require.NoError(t, err)
	p, err := NewProvider(Config{
		Name: "corp", IDPMetadataXML: fx.MetadataXML,
		SPEntityID: "https://keyorix.internal/saml/corp/metadata", ACSURL: acsURL,
		AllowIDPInitiated: true, GroupsAttr: "eduPersonAffiliation",
	})
	require.NoError(t, err)

	t.Run("at the limit is accepted", func(t *testing.T) {
		resp := signedResponseWithElements(t, fx, idpEntityID, p, maxResponseElements)
		info, err := p.ParseResponse(postSAMLResponse(t, acsURL, resp), nil)
		require.NoError(t, err, "a signed response of exactly %d elements must still log in", maxResponseElements)
		assert.Equal(t, "user@corp.example", info.Subject)
	})

	t.Run("one over the limit is refused cleanly", func(t *testing.T) {
		resp := signedResponseWithElements(t, fx, idpEntityID, p, maxResponseElements+1)
		var err error
		logged := captureLog(t, func() {
			require.NotPanics(t, func() { _, err = p.ParseResponse(postSAMLResponse(t, acsURL, resp), nil) })
		})
		require.ErrorIs(t, err, errInvalidSAMLResponse)
		assert.Contains(t, logged, "response has more than 1000 elements", "refused by our pre-check")
		assert.NotContains(t, logged, "panic", "the library must never be reached with an over-limit response")
	})

	t.Run("deep nesting is refused without a stack overflow", func(t *testing.T) {
		deep := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
			strings.Repeat("<a>", 200000) + strings.Repeat("</a>", 200000) + `</samlp:Response>`
		var err error
		logged := captureLog(t, func() {
			require.NotPanics(t, func() {
				_, err = p.ParseResponse(postSAMLResponse(t, acsURL, base64.StdEncoding.EncodeToString([]byte(deep))), nil)
			})
		})
		require.ErrorIs(t, err, errInvalidSAMLResponse)
		assert.Contains(t, logged, "nests deeper than")
		assert.NotContains(t, logged, "panic")
	})
}
