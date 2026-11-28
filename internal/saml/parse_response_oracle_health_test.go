package saml

// parse_response_oracle_health_test.go keeps FuzzParseResponse's error oracle able to
// see a raw library error (keyorix#4750).
//
// ParseResponse has three places that refuse a response: the epilogue check, the strict
// assertion shape check, and the library call (parseResponseRecovered). The first two
// return the sentinel by construction, so a fuzz seed that is refused by either one says
// nothing about the third. Before this seed every committed seed was refused by one of
// the first two (or accepted, for the signed one), so a change that returned the
// library's error instead of errInvalidSAMLResponse stayed green. The seed below is the
// smallest input that gets past both pre-checks and fails in the library: well-formed,
// one Assertion with one Subject/NameID and one Conditions, no signature.

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	csaml "github.com/crewjam/saml"
	"github.com/stretchr/testify/require"
)

// unsignedWellFormedResponseSeed is the base64 SAMLResponse FuzzParseResponse seeds the
// library-failure branch with. The NameID differs from the signed fixture's on purpose
// (nothing here is ever accepted); the shape is what matters.
func unsignedWellFormedResponseSeed() string {
	const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" Destination="https://keyorix.internal/auth/saml/corp/acs">` +
		`<saml:Issuer>https://idp.example/entity</saml:Issuer>` +
		`<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">` +
		`<saml:Issuer>https://idp.example/entity</saml:Issuer>` +
		`<saml:Subject><saml:NameID>user@corp.example</saml:NameID></saml:Subject>` +
		`<saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/>` +
		`</saml:Assertion></samlp:Response>`
	return base64.StdEncoding.EncodeToString([]byte(xml))
}

// TestParseResponseSeed_ReachesLibraryFailureBranch is the oracle-health guard for
// FuzzParseResponse: the seed it adds must pass both pre-checks, be refused by the
// library with a validation error (not a recovered panic), and still reach the caller as
// the bare sentinel. If a later change makes either pre-check refuse the seed, the
// fuzzer's ERROR-ORACLE SANITIZATION invariant is blind to the library branch again and
// this test fails instead of the fuzzer staying green.
func TestParseResponseSeed_ReachesLibraryFailureBranch(t *testing.T) {
	p, acsURL, _ := buildSignedResponseB64(t)
	seed := unsignedWellFormedResponseSeed()

	body := url.Values{"SAMLResponse": {seed}}.Encode()
	req := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, req.ParseForm())

	require.NoError(t, validatePostedResponseHasNoEpilogue(req),
		"seed must pass the epilogue check, or it never reaches the library")
	nameID, err := strictAssertionShape(req)
	require.NoError(t, err, "seed must pass strictAssertionShape, or it never reaches the library")
	require.Equal(t, "user@corp.example", nameID)

	assertion, err := p.parseResponseRecovered(req, nil)
	require.Error(t, err, "an unsigned response must be refused by the library")
	require.Nil(t, assertion)
	var ire *csaml.InvalidResponseError
	require.True(t, errors.As(err, &ire),
		"the library must refuse the seed with its own validation error, not a recovered panic: %v", err)

	info, perr := submitSAMLResponse(t, p, acsURL, seed)
	require.Nil(t, info)
	require.True(t, perr == errInvalidSAMLResponse,
		"a library failure must reach the caller as the bare sentinel, got %q (%T)", perr, perr)
}
