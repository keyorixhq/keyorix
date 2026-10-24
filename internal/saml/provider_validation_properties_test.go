package saml

// provider_validation_properties_test.go pins, end to end through Provider.ParseResponse,
// the validation decisions this package delegates to crewjam/saml (signature, audience,
// recipient, time window, InResponseTo, issuer, status) plus two limits of the
// namespace-strict shape check. The package's own code has almost no branch for the
// delegated decisions: they hold because NewProvider wires the library correctly and
// ParseResponse refuses whatever the library refuses. Mutation testing cannot see a library
// regression or a mis-wired Provider, so each property is named and fails closed.
//
// A refusal alone proves little (a broken fixture is refused too), so every refusal also
// asserts the server-side log line carries the reason for THAT property, and each table has
// an accepted control built the same way.

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

const propSPEntityID = "https://keyorix.internal/saml/corp/metadata"

func setAttr(el *etree.Element, attr, value string) {
	el.RemoveAttr(attr)
	el.CreateAttr(attr, value)
}

func setTimeAttr(el *etree.Element, attr string, t time.Time) {
	setAttr(el, attr, t.UTC().Format(time.RFC3339))
}

func subjectConfirmationData(a *etree.Element) *etree.Element {
	return childByTag(childByTag(childByTag(a, "Subject"), "SubjectConfirmation"), "SubjectConfirmationData")
}

func postRequest(t *testing.T, acsURL, samlResponseB64 string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(url.Values{"SAMLResponse": {samlResponseB64}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, req.ParseForm())
	return req
}

// captureLog redirects the standard logger (where ParseResponse writes the library's
// private detail) and returns a reader for what was logged.
func captureLog(t *testing.T) func() string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf.String
}

func editResponse(t *testing.T, b64 string, fn func(resp *etree.Element)) *etree.Document {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	require.NoError(t, err)
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(raw))
	fn(doc.Root())
	return doc
}

func encodeDoc(t *testing.T, doc *etree.Document) string {
	t.Helper()
	out, err := doc.WriteToBytes()
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(out)
}

// tamperResponse applies fn to the Response WITHOUT signing it again: the Response
// signature (which covers the Assertion) no longer matches.
func tamperResponse(t *testing.T, b64 string, fn func(resp *etree.Element)) string {
	t.Helper()
	return encodeDoc(t, editResponse(t, b64, fn))
}

// resignResponse applies fn to the Response envelope and signs the Response again with the
// trusted IdP key, so only fn's change distinguishes it from a genuine response.
func resignResponse(t *testing.T, b64 string, key *rsa.PrivateKey, cert *x509.Certificate, fn func(resp *etree.Element)) string {
	t.Helper()
	doc := editResponse(t, b64, func(resp *etree.Element) {
		for _, sig := range resp.SelectElements("Signature") {
			resp.RemoveChild(sig)
		}
		fn(resp)
	})
	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert,
	}))
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	require.NoError(t, ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod))
	signed, err := ctx.SignEnveloped(doc.Root())
	require.NoError(t, err)
	// The library finds the Signature by name among the root's children; its position
	// (the schema puts it after Issuer) is irrelevant, so it is left where it was appended.
	out := etree.NewDocument()
	out.SetRoot(signed)
	return encodeDoc(t, out)
}

// requireRefused submits b64 and requires the sanitized refusal, no identity, and that the
// operator-side log names wantLog (the reason for this specific property).
func requireRefused(t *testing.T, p *Provider, acsURL, b64 string, requestIDs []string, wantLog string) {
	t.Helper()
	logged := captureLog(t)
	info, err := p.ParseResponse(postRequest(t, acsURL, b64), requestIDs)
	require.ErrorIs(t, err, errInvalidSAMLResponse)
	require.Nil(t, info, "a refused response must not yield an identity")
	require.Equal(t, "saml: invalid response", err.Error(), "the caller sees only the fixed error")
	require.Contains(t, logged(), wantLog, "refused, but not for the reason under test")
}

// TestParseResponse_Property_AssertionValidationFailsClosed: every violation of an
// assertion-level condition is refused, and the unmodified control is accepted.
func TestParseResponse_Property_AssertionValidationFailsClosed(t *testing.T) {
	cases := map[string]struct {
		mutate  func(a *etree.Element)
		wantLog string
	}{
		"time window: assertion not yet valid (NotBefore in the future)": {func(a *etree.Element) {
			setTimeAttr(childByTag(a, "Conditions"), "NotBefore", time.Now().Add(time.Hour))
		}, "Conditions is not yet valid"},
		"time window: assertion expired (NotOnOrAfter in the past)": {func(a *etree.Element) {
			setTimeAttr(childByTag(a, "Conditions"), "NotOnOrAfter", time.Now().Add(-time.Hour))
		}, "Conditions is expired"},
		"time window: SubjectConfirmationData expired": {func(a *etree.Element) {
			setTimeAttr(subjectConfirmationData(a), "NotOnOrAfter", time.Now().Add(-time.Hour))
		}, "SubjectConfirmationData is expired"},
		"time window: assertion IssueInstant too old": {func(a *etree.Element) {
			setTimeAttr(a, "IssueInstant", time.Now().Add(-time.Hour))
		}, "expired on"},
		"recipient: SubjectConfirmationData Recipient is another ACS": {func(a *etree.Element) {
			setAttr(subjectConfirmationData(a), "Recipient", "https://other.example/acs")
		}, "Recipient is not"},
		"recipient: SubjectConfirmationData Recipient missing": {func(a *etree.Element) {
			subjectConfirmationData(a).RemoveAttr("Recipient")
		}, "Recipient is not"},
		"audience: AudienceRestriction names another service provider": {func(a *etree.Element) {
			childByTag(childByTag(childByTag(a, "Conditions"), "AudienceRestriction"), "Audience").SetText("https://other.example/sp")
		}, "does not match this service provider"},
		"audience: AudienceRestriction absent (the library would accept vacuously)": {func(a *etree.Element) {
			c := childByTag(a, "Conditions")
			c.RemoveChild(childByTag(c, "AudienceRestriction"))
		}, "no AudienceRestriction"},
		"issuer: assertion issued by another entity": {func(a *etree.Element) {
			childByTag(a, "Issuer").SetText("https://evil.example/entity")
		}, "issuer is not"},
	}

	t.Run("control: unmodified signed assertion is accepted", func(t *testing.T) {
		p, acsURL, b64 := buildSignedResponseB64WithAssertion(t, func(*etree.Element) {})
		info, err := p.ParseResponse(postRequest(t, acsURL, b64), nil)
		require.NoError(t, err)
		require.Equal(t, "user@corp.example", info.Subject)
	})
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, acsURL, b64 := buildSignedResponseB64WithAssertion(t, tc.mutate)
			requireRefused(t, p, acsURL, b64, nil, tc.wantLog)
		})
	}
}

// TestParseResponse_Property_ResponseLevelChecksFailClosed: the Response envelope carries
// Issuer, Destination, Status and IssueInstant; each wrong value is refused even though the
// Response is validly signed (so the signature cannot be the reason).
func TestParseResponse_Property_ResponseLevelChecksFailClosed(t *testing.T) {
	cases := map[string]struct {
		fn      func(resp *etree.Element)
		wantLog string
	}{
		"issuer: Response issued by another entity": {func(r *etree.Element) {
			childByTag(r, "Issuer").SetText("https://evil.example/entity")
		}, "response Issuer does not match"},
		"destination: Response addressed to another URL": {func(r *etree.Element) {
			setAttr(r, "Destination", "https://other.example/acs")
		}, "Destination"},
		"time window: Response IssueInstant too old": {func(r *etree.Element) {
			setTimeAttr(r, "IssueInstant", time.Now().Add(-time.Hour))
		}, "response IssueInstant expired"},
		"status: IdP reports failure": {func(r *etree.Element) {
			setAttr(childByTag(childByTag(r, "Status"), "StatusCode"), "Value", "urn:oasis:names:tc:SAML:2.0:status:Responder")
		}, "urn:oasis:names:tc:SAML:2.0:status:Responder"},
	}

	t.Run("control: re-signed unmodified Response is accepted", func(t *testing.T) {
		p, acsURL, b64, key, cert := buildSignedResponseWithKey(t, nil)
		info, err := p.ParseResponse(postRequest(t, acsURL, resignResponse(t, b64, key, cert, func(*etree.Element) {})), nil)
		require.NoError(t, err)
		require.Equal(t, "user@corp.example", info.Subject)
	})
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, acsURL, b64, key, cert := buildSignedResponseWithKey(t, nil)
			requireRefused(t, p, acsURL, resignResponse(t, b64, key, cert, tc.fn), nil, tc.wantLog)
		})
	}
}

// TestParseResponse_Property_InResponseToBinding: with IdP-initiated login off (the
// default), a response is accepted only for a request ID this SP issued; with no pending
// request ID, or a different one, it is refused.
func TestParseResponse_Property_InResponseToBinding(t *testing.T) {
	const issued = "id-issued-by-this-sp"
	build := func(t *testing.T) (*Provider, string, string) {
		p, acsURL, b64, key, cert := buildSignedResponseWithKey(t, func(a *etree.Element) {
			setAttr(subjectConfirmationData(a), "InResponseTo", issued)
		})
		b64 = resignResponse(t, b64, key, cert, func(r *etree.Element) { setAttr(r, "InResponseTo", issued) })
		p.sp.AllowIDPInitiated = false
		return p, acsURL, b64
	}

	t.Run("accepted for the request ID this SP issued", func(t *testing.T) {
		p, acsURL, b64 := build(t)
		info, err := p.ParseResponse(postRequest(t, acsURL, b64), []string{"unrelated", issued})
		require.NoError(t, err)
		require.Equal(t, "user@corp.example", info.Subject)
	})
	t.Run("refused when no request is pending (unsolicited response)", func(t *testing.T) {
		p, acsURL, b64 := build(t)
		requireRefused(t, p, acsURL, b64, nil, "InResponseTo")
	})
	t.Run("refused for a request ID this SP did not issue", func(t *testing.T) {
		p, acsURL, b64 := build(t)
		requireRefused(t, p, acsURL, b64, []string{"some-other-request"}, "InResponseTo")
	})
	t.Run("refused when the response carries no InResponseTo", func(t *testing.T) {
		p, acsURL, b64 := buildSignedResponseB64(t)
		p.sp.AllowIDPInitiated = false
		requireRefused(t, p, acsURL, b64, []string{issued}, "InResponseTo")
	})
}

// TestNewProvider_Property_IDPInitiatedOffByDefault: AllowIDPInitiated is false unless the
// operator opts in, so the InResponseTo binding above is the default posture.
func TestNewProvider_Property_IDPInitiatedOffByDefault(t *testing.T) {
	idpMD, _, _ := signedIDPFixture(t, "https://idp.example/entity")
	cfg := Config{
		Name: "corp", IDPMetadataXML: idpMD, SPEntityID: propSPEntityID,
		ACSURL: "https://keyorix.internal/auth/saml/corp/acs",
	}
	p, err := NewProvider(cfg)
	require.NoError(t, err)
	require.False(t, p.sp.AllowIDPInitiated)

	cfg.AllowIDPInitiated = true
	p, err = NewProvider(cfg)
	require.NoError(t, err)
	require.True(t, p.sp.AllowIDPInitiated)
}

// TestParseResponse_Property_SignatureRequiredAndPinned: some valid signature from the
// pinned IdP certificate must cover the assertion; unsigned, edited-after-signing and
// signed-by-another-key responses are all refused.
func TestParseResponse_Property_SignatureRequiredAndPinned(t *testing.T) {
	t.Run("response and assertion both unsigned is refused", func(t *testing.T) {
		p, acsURL, b64 := buildSignedResponseB64(t)
		b64 = tamperResponse(t, b64, func(r *etree.Element) {
			a := childByTag(r, "Assertion")
			for _, parent := range []*etree.Element{r, a} {
				for _, sig := range parent.SelectElements("Signature") {
					parent.RemoveChild(sig)
				}
				require.Empty(t, parent.SelectElements("Signature"))
			}
		})
		requireRefused(t, p, acsURL, b64, nil, "signature element not present")
	})
	t.Run("assertion edited after signing is refused", func(t *testing.T) {
		p, acsURL, b64 := buildSignedResponseB64(t)
		b64 = tamperResponse(t, b64, func(r *etree.Element) {
			nid := childByTag(childByTag(childByTag(r, "Assertion"), "Subject"), "NameID")
			require.Equal(t, "user@corp.example", nid.Text())
			nid.SetText("admin@corp.example")
		})
		requireRefused(t, p, acsURL, b64, nil, "cannot validate signature on Response")
	})
	t.Run("response signed by a key the provider does not pin is refused", func(t *testing.T) {
		pinned, acsURL, _ := buildSignedResponseB64(t)
		_, _, foreign := buildSignedResponseB64(t) // same entity IDs, different generated key
		requireRefused(t, pinned, acsURL, foreign, nil, "Could not verify certificate against trusted certs")
	})
	t.Run("signature value corrupted is refused", func(t *testing.T) {
		p, acsURL, b64 := buildSignedResponseB64(t)
		b64 = tamperResponse(t, b64, func(r *etree.Element) {
			sv := childByTag(childByTag(r, "Signature"), "SignatureValue")
			require.NotNil(t, sv)
			txt := strings.TrimSpace(sv.Text())
			flipped := "A"
			if strings.HasPrefix(txt, "A") {
				flipped = "B"
			}
			sv.SetText(flipped + txt[1:])
		})
		requireRefused(t, p, acsURL, b64, nil, "cannot validate signature on Response")
	})
}

// TestParseResponse_Property_RefusalNeverReflectsLibraryDetail: a refusal returns the fixed
// error and logs the library detail server-side only (the library's message names the
// expected issuer; that must reach the operator log and not the caller).
func TestParseResponse_Property_RefusalNeverReflectsLibraryDetail(t *testing.T) {
	p, acsURL, b64, key, cert := buildSignedResponseWithKey(t, nil)
	b64 = resignResponse(t, b64, key, cert, func(r *etree.Element) {
		childByTag(r, "Issuer").SetText("https://evil.example/entity")
	})
	logged := captureLog(t)
	_, err := p.ParseResponse(postRequest(t, acsURL, b64), nil)
	require.ErrorIs(t, err, errInvalidSAMLResponse)
	require.NotContains(t, err.Error(), "https://idp.example/entity", "library detail must not reach the caller")
	require.NotContains(t, err.Error(), "Issuer")
	require.Contains(t, logged(), "https://idp.example/entity", "the detail belongs in the operator log")
}

func strictShapeOf(t *testing.T, doc string) (string, error) {
	t.Helper()
	return strictAssertionShape(postRequest(t, "/acs", base64.StdEncoding.EncodeToString([]byte(doc))))
}

// TestStrictAssertionShape_DepthLimitIsExact: maxResponseDepth elements deep is the last
// accepted depth and one more is refused (the boundary the unbounded-stack guard rests on).
func TestStrictAssertionShape_DepthLimitIsExact(t *testing.T) {
	// Response(1) > Assertion(2) > Conditions(3) > nested <x> elements.
	doc := func(totalDepth int) string {
		nested := totalDepth - 3
		return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
			`<saml:Assertion><saml:Subject><saml:NameID>user@corp.example</saml:NameID></saml:Subject><saml:Conditions>` +
			strings.Repeat("<x>", nested) + strings.Repeat("</x>", nested) +
			`</saml:Conditions></saml:Assertion></samlp:Response>`
	}
	nameID, err := strictShapeOf(t, doc(maxResponseDepth))
	require.NoError(t, err, "exactly maxResponseDepth elements deep must be accepted")
	require.Equal(t, "user@corp.example", nameID)

	_, err = strictShapeOf(t, doc(maxResponseDepth+1))
	require.ErrorContains(t, err, "nests deeper")
}

// TestStrictAssertionShape_CountsEveryIdentifierBesideNameID: the refusal reports how many
// identifiers the Subject carried, one per BaseID/EncryptedID however spelled, so the
// count is a faithful record of what was refused.
func TestStrictAssertionShape_CountsEveryIdentifierBesideNameID(t *testing.T) {
	const head = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><saml:Subject><saml:NameID>user@corp.example</saml:NameID>`
	const tail = `</saml:Subject><saml:Conditions/></saml:Assertion></samlp:Response>`
	for name, tc := range map[string]struct{ extra, want string }{
		"one BaseID":                  {`<saml:BaseID/>`, "saml: Subject has 1 NameID and 2 identifier elements, want exactly 1 NameID"},
		"BaseID and EncryptedID":      {`<saml:BaseID/><saml:EncryptedID/>`, "saml: Subject has 1 NameID and 3 identifier elements, want exactly 1 NameID"},
		"foreign-namespace BaseID x2": {`<x:BaseID xmlns:x="urn:example:not-saml"/><x:BaseID xmlns:x="urn:example:not-saml"/>`, "saml: Subject has 1 NameID and 3 identifier elements, want exactly 1 NameID"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := strictShapeOf(t, head+tc.extra+tail)
			require.EqualError(t, err, tc.want)
		})
	}
}
