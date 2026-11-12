package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	csaml "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/grammar"
)

// FuzzSAMLXMLGrammar is the GRAMMAR-DRIVEN counterpart to FuzzSAMLXMLTransitive.
// It keeps that target's fixture and ALL FOUR of its oracles unchanged — the only
// difference is how the Subject-sibling fragment is produced: instead of mutating
// raw fragment bytes (which stall the instant the bytes stop being well-formed XML
// in context — the brief's "first tag check" stall for XML), the fuzzer's bytes
// are decoded by grammar.DecodeSAMLFragment into a STRUCTURAL SAML shape
// (correctly-namespaced NameID, foreign-namespace look-alike, prefix-rebound
// NameID, deep-nesting / wide-attribute flood, comment/CDATA sibling) plus the
// shape selector, and a well-formed fragment realising that shape is built. The
// engine therefore mutates structural choices, so every iteration yields a
// fragment that is well-formed XML in context and reaches the signature / namespace
// surface, rather than being discarded as un-parseable.
//
// This target and FuzzSAMLXMLTransitive are the XML half of the pre-registered
// grammar-vs-byte measurement (see /mnt/data/wave4/out/wg-REPORT.md Phase 2).
//
// Oracles (identical to FuzzSAMLXMLTransitive; see that file's doc comment for the
// full derivation):
//   - (a) BOUNDED WORK on a raw, unsigned fragment wrapped in a minimal Response
//     envelope and fed to ParseResponse (fuzzutil.Guard).
//   - (b)/(c) NAMESPACE-RESOLUTION FAIL-CLOSED: an ACCEPTED signed response's
//     identity must come from a namespace-correct NameID, never the injected
//     sibling.
//   - (d) BARE-LIBRARY REGRESSION GUARD (GO-2026-6909): the bare crewjam/saml
//     ServiceProvider must not panic on, nor authenticate a foreign-namespace
//     NameID from, a validly signed assertion.
//
// What this oracle does NOT verify (same exclusions as the byte-level target):
//   - It does NOT assert that any fragment-bearing response is ACCEPTED — a
//     mutated assertion SHOULD be rejected far more often than not, so only the
//     accept-implies-namespace-correct direction is checked.
//   - It does NOT re-derive crewjam/saml's signature cryptography; it trusts the
//     real SignEnveloped pipeline to produce a genuine signature and only probes
//     the parse / namespace-resolution behaviour above it.
//   - Billion-laughs / entity expansion is NOT an oracle here (the path never
//     resolves entities — established in the byte-level target's research notes);
//     a DOCTYPE/entity fragment only exercises bounded work.
//   - It does NOT verify Keyorix's own pre-validation beyond what ParseResponse
//     exposes; strictAssertionShape caps are exercised, not asserted.
func FuzzSAMLXMLGrammar(f *testing.F) {
	const idpEntityID = "https://idp.example/entity"
	const spEntityID = "https://keyorixhq.internal/saml/corp/metadata"
	const acsURL = "https://keyorixhq.internal/auth/saml/corp/acs"
	const legitSubject = "legit-subject@corp.example"
	const samlNS = grammar.SAMLAssertionNS

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "xml-grammar-idp-signing"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		f.Fatal(err)
	}
	idpCert, err := x509.ParseCertificate(der)
	if err != nil {
		f.Fatal(err)
	}
	idpMD := []byte(fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>%s</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, idpEntityID, base64.StdEncoding.EncodeToString(der)))

	p, err := NewProvider(Config{
		Name:              "corp",
		IDPMetadataXML:    idpMD,
		SPEntityID:        spEntityID,
		ACSURL:            acsURL,
		AllowIDPInitiated: true,
		EmailAttr:         "mail",
		NameAttr:          "cn",
		GroupsAttr:        "eduPersonAffiliation",
	})
	if err != nil {
		f.Fatal(err)
	}

	idpMetadataURL, err := url.Parse(idpEntityID)
	if err != nil {
		f.Fatal(err)
	}
	idp := &csaml.IdentityProvider{Key: priv, Certificate: idpCert, MetadataURL: *idpMetadataURL}
	spMetadata := p.sp.Metadata()

	var acsEndpoint *csaml.IndexedEndpoint
	var spssoDescriptor *csaml.SPSSODescriptor
	for i := range spMetadata.SPSSODescriptors {
		d := spMetadata.SPSSODescriptors[i]
		for j := range d.AssertionConsumerServices {
			ep := d.AssertionConsumerServices[j]
			if ep.Binding == csaml.HTTPPostBinding {
				acsEndpoint = &ep
				spssoDescriptor = &d
				break
			}
		}
		if acsEndpoint != nil {
			break
		}
	}
	if acsEndpoint == nil {
		f.Fatal("SP metadata advertises no HTTP-POST ACS endpoint")
	}

	signAssertion := func(el *etree.Element) (*etree.Element, error) {
		if err := etreeutils.TransformExcC14n(el, "", false); err != nil {
			return nil, err
		}
		keyStore := dsig.TLSCertKeyStore(tls.Certificate{
			Certificate: [][]byte{idpCert.Raw},
			PrivateKey:  priv,
			Leaf:        idpCert,
		})
		signingCtx := dsig.NewDefaultSigningContext(keyStore)
		if err := signingCtx.SetSignatureMethod(dsig.RSASHA1SignatureMethod); err != nil {
			return nil, err
		}
		signingCtx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		return signingCtx.SignEnveloped(el)
	}

	buildSignedResponse := func(siblingFragment string, shape uint8) (string, map[string]bool, bool) {
		now := time.Now().UTC()
		scData := fmt.Sprintf(`<saml:SubjectConfirmationData Recipient="%s" NotOnOrAfter="%s"/>`, acsURL, now.Add(time.Hour).Format(time.RFC3339))
		if shape%4 == 3 {
			scData = ""
		}
		subject := fmt.Sprintf(`<saml:Subject><saml:NameID>%s</saml:NameID>%s<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">%s</saml:SubjectConfirmation></saml:Subject>`,
			legitSubject, siblingFragment, scData)
		conditions := fmt.Sprintf(`<saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>`, spEntityID)
		switch shape % 4 {
		case 1:
			subject = siblingFragment
		case 2:
			conditions = ""
		}
		assertionXML := fmt.Sprintf(`<saml:Assertion xmlns:saml="%s" ID="_xg1" IssueInstant="%s" Version="2.0"><saml:Issuer>%s</saml:Issuer>%s%s</saml:Assertion>`,
			samlNS, now.Format(time.RFC3339), idpEntityID, subject, conditions)

		doc := etree.NewDocument()
		if err := doc.ReadFromString(assertionXML); err != nil {
			return "", nil, false
		}
		trusted := map[string]bool{}
		for _, s := range doc.Root().ChildElements() {
			if s.Tag != "Subject" || s.NamespaceURI() != samlNS {
				continue
			}
			for _, n := range s.ChildElements() {
				if n.Tag == "NameID" && n.NamespaceURI() == samlNS {
					trusted[n.Text()] = true
				}
			}
		}
		signedAssertionEl, err := signAssertion(doc.Root())
		if err != nil {
			return "", nil, false
		}

		idpReq := &csaml.IdpAuthnRequest{
			IDP:                     idp,
			HTTPRequest:             httptest.NewRequest(http.MethodGet, "https://idp.example/sso", nil),
			RelayState:              "return-here",
			ServiceProviderMetadata: spMetadata,
			SPSSODescriptor:         spssoDescriptor,
			ACSEndpoint:             acsEndpoint,
			Now:                     time.Now(),
			AssertionEl:             signedAssertionEl,
		}
		form, err := idpReq.PostBinding()
		if err != nil {
			return "", nil, false
		}
		return form.SAMLResponse, trusted, true
	}

	wrapMinimalResponse := func(fragment string) string {
		return fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_xgr1" Version="2.0" IssueInstant="%s"><saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>%s</samlp:Response>`,
			time.Now().UTC().Format(time.RFC3339), idpEntityID, fragment)
	}

	post := func(samlResponseB64 string) (*http.Request, bool) {
		body := url.Values{"SAMLResponse": {samlResponseB64}}.Encode()
		req := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := req.ParseForm(); err != nil {
			return nil, false
		}
		return req, true
	}

	acsParsed, err := url.Parse(acsURL)
	if err != nil {
		f.Fatal(err)
	}
	rawSP := *p.sp
	rawSP.ValidateAudienceRestriction = nil

	rawParse := func(samlResponseB64 string) (nameID *string, accepted bool, panicked any) {
		raw, derr := base64.StdEncoding.DecodeString(samlResponseB64)
		if derr != nil {
			return nil, false, nil
		}
		defer func() {
			if r := recover(); r != nil {
				nameID, accepted, panicked = nil, false, r
			}
		}()
		a, perr := rawSP.ParseXMLResponse(raw, nil, *acsParsed)
		if perr != nil {
			return nil, false, nil
		}
		if a.Subject != nil && a.Subject.NameID != nil {
			v := a.Subject.NameID.Value
			nameID = &v
		}
		return nameID, true, nil
	}

	// Vacuity guard: the control response (no sibling) must be accepted by both
	// the wrapped provider and the bare library.
	{
		resp, _, ok := buildSignedResponse("", 0)
		if !ok {
			f.Fatal("fixture: cannot build the control signed response")
		}
		req, ok := post(resp)
		if !ok {
			f.Fatal("fixture: cannot post the control signed response")
		}
		info, cerr := p.ParseResponse(req, nil)
		if cerr != nil || info == nil || info.Subject != legitSubject {
			f.Fatalf("fixture: control response not accepted by the wrapped provider (info=%v err=%v)", info, cerr)
		}
		nid, accepted, pv := rawParse(resp)
		if pv != nil || !accepted || nid == nil || *nid != legitSubject {
			f.Fatalf("fixture: control response not accepted by the bare library (accepted=%v nameID=%v panic=%v)", accepted, nid, pv)
		}
	}

	// Seeds: grammar control bytes decoded by grammar.DecodeSAMLFragment.
	f.Add([]byte{0, 0})       // shape 0, empty fragment
	f.Add([]byte{0, 1, 5, 5}) // correctly-namespaced sibling
	f.Add([]byte{0, 2, 7, 9}) // foreign-namespace NameID look-alike
	f.Add([]byte{0, 3, 3, 4}) // prefix-rebound NameID
	f.Add([]byte{0, 4, 1, 0x08, 0x00}) // bounded-work flood (deep XML chain)
	f.Add([]byte{1, 2, 2})    // shape 1 (no Subject), foreign NameID
	f.Add([]byte{2, 0})       // shape 2 (no Conditions)
	f.Add([]byte{3, 0})       // shape 3 (no SubjectConfirmationData)

	f.Fuzz(func(t *testing.T, data []byte) {
		fragment, shape := grammar.DecodeSAMLFragment(data)

		// --- Oracle (a): bounded work on raw, unsigned bytes ---
		if req, ok := post(base64.StdEncoding.EncodeToString([]byte(wrapMinimalResponse(fragment)))); ok {
			fuzzutil.Guard(t.Fatalf, "saml.ParseResponse(xml-grammar flood)", func() {
				_, _ = p.ParseResponse(req, nil)
			})
		}

		const maxSignedFragmentBytes = 16 << 10
		if len(fragment) > maxSignedFragmentBytes {
			return
		}

		samlResponse, trusted, ok := buildSignedResponse(fragment, shape)
		if !ok {
			return
		}
		req, ok := post(samlResponse)
		if !ok {
			return
		}

		var info *AssertionInfo
		var perr error
		fuzzutil.Guard(t.Fatalf, "saml.ParseResponse(xml-grammar nsdiff)", func() {
			info, perr = p.ParseResponse(req, nil)
		})
		if perr == nil {
			if info == nil {
				t.Fatalf("ParseResponse returned nil error but nil AssertionInfo (fragment=%q)", fragment)
			}
			if info.Subject != "" && !trusted[info.Subject] {
				t.Fatalf("SAML NAMESPACE CONFUSION: accepted response reported Subject %q, but only an assertion-namespace NameID %v may be trusted (shape=%d fragment=%q)", info.Subject, trusted, shape%4, fragment)
			}
		}

		var nid *string
		var accepted bool
		var pv any
		fuzzutil.Guard(t.Fatalf, "crewjam/saml.ParseXMLResponse(xml-grammar raw)", func() {
			nid, accepted, pv = rawParse(samlResponse)
		})
		if pv != nil {
			t.Fatalf("crewjam/saml panicked on a validly signed assertion (shape=%d fragment=%q): %v", shape%4, fragment, pv)
		}
		if accepted && nid != nil && !trusted[*nid] {
			t.Fatalf("crewjam/saml authenticated Subject.NameID %q that is not an assertion-namespace NameID %v (shape=%d fragment=%q)", *nid, trusted, shape%4, fragment)
		}
		if accepted && shape%4 != 0 {
			supplies := strings.Contains(fragment, "Subject") || strings.Contains(fragment, "Conditions") || strings.Contains(fragment, "SubjectConfirmation")
			if !supplies {
				t.Fatalf("crewjam/saml accepted a signed assertion with a required element missing (shape=%d)", shape%4)
			}
		}
	})
}
