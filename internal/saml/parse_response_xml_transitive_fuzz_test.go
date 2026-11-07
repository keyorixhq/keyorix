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
)

// FuzzSAMLXMLTransitive fuzzes the XML stack two libraries beneath crewjam/saml's
// own signature wall: beevik/etree (crewjam's tree parser) and, beneath that,
// encoding/xml (etree's own decoder, and the second, independent decode crewjam runs
// via unmarshalElement to populate its Go structs). Ground-truth research before
// writing this harness (see docs/findings/*.md from 2026-09-18) established two
// things that reshape the oracles below versus the original brief:
//
//   - Billion-laughs is not reachable on this path at all: xrv.Validate and etree's
//     tree-builder both decode via xml.Decoder.RawToken(), which never resolves
//     entities (internal or external); the one place encoding/xml.Unmarshal DOES run
//     (unmarshalElement) receives content etree has already re-escaped, so there is no
//     entity-expansion oracle to assert here.
//   - There is no XML nesting-depth limit in this Go toolchain (confirmed: 1,000,000
//     levels decodes cleanly). CVE-2022-30633 made deep nesting SAFE (iterative
//     Decoder.Skip), not REJECTED. So bounded-work is a wall-clock/hang bound, not an
//     expected error.
//
// Oracles:
//
//   - (a) BOUNDED WORK: raw, unsigned bytes are wrapped in a minimal Response envelope
//     and fed straight to ParseResponse. crewjam unconditionally runs
//     unmarshalElement(responseEl, &response) (service_provider.go) before any
//     signature check -- and that walks etree's OWN NamespaceURI() (an ancestor-walk,
//     service_provider.go's elementToBytes) for every descendant. A flood of
//     uniquely-prefixed namespace declarations down a deep chain makes each such walk
//     progressively longer -- an O(n*depth) trap hiding behind what looks like O(n)
//     parsing. fuzzutil.Guard (matching every sibling harness in this package) is the
//     bounded-work assertion: this is the same idiom FuzzParseResponse/XSW/Content use
//     for "never hangs", applied here specifically against flood/nesting/attribute-
//     count inputs sized so legitimate linear work comfortably clears the timeout and
//     only genuine super-linear blowups trip it.
//   - (b)/(c) NAMESPACE-RESOLUTION DIFFERENTIAL + FAIL-CLOSED: every iteration builds a
//     FRESH, genuinely signed (real goxmldsig SignEnveloped, same TransformExcC14n +
//     exclusive-C14N pipeline crewjam's own MakeAssertionEl uses -- no forged/bypassed
//     signature) Assertion whose Subject contains one namespace-correct
//     <saml:NameID>legitSubject</saml:NameID> plus a fuzzer-controlled sibling
//     fragment spliced in immediately after it. If ParseResponse ACCEPTS the result,
//     the only sound invariant is: the identity it reports came from the
//     namespace-correct element, not from whatever the fuzzed fragment injected.
//   - (d) LIBRARY-LEVEL REGRESSION GUARD (GO-2026-6909): the same signed responses are
//     also handed straight to a bare crewjam/saml ServiceProvider, bypassing this
//     package's own pre-validation (strictAssertionShape), recover and audience hook.
//     A signed Assertion that omits Subject, Conditions or SubjectConfirmationData
//     must be rejected with an error, never panic; and an accepted assertion's
//     Subject.NameID must be one of the assertion-namespace NameID elements actually
//     present in the signed XML, never a foreign-namespace look-alike. crewjam/saml
//     v0.5.1 fails this oracle (nil-pointer panics, namespace-blind NameID binding);
//     v0.5.2 and later pass. The seeds include the regression triggers, so this
//     target is the canary if the dependency is ever downgraded or its binding
//     rules regress.
//
// The input is (fragment, shape): shape%4 selects the signed Assertion's form --
// 0 complete, 1 no Subject, 2 no Conditions, 3 bearer SubjectConfirmation without
// SubjectConfirmationData.
func FuzzSAMLXMLTransitive(f *testing.F) {
	const idpEntityID = "https://idp.example/entity"
	const spEntityID = "https://keyorixhq.internal/saml/corp/metadata"
	const acsURL = "https://keyorixhq.internal/auth/saml/corp/acs"
	const legitSubject = "legit-subject@corp.example"

	// --- signed IdP fixture: cert embedded in metadata == key used to sign below ---
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "xml-transitive-idp-signing"},
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

	// signAssertion mirrors crewjam's own MakeAssertionEl/Assertion.Element() pipeline
	// exactly (TransformExcC14n pre-pass, then exclusive-C14N signing with an empty
	// inclusive-prefix list) so a hand-built etree.Element -- with whatever namespace
	// layout the caller constructed -- verifies through the real production path,
	// with no forged or bypassed signature involved.
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

	// buildSignedResponse builds one fresh, validly signed Response whose Assertion's
	// Subject carries the namespace-correct legitSubject NameID followed immediately
	// by the caller's raw sibling fragment. Returns ("", false) if the fragment
	// doesn't yield well-formed XML in context, or the IdP-side pipeline otherwise
	// can't build a response for it -- a fixture limitation, not a target defect, so
	// the caller skips those inputs (matching FuzzParseResponseContent's signResponse
	// pattern).
	const samlNS = "urn:oasis:names:tc:SAML:2.0:assertion"
	// buildSignedResponse returns the base64 SAMLResponse plus the set of NameID
	// values that sit in the assertion namespace directly under a Subject of the
	// (pre-signing) assertion -- the only identifiers an accepted response may report.
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
		case 1: // no Subject; the fragment lands at assertion level
			subject = siblingFragment
		case 2: // no Conditions
			conditions = ""
		}
		assertionXML := fmt.Sprintf(`<saml:Assertion xmlns:saml="%s" ID="_xt1" IssueInstant="%s" Version="2.0"><saml:Issuer>%s</saml:Issuer>%s%s</saml:Assertion>`,
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

	// wrapMinimalResponse embeds a raw (possibly malformed, possibly huge) fragment
	// into a minimal, UNSIGNED Response envelope. crewjam runs
	// unmarshalElement(responseEl, &response) -- which walks etree's ancestor-based
	// NamespaceURI() for every descendant via elementToBytes -- unconditionally,
	// before any signature check, so this reaches the bounded-work surface with zero
	// signing needed.
	wrapMinimalResponse := func(fragment string) string {
		return fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_xtr1" Version="2.0" IssueInstant="%s"><saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>%s</samlp:Response>`,
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

	// --- Seeds ---
	// Bounded-work floods (raw, unsigned -- oracle (a)):
	f.Add([]byte(strings.Repeat("<a>", 10000)+strings.Repeat("</a>", 10000)), uint8(0)) // 10k nested elements
	{
		var attrs strings.Builder
		for i := range 50000 {
			fmt.Fprintf(&attrs, ` a%d="v"`, i)
		}
		f.Add([]byte("<r"+attrs.String()+"/>"), uint8(0)) // 50k attributes
	}
	{
		// Deep chain, each level declaring a UNIQUE, unused namespace prefix -- the
		// specific shape that makes etree's ancestor-walking NamespaceURI() (called
		// once per descendant inside elementToBytes) progressively longer per level:
		// O(depth) per call, O(n*depth) total across all n descendants.
		var b strings.Builder
		for i := range 5000 {
			fmt.Fprintf(&b, `<e%d xmlns:p%d="urn:ns:%d">`, i, i, i)
		}
		b.WriteString("<leaf/>")
		for i := 4999; i >= 0; i-- {
			fmt.Fprintf(&b, `</e%d>`, i)
		}
		f.Add([]byte(b.String()), uint8(0))
	}
	f.Add([]byte(`<!DOCTYPE r [<!ENTITY a "1"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]><r>&b;</r>`), uint8(0)) // DOCTYPE w/ internal entities

	// Namespace-resolution seeds (spliced as the Subject sibling fragment -- oracle
	// (b)/(c)). These are deliberately SAFE shapes (no confirmed trigger), so
	// `go test -run FuzzSAMLXMLTransitive` stays green; see the file doc comment.
	f.Add([]byte(``), uint8(0))                                                                                                                                               // baseline: no sibling at all
	f.Add([]byte(`<saml:AttributeStatement><saml:Attribute Name="dept"><saml:AttributeValue>eng</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`), uint8(0)) // unrelated, correctly-namespaced sibling
	f.Add([]byte(`<x:Marker xmlns:x="urn:oasis:names:tc:SAML:2.0:assertion">shadow-correct-ns</x:Marker>`), uint8(0))                                                         // default-namespace-shadowing style, but CORRECTLY re-bound to the real SAML namespace
	f.Add([]byte(`<!--comment-only sibling-->`), uint8(0))

	// GO-2026-6909 regression triggers (crewjam/saml <= v0.5.1 fails these through the
	// bare library; v0.5.2+ rejects/ignores them): a foreign-namespace NameID after the
	// legitimate one (last match won in v0.5.1), and signed assertions with no Subject,
	// no Conditions, or a bearer SubjectConfirmation without SubjectConfirmationData.
	f.Add([]byte(`<evil:NameID xmlns:evil="urn:evil">attacker@evil.example</evil:NameID>`), uint8(0))
	f.Add([]byte(``), uint8(1))
	f.Add([]byte(``), uint8(2))
	f.Add([]byte(``), uint8(3))

	// rawSP is a bare crewjam/saml ServiceProvider for oracle (d): same IdP trust and
	// entity IDs as the wrapped provider, but WITHOUT this package's pre-validation,
	// recover, or audience-restriction hook override, so it exercises the library's
	// own validateAssertion and struct binding.
	acsParsed, err := url.Parse(acsURL)
	if err != nil {
		f.Fatal(err)
	}
	rawSP := *p.sp
	rawSP.ValidateAudienceRestriction = nil

	// rawParse runs the bare library on a base64 SAMLResponse and converts a panic into
	// a returned value (a panic here is itself the finding for oracle (d)).
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

	// Vacuity guard: the complete, unmutated assertion must be accepted by both the
	// wrapped provider and the bare library, otherwise every oracle below would pass
	// trivially because the fixture itself is being rejected.
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

	f.Fuzz(func(t *testing.T, fragment []byte, shape uint8) {
		// --- Oracle (a): bounded work on raw, unsigned bytes ---
		if req, ok := post(base64.StdEncoding.EncodeToString([]byte(wrapMinimalResponse(string(fragment))))); ok {
			fuzzutil.Guard(t.Fatalf, "saml.ParseResponse(xml-transitive flood)", func() {
				_, _ = p.ParseResponse(req, nil)
			})
		}

		// The signed path (b)-(d) signs the fragment on the IdP side and then runs the
		// full xrv + etree + exc-C14N + signature verification twice (wrapped provider
		// and bare library) under fuzzutil.Guard's 3s budget. A flood-sized fragment
		// (the 50k-attribute and 5k-deep seeds) blows that budget on a slow or
		// single-CPU runner, which is a flake, not an amplification finding. Oracle (a)
		// above already covers bounded work on such inputs, and anything this large is
		// refused by strictAssertionShape's element/depth caps anyway.
		const maxSignedFragmentBytes = 16 << 10
		if len(fragment) > maxSignedFragmentBytes {
			return
		}

		// --- Oracle (b)/(c)/(d): namespace-resolution differential + fail-closed ---
		samlResponse, trusted, ok := buildSignedResponse(string(fragment), shape)
		if !ok {
			return // fragment isn't well-formed XML in this context -- not useful here
		}
		req, ok := post(samlResponse)
		if !ok {
			return
		}

		var info *AssertionInfo
		var perr error
		fuzzutil.Guard(t.Fatalf, "saml.ParseResponse(xml-transitive nsdiff)", func() {
			info, perr = p.ParseResponse(req, nil)
		})
		if perr == nil {
			if info == nil {
				t.Fatalf("ParseResponse returned nil error but nil AssertionInfo (fragment=%q)", fragment)
			}
			// Fail-closed: an ACCEPTED response's identity must come from the
			// namespace-correct NameID, never from whatever the sibling fragment
			// injected. Restricted to a non-empty divergent Subject so a fragment that
			// merely displaces/blanks the identity (e.g. a second, empty <Subject>
			// silently winning per encoding/xml's last-match-wins rule) isn't
			// misreported as namespace confusion -- that's a different, non-security
			// degraded-parse outcome this oracle doesn't target.
			if info.Subject != "" && !trusted[info.Subject] {
				t.Fatalf("SAML NAMESPACE CONFUSION: accepted response reported Subject %q, but only an assertion-namespace NameID %v may be trusted (shape=%d fragment=%q)", info.Subject, trusted, shape%4, fragment)
			}
		}

		// --- Oracle (d): the bare library must not panic and must not authenticate a
		// foreign-namespace identifier (crewjam/saml <= v0.5.1 does both). ---
		var nid *string
		var accepted bool
		var pv any
		fuzzutil.Guard(t.Fatalf, "crewjam/saml.ParseXMLResponse(xml-transitive raw)", func() {
			nid, accepted, pv = rawParse(samlResponse)
		})
		if pv != nil {
			t.Fatalf("crewjam/saml panicked on a validly signed assertion (shape=%d fragment=%q): %v", shape%4, fragment, pv)
		}
		if accepted && nid != nil && !trusted[*nid] {
			t.Fatalf("crewjam/saml authenticated Subject.NameID %q that is not an assertion-namespace NameID %v (shape=%d fragment=%q)", *nid, trusted, shape%4, fragment)
		}
		// A signed assertion missing a required element must be rejected. The fragment
		// is excluded when it could itself supply the element.
		if accepted && shape%4 != 0 {
			fs := string(fragment)
			supplies := strings.Contains(fs, "Subject") || strings.Contains(fs, "Conditions") || strings.Contains(fs, "SubjectConfirmation")
			if !supplies {
				t.Fatalf("crewjam/saml accepted a signed assertion with a required element missing (shape=%d)", shape%4)
			}
		}
	})
}
