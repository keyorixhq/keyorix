package saml

// FuzzSAMLFullIdentity — structure-aware XSW / XML-structure differential whose oracle
// checks the FULL derived identity, not just the Subject (task SXS1).
//
// WHY THIS EXISTS (verified gap, not a duplicate). The package already has four
// structure-aware SAML oracles driving (*Provider).ParseResponse — FuzzParseResponseXSW,
// and the S1/S2/S3 differential oracles (response_differential_*). EVERY one of them
// asserts only on `info.Subject`. None checks `info.Email`, `info.Name`, or `info.Groups`
// provenance. But the real ACS handler (internal/core.(*KeyorixCore).CompleteSAML,
// internal/core/sso.go:401) consumes the WHOLE struct this code returns:
//
//   - info.Subject / info.Email -> account resolution (sso.go:431, resolveSSOUser)
//   - info.Groups -> GROUP AND ROLE reconciliation (sso.go:504-516, reconcileSSOGroups /
//     reconcileSSORoles via GroupRoleMap) — i.e. an attacker-chosen `groups` set directly
//     drives which Keyorix roles (up to admin) the logging-in user is granted.
//
// So a structural attack that keeps the genuinely-signed NameID but makes ParseResponse
// read a DIFFERENT groups/email/name set is a privilege-escalation XSW the four existing
// Subject-only oracles pass clean. The task names exactly this: "accept ONLY when the
// identity it derives (NameID, groups, email) equals the one in the signed data".
//
// ORACLE. The fixture is ONE genuinely-signed response carrying one identity with a
// DISTINCT value in every field (so each is individually targetable and unambiguous).
// On ANY acceptance, the full derived identity must equal that signed identity exactly:
// Subject, Email, Name, and Groups (compared as a set). The only legitimate success is the
// signed identity, so there are no false positives — a mutation crewjam/strictShape rejects
// errors out (fine), one it ignores still yields the signed identity (fine), and one that
// verifies while changing ANY field is the finding.
//
// MUTATIONS. Ops 0..14 delegate to the shared diffMutate engine (sibling/wrapped/duplicated
// assertion, namespace tricks, dup/missing Subject&Conditions, comment-in-NameID, wrong
// audience, expired window, xmlenc wrapper, raw blob, epilogue). Ops >=15 are
// ATTRIBUTE-TARGETED and are the new surface this harness adds: comment-truncation inside
// the signed email / group / name AttributeValue text (the C14N comment class applied to
// attribute values, not just the NameID), and injection of an unsigned AttributeStatement
// granting an elevated group — the groups-escalation shapes the Subject-only oracles can't see.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	csaml "github.com/crewjam/saml"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// Distinct signed identity: every field is a different string so a mutation that swaps one
// field's source is unambiguous in the failure message and cannot accidentally match another.
const (
	// Fixture entity IDs.
	fidIDPEntityID = "https://fid-idp.example/entity"
	fidSPEntityID  = "https://keyorix.internal/saml/fid/metadata"

	fidSubject = "subject-user@corp.example"
	fidEmail   = "mail-addr@corp.example"
	fidName    = "Full Identity User"
	fidGroup1  = "signed-admins"
	fidGroup2  = "signed-devs"
	// The elevated group an injected/unsigned AttributeStatement tries to smuggle in.
	fidEvilGroup = "superadmin-injected"
)

// fidMutate applies diffMutate for ops 0..14 and attribute-targeted mutations for ops >=15.
func fidMutate(signed []byte, op uint8, off uint16, blob []byte) []byte {
	if op%fidNumOps == 4 { // NameID splice on THIS fixture's subject (diffMutate's op 4 targets another fixture's)
		return spliceCommentInto(signed, fidSubject, blob)
	}
	if op%fidNumOps < diffNumOps {
		return diffMutate(signed, op%fidNumOps, off, blob)
	}
	switch op % fidNumOps {
	case 15: // comment-splice inside the signed EMAIL value text
		return spliceCommentInto(signed, fidEmail, blob)
	case 16: // comment-splice inside a signed GROUP value text
		return spliceCommentInto(signed, fidGroup1, blob)
	case 17: // comment-splice inside the signed NAME value text
		return spliceCommentInto(signed, fidName, blob)
	case 18: // inject an unsigned AttributeStatement (eduPersonAffiliation=evil) INTO the signed assertion
		return injectAttributeStatement(signed, true)
	case 19: // append the evil AttributeStatement as a sibling of the signed one (not nested in it)
		return injectAttributeStatement(signed, false)
	case 20: // duplicate the signed assertion's own groups AttributeValue, then rewrite the copy to the evil group
		return dupGroupValueAsEvil(signed)
	case 21: // matched evil assertion as the FIRST child of Response (sibling XSW)
		return injectFidEvilAssertion(signed, fidEvilFirst)
	case 22: // matched evil assertion appended AFTER the signed assertion
		return injectFidEvilAssertion(signed, fidEvilLast)
	case 23: // matched evil assertion wrapping the signed one in its Advice
		return injectFidEvilAssertion(signed, fidEvilWrap)
	}
	return signed
}

// fidNumOps = diffNumOps structural ops (0..14) + 9 attribute-targeted ops (15..23).
const fidNumOps = diffNumOps + 9

// fidForgedAssertion returns an UNSIGNED copy of the signed assertion that grants fidEvilGroup
// on top of the signed groups. It is built from the signed fixture at runtime rather than
// from a constant, so it inherits everything crewjam's validateAssertion checks before it
// reads any attribute: the fresh IssueInstant (MaxIssueDelay), the bearer SubjectConfirmation
// (Recipient, NotOnOrAfter), the Conditions window and audience, the issuer, the NameID, and
// the email and name attributes. Only the signature is dropped, the ID changes and one group
// is added. A forged assertion with a hard-coded 2024 IssueInstant and no bearer confirmation
// is refused as expired before identity is read, so the groups check would stay unreachable
// (TestFullIdentity_EvilAssertionPassesLibraryValidation pins the reachable shape).
// Returns nil when the signed assertion has no group value to extend.
func fidForgedAssertion(signedAssertion *etree.Element) *etree.Element {
	evil := signedAssertion.Copy()
	for _, sig := range evil.FindElements("./Signature") {
		evil.RemoveChild(sig)
	}
	evil.CreateAttr("ID", "_fidevil")
	for _, av := range evil.FindElements(".//AttributeValue") {
		if av.Text() == fidGroup1 {
			ev := av.Copy()
			ev.SetText(fidEvilGroup)
			av.Parent().AddChild(ev)
			return evil
		}
	}
	return nil
}

type fidEvilPlacement int

const (
	fidEvilFirst fidEvilPlacement = iota // first child of Response
	fidEvilLast                          // last child of Response
	fidEvilWrap                          // outer assertion; the signed one moves into its Advice
)

// injectFidEvilAssertion places the forged assertion relative to the signed one. A parse
// failure or missing target returns the input unchanged (TestFullIdentity_AllOpsChangeTheDocument
// pins that this does not happen on the fixture). Ops 21 and 22 are refused first by
// strictAssertionShape ("exactly one Assertion child of root"), before crewjam runs; the
// ops exist to cover a regression of that layer. Op 23 keeps one Assertion child and is
// refused by the library's own checks.
func injectFidEvilAssertion(signed []byte, where fidEvilPlacement) []byte {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(signed); err != nil || doc.Root() == nil {
		return signed
	}
	root := doc.Root()
	signedAssertion := root.FindElement(".//Assertion")
	if signedAssertion == nil {
		return signed
	}
	evil := fidForgedAssertion(signedAssertion)
	if evil == nil {
		return signed
	}
	switch where {
	case fidEvilFirst:
		root.InsertChildAt(0, evil)
	case fidEvilLast:
		root.AddChild(evil)
	case fidEvilWrap:
		adv := etree.NewElement("Advice")
		adv.Space = signedAssertion.Space
		if cond := evil.FindElement("./Conditions"); cond != nil {
			evil.InsertChildAt(cond.Index()+1, adv) // schema order: Conditions, Advice, statements
		} else {
			evil.AddChild(adv)
		}
		adv.AddChild(signedAssertion.Copy())
		root.RemoveChild(signedAssertion)
		root.AddChild(evil)
	}
	out, err := doc.WriteToBytes()
	if err != nil {
		return signed
	}
	return out
}

// spliceCommentInto inserts an XML comment into the middle of the first occurrence of
// target's text. Exclusive-C14N-without-comments strips it so an enveloped signature over
// that subtree stays valid, but a DOM reader that splits text on comment boundaries could
// read a different value — the attribute-value comment-truncation class.
func spliceCommentInto(signed []byte, target string, blob []byte) []byte {
	s := string(signed)
	i := strings.Index(s, target)
	if i < 0 {
		return signed
	}
	k := len(target) / 2
	comment := "<!--" + sanitizeComment(string(blob)) + "-->"
	return []byte(s[:i+k] + comment + s[i+k:])
}

// evilAttributeStatement is an unsigned AttributeStatement granting fidEvilGroup under the
// eduPersonAffiliation attribute the provider maps to Groups.
const evilAttributeStatement = `<saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
	`<saml:Attribute FriendlyName="eduPersonAffiliation" Name="eduPersonAffiliation">` +
	`<saml:AttributeValue>` + fidEvilGroup + `</saml:AttributeValue>` +
	`</saml:Attribute></saml:AttributeStatement>`

// injectAttributeStatement adds the evil AttributeStatement either inside the signed
// Assertion (intoSigned) or as a sibling AttributeStatement elsewhere under root. Both
// tamper with the signed subtree or add unsigned data; a correct SP must ignore/reject.
func injectAttributeStatement(signed []byte, intoSigned bool) []byte {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(signed); err != nil || doc.Root() == nil {
		return signed
	}
	root := doc.Root()
	a := root.FindElement(".//Assertion")
	if a == nil {
		return signed
	}
	frag := parseFragment(evilAttributeStatement)
	if intoSigned {
		a.AddChild(frag)
	} else {
		root.AddChild(frag)
	}
	out, err := doc.WriteToBytes()
	if err != nil {
		return signed
	}
	return out
}

// dupGroupValueAsEvil finds a signed group AttributeValue and rewrites a duplicated copy of
// it to fidEvilGroup, leaving the original in place — a value-injection shape.
func dupGroupValueAsEvil(signed []byte) []byte {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(signed); err != nil || doc.Root() == nil {
		return signed
	}
	for _, av := range doc.Root().FindElements(".//AttributeValue") {
		if av.Text() == fidGroup1 {
			ev := av.Copy()
			ev.SetText(fidEvilGroup)
			if p := av.Parent(); p != nil {
				p.AddChild(ev)
			}
			break
		}
	}
	out, err := doc.WriteToBytes()
	if err != nil {
		return signed
	}
	return out
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// fidFixture is a real signed SAML response asserting the full distinct identity, plus the
// provider that verifies it. Shared by FuzzSAMLFullIdentity and TestFullIdentity_*.
type fidFixture struct {
	p         *Provider
	signedXML []byte
	acsURL    string
	// IdP signing key and certificate: TestFullIdentity_EvilAssertionPassesLibraryValidation
	// re-signs the forged assertion with them.
	priv *rsa.PrivateKey
	cert *x509.Certificate
}

func newFIDFixture(tb testing.TB) *fidFixture {
	tb.Helper()
	const (
		idpEntityID = fidIDPEntityID
		spEntityID  = fidSPEntityID
		acsURL      = "https://keyorix.internal/auth/saml/fid/acs"
	)

	// Signed IdP fixture: cert embedded in metadata == key used to sign.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "fid-idp-signing"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		tb.Fatal(err)
	}
	idpCert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	idpMD := []byte(fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>%s</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://fid-idp.example/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, idpEntityID, base64.StdEncoding.EncodeToString(der)))

	// Attribute names match crewjam DefaultAssertionMaker's FriendlyNames so the signed
	// email/name/groups are actually extracted into AssertionInfo.
	p, err := NewProvider(Config{
		Name: "fid", IDPMetadataXML: idpMD, SPEntityID: spEntityID, ACSURL: acsURL,
		AllowIDPInitiated: true, EmailAttr: "mail", NameAttr: "cn", GroupsAttr: "eduPersonAffiliation",
	})
	if err != nil {
		tb.Fatal(err)
	}

	idpMetadataURL, err := url.Parse(idpEntityID)
	if err != nil {
		tb.Fatal(err)
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
		tb.Fatal("SP metadata advertises no HTTP-POST ACS endpoint")
	}
	idpReq := &csaml.IdpAuthnRequest{
		IDP: idp, HTTPRequest: httptest.NewRequest(http.MethodGet, "https://fid-idp.example/sso", nil),
		RelayState: "return-here", ServiceProviderMetadata: spMetadata,
		SPSSODescriptor: spssoDescriptor, ACSEndpoint: acsEndpoint, Now: time.Now(),
	}
	session := &csaml.Session{
		ID: "sess-fid", CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour),
		NameID: fidSubject, UserEmail: fidEmail, UserCommonName: fidName,
		Groups: []string{fidGroup1, fidGroup2},
	}
	if err := (csaml.DefaultAssertionMaker{}).MakeAssertion(idpReq, session); err != nil {
		tb.Fatal(err)
	}
	form, err := idpReq.PostBinding()
	if err != nil {
		tb.Fatal(err)
	}
	signedXML, err := base64.StdEncoding.DecodeString(form.SAMLResponse)
	if err != nil {
		tb.Fatal(err)
	}
	return &fidFixture{p: p, signedXML: signedXML, acsURL: acsURL, priv: priv, cert: idpCert}
}

// fidWantGroups is the signed groups set, sorted, that every acceptance must match.
func fidWantGroups() []string { return sortedCopy([]string{fidGroup1, fidGroup2}) }

// checkFullIdentity is the oracle: given a parse result (info, perr), it returns a non-empty
// failure string iff the result is an acceptance whose derived identity deviates from the
// signed fixture identity in ANY field. Returns "" for a rejection (safe) or an exact match.
// Factored out so TestFullIdentity_OracleRejectsForgedResults exercises the SAME comparison
// the fuzzer uses.
func checkFullIdentity(info *AssertionInfo, perr error, op uint8, off uint16) string {
	if perr != nil {
		return "" // correctly rejected — the safe outcome for a tampered response
	}
	if info == nil {
		return fmt.Sprintf("ParseResponse returned nil error but nil AssertionInfo (op=%d off=%d)", op, off)
	}
	if info.Subject != fidSubject {
		return fmt.Sprintf("SAML XSW BYPASS (subject): verified subject %q != signed %q (op=%d off=%d)", info.Subject, fidSubject, op, off)
	}
	if info.Email != fidEmail {
		return fmt.Sprintf("SAML IDENTITY-INJECTION BYPASS (email): verified email %q != signed %q, subject still %q (op=%d off=%d)", info.Email, fidEmail, info.Subject, op, off)
	}
	if info.Name != fidName {
		return fmt.Sprintf("SAML IDENTITY-INJECTION BYPASS (name): verified name %q != signed %q (op=%d off=%d)", info.Name, fidName, op, off)
	}
	if got, want := sortedCopy(info.Groups), fidWantGroups(); strings.Join(got, ",") != strings.Join(want, ",") {
		return fmt.Sprintf("SAML PRIVILEGE-ESCALATION XSW (groups): verified groups %v != signed %v, subject still %q (op=%d off=%d)", got, want, info.Subject, op, off)
	}
	return ""
}

func FuzzSAMLFullIdentity(f *testing.F) {
	fx := newFIDFixture(f)

	// Sanity: the pristine fixture must parse to exactly the signed identity in every field.
	// If this fails the harness is miswired (fixture attr names vs maker), not a finding.
	// checkFullIdentity treats a parse error as a safe rejection, so a fixture that stops
	// verifying would reject every op and keep the fuzzer green: fail on perr explicitly.
	info, op, off, perr := mustParse(fx)
	if perr != nil {
		f.Fatalf("harness: pristine signed fixture was rejected by ParseResponse: %v", perr)
	}
	if msg := checkFullIdentity(info, perr, op, off); msg != "" {
		f.Fatalf("harness: pristine signed fixture did not yield the signed identity: %s", msg)
	}

	f.Add(uint8(0), uint16(0), []byte("x"))
	for op := range uint8(fidNumOps) {
		f.Add(op, uint16(0), []byte("y"))
	}
	f.Add(uint8(15), uint16(0), []byte("Z"))
	f.Add(uint8(16), uint16(0), []byte("Z"))
	f.Add(uint8(18), uint16(0), []byte(""))
	f.Add(uint8(21), uint16(0), []byte(""))

	f.Fuzz(func(t *testing.T, op uint8, off uint16, blob []byte) {
		mutated := fidMutate(fx.signedXML, op, off, blob)

		var info *AssertionInfo
		var perr error
		fuzzutil.Guard(t.Fatalf, "saml.ParseResponse.FullIdentity", func() {
			info, perr = fx.p.ParseResponse(postedReq(fx.acsURL, mutated), nil)
		})
		if msg := checkFullIdentity(info, perr, op, off); msg != "" {
			t.Fatal(msg)
		}
	})
}

// mustParse parses the pristine signed fixture and returns the parse result plus op/off = 0,
// which denote the pristine input (error last, as checkFullIdentity's caller reorders them).
func mustParse(fx *fidFixture) (*AssertionInfo, uint8, uint16, error) {
	info, perr := fx.p.ParseResponse(postedReq(fx.acsURL, fx.signedXML), nil)
	return info, 0, 0, perr
}

// postedReq builds an application/x-www-form-urlencoded POST carrying rawXML as the
// base64 SAMLResponse form value, with Form already parsed (strictAssertionShape reads
// r.PostForm).
func postedReq(acsURL string, rawXML []byte) *http.Request {
	body := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(rawXML)}}.Encode()
	req := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()
	return req
}
