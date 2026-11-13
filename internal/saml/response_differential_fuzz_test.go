package saml

// Differential fuzzing of (*Provider).ParseResponse against INDEPENDENT offline
// references (task SD1). Unlike parse_response_xsw_fuzz_test.go — which asserts an
// internal invariant using a hard-coded "signed subject" constant as ground truth —
// this harness derives ground truth from a reference that does not share Keyorix's
// code path:
//
//   - crewjam/saml (R1), configured with the SAME trust as Keyorix's internal SP but
//     with crewjam's OWN default audience hook (no Keyorix hardening), is the
//     accept/reject reference for oracle S1.
//   - goxmldsig (R2) is the signature-provenance reference for oracle S2: it decides,
//     independently of crewjam, which element carries a signature valid against the
//     pinned IdP certificate, and what identity lives inside that signed subtree.
//
// Because Keyorix = crewjam ∩ (epilogue + strict-shape + audience + NameID-cross-check),
// accept(Keyorix) ⟹ accept(crewjam-same-trust) holds by construction; the sound S1
// oracle is that implication (Keyorix must never accept what crewjam rejects), plus
// "Keyorix must never accept a response goxmldsig cannot validate a signature for".
// The reverse (crewjam accepts, Keyorix rejects) is over-strict and only counted.
//
// See .scratch/sd1-REPORT.md (uncommitted, private) for the full design, the
// red-proof evidence, and the per-oracle "what this does NOT verify" sections.

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	csaml "github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/keyorixhq/keyorix/internal/saml/samltest"
)

const (
	diffIDPEntityID = "https://idp.example/entity"
	diffSPEntityID  = "https://keyorix.internal/saml/corp/metadata"
	diffACSURL      = "https://keyorix.internal/auth/saml/corp/acs"
	diffSubject     = "user@corp.example"
	diffEvilSubject = "xsw-attacker@evil.example" // must differ from diffSubject
)

// diffFixture bundles everything a differential iteration needs: the Keyorix provider
// under test, a crewjam reference SP (R1) with the same trust but default hardening,
// a goxmldsig validation context (R2) pinned to the IdP cert, and the base64 of one
// genuinely signed, IdP-initiated response asserting diffSubject.
type diffFixture struct {
	p         *Provider
	refSP     *csaml.ServiceProvider
	vctx      *dsig.ValidationContext
	signedB64 string
}

func newDiffFixture(tb testing.TB) *diffFixture {
	tb.Helper()
	fx, err := samltest.NewIdPFixture(diffIDPEntityID)
	if err != nil {
		tb.Fatalf("NewIdPFixture: %v", err)
	}
	p, err := NewProvider(Config{
		Name: "corp", IDPMetadataXML: fx.MetadataXML, SPEntityID: diffSPEntityID, ACSURL: diffACSURL,
		AllowIDPInitiated: true, EmailAttr: "mail", NameAttr: "cn", GroupsAttr: "eduPersonAffiliation",
	})
	if err != nil {
		tb.Fatalf("NewProvider: %v", err)
	}
	spMeta := p.RawServiceProviderMetadata()
	buildTime := time.Now()
	signedB64, err := samltest.SignedResponse(fx, diffIDPEntityID, spMeta, diffSubject, diffSubject, "User Corp", []string{"admins"}, "return-here")
	if err != nil {
		tb.Fatalf("SignedResponse: %v", err)
	}

	// Reference crewjam SP (R1): same trust (IdP metadata, SP entity/ACS, IdP-initiated)
	// as Keyorix's internal SP, but crewjam's OWN default ValidateAudienceRestriction
	// (vacuous on a missing AudienceRestriction) — i.e. NONE of Keyorix's extra checks.
	idp, err := parseIDPMetadata(fx.MetadataXML)
	if err != nil {
		tb.Fatalf("parseIDPMetadata: %v", err)
	}
	metaU, err := url.Parse(diffSPEntityID)
	if err != nil {
		tb.Fatalf("parse sp entity id: %v", err)
	}
	acsU, err := url.Parse(diffACSURL)
	if err != nil {
		tb.Fatalf("parse acs url: %v", err)
	}
	refSP := &csaml.ServiceProvider{
		EntityID: diffSPEntityID, MetadataURL: *metaU, AcsURL: *acsU,
		IDPMetadata: idp, AllowIDPInitiated: true,
	}

	// Pin BOTH Keyorix's internal crewjam SP and the reference SP to the same fixed
	// clock at fixture-build time. crewjam's assertion validity window (MaxIssueDelay,
	// 90s) would otherwise expire partway through a multi-minute fuzz run, and since
	// Keyorix's call and the reference call happen microseconds apart, an input tested
	// right at the expiry instant could have Keyorix see "valid" and the reference see
	// "expired" — a wall-clock race, not a Keyorix defect. A per-SP fixed clock (NOT the
	// deprecated process-global csaml.TimeNow) makes every time check deterministic and
	// identical across the two, without affecting any other test in the package. Time
	// checks are delegated identically to crewjam on both sides, so pinning them cannot
	// hide a Keyorix-specific divergence.
	clk := dsig.NewFakeClockAt(buildTime)
	p.sp.Clock = clk
	refSP.Clock = clk

	store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{fx.Cert}}
	vctx := dsig.NewDefaultValidationContext(store)

	return &diffFixture{p: p, refSP: refSP, vctx: vctx, signedB64: signedB64}
}

// diffReq builds a parsed HTTP POST form request at the ACS carrying raw as the
// base64 SAMLResponse. (The package already has postRequest(t, acsURL, b64) for the
// *testing.T case; this one is usable from a fuzz body with no t.Helper needs and
// takes raw bytes.)
func diffReq(raw []byte) *http.Request {
	body := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(raw)}}.Encode()
	req := httptest.NewRequest(http.MethodPost, diffACSURL, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()
	return req
}

// elementAllText concatenates every CharData token directly under el (skipping comments
// and PIs), mirroring how both crewjam/saml and Keyorix's own strictAssertionShape read a
// NameID's value — a comment spliced into the middle of the text must NOT truncate it.
func elementAllText(el *etree.Element) string {
	var b strings.Builder
	for _, tok := range el.Child {
		if cd, ok := tok.(*etree.CharData); ok {
			b.WriteString(cd.Data)
		}
	}
	return strings.TrimSpace(b.String())
}

// subjectNameIDText returns the NameID text of the first .//Subject/NameID descendant of
// el (falling back to any .//NameID). Namespace-agnostic (matches by local tag, like
// etree paths), and comment-robust (see elementAllText).
func subjectNameIDText(el *etree.Element) string {
	var nid *etree.Element
	for _, subj := range el.FindElements(".//Subject") {
		if n := subj.FindElement("./NameID"); n != nil {
			nid = n
			break
		}
	}
	if nid == nil {
		nid = el.FindElement(".//NameID")
	}
	if nid == nil {
		return ""
	}
	return elementAllText(nid)
}

// signedIdentities uses goxmldsig (R2), INDEPENDENTLY of crewjam, to find every element
// in raw that carries a signature valid against the pinned IdP cert, and returns the set
// of Subject NameIDs found inside those validly-signed subtrees. A copy of each candidate
// element is validated as a standalone element (goxmldsig mutates/detaches the signature).
func (fx *diffFixture) signedIdentities(raw []byte) (ids map[string]struct{}, count int) {
	ids = map[string]struct{}{}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return ids, 0
	}
	root := doc.Root()
	if root == nil {
		return ids, 0
	}
	// Candidate signed elements: the root (response-level signature) and every Assertion.
	candidates := []*etree.Element{root}
	candidates = append(candidates, root.FindElements(".//Assertion")...)
	for _, cand := range candidates {
		// Validate a detached copy so repeated validation across candidates is independent
		// and goxmldsig's in-place signature detach cannot corrupt the shared tree.
		cdoc := etree.NewDocument()
		cdoc.SetRoot(cand.Copy())
		validated, err := func() (v *etree.Element, e error) {
			defer func() {
				if r := recover(); r != nil {
					v, e = nil, fmt.Errorf("goxmldsig panic: %v", r)
				}
			}()
			return fx.vctx.Validate(cdoc.Root())
		}()
		if err != nil || validated == nil {
			continue
		}
		if id := subjectNameIDText(validated); id != "" {
			ids[id] = struct{}{}
			count++
		}
	}
	return ids, count
}

// TestSAMLDifferential_FixtureIsSignedAssertion is the green baseline: the unmutated
// signed response must be accepted by Keyorix with exactly diffSubject, accepted by the
// crewjam reference, and goxmldsig must validate a signature whose subtree holds exactly
// diffSubject. If this fails, the harness's independent-reference wiring is wrong and no
// fuzz result from it can be trusted (fix the fixture, never the oracle).
func TestSAMLDifferential_FixtureIsSignedAssertion(t *testing.T) {
	fx := newDiffFixture(t)
	raw, err := base64.StdEncoding.DecodeString(fx.signedB64)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	// Keyorix accepts with diffSubject.
	info, err := fx.p.ParseResponse(postRequest(t, diffACSURL, fx.signedB64), nil)
	if err != nil {
		t.Fatalf("Keyorix rejected the genuine signed response: %v", err)
	}
	if info.Subject != diffSubject {
		t.Fatalf("Keyorix subject = %q, want %q", info.Subject, diffSubject)
	}

	// crewjam reference (R1) accepts.
	if _, err := fx.refSP.ParseResponse(postRequest(t, diffACSURL, fx.signedB64), nil); err != nil {
		t.Fatalf("crewjam reference rejected the genuine signed response: %v", err)
	}

	// goxmldsig (R2) validates a signature whose subtree holds exactly diffSubject.
	ids, count := fx.signedIdentities(raw)
	if count == 0 {
		t.Fatalf("goxmldsig validated no signed element in the genuine response")
	}
	if _, ok := ids[diffSubject]; !ok {
		t.Fatalf("goxmldsig signed identities = %v, want to contain %q", ids, diffSubject)
	}
	if len(ids) != 1 {
		t.Fatalf("goxmldsig found %d distinct signed identities %v, want exactly 1 (%q)", len(ids), ids, diffSubject)
	}

	// xml-roundtrip-validator (R3) accepts the genuine response.
	if err := xrv.Validate(strings.NewReader(string(raw))); err != nil {
		t.Fatalf("xrv rejected the genuine signed response: %v", err)
	}
}
