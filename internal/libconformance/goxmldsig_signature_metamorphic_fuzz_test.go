package libconformance

// GOXMLDSIG SIGNATURE METAMORPHIC (task XM1, oracle SIG-1). The security property crewjam/saml
// ultimately rests on is: a signature verifies the EXACT bytes it covers, and ANY change to
// those bytes makes verification FAIL. goxmldsig is the engine that enforces it. This target
// exercises goxmldsig's own sign→verify round trip at the library level and asserts the
// tamper-rejection property that XML Signature Wrapping (XSW) attacks exist to defeat.
//
// ORACLE SIG-1 (sound by construction — gated, no false-positive direction):
//
//	sign the fuzzed element (enveloped), serialise, and Validate it.
//	IF it does not verify (err != nil): SKIP — this input did not produce a verifiable
//	   signature, and we assert nothing about it (so a benign clock/cert/shape reason to not
//	   verify can never be a false finding).
//	IF it DOES verify: TAMPER with the signed content (add an attribute to the signed root,
//	   which exclusive-C14N includes in the digest) and Validate again.
//	   INVARIANT: the tampered document must NOT verify. A tampered document that still
//	   verifies is a catastrophic signature-integrity failure (TAMPER-ACCEPTED candidate).
//
// This is additive to the SAML-handler differential (SXS1, whole crewjam ParseResponse) and to
// FuzzXMLParserDifferential (no keys). It is the only target that drives goxmldsig's signer and
// validator directly.
//
// WHAT THIS ORACLE DOES NOT VERIFY (stated so the green is not over-read):
//   - It does NOT assert "a freshly signed document always verifies" — that direction CAN fail
//     for benign reasons (an input whose shape SignEnveloped mangles), so asserting it would be
//     unsound. Only the TAMPER-REJECTION direction, gated on an actually-verifying document, is
//     asserted.
//   - It does NOT assert "re-serialising an equivalent form keeps the same verdict" — a benign
//     re-serialisation (whitespace) legitimately breaks an XML signature, so that direction is
//     unsound and is NOT a finding here (it is the C14N idempotence target's concern at the
//     canonical-form layer, not the verdict layer).
//   - The tamper is a single, deterministic "add an attribute to the signed root" mutation; it
//     does NOT enumerate the full XSW family (sibling injection, ID-reference confusion, comment
//     splitting). Those are a LEFTOVER (see report) better driven through the crewjam layer
//     (SXS1), which resolves the ID/Reference binding this library target does not model.
//   - One fixed RSA test key (goxmldsig RandomKeyStoreForTest) and the real clock; a cert
//     outside its validity window simply makes Validate fail → SKIP, never a false finding.

import (
	"crypto/x509"
	"sync"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// sigHarness holds the one-time signing/validation context (RSA keygen is expensive; build it
// once and reuse across inputs — the stock engine runs one body at a time per process).
type sigHarness struct {
	sign     *dsig.SigningContext
	validate *dsig.ValidationContext
	ok       bool
}

var (
	sigHarnessOnce sync.Once
	sigHarnessInst sigHarness
)

func getSigHarness() sigHarness {
	sigHarnessOnce.Do(func() {
		ks := dsig.RandomKeyStoreForTest()
		_, certDER, err := ks.GetKeyPair()
		if err != nil {
			return
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return
		}
		store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
		vc := dsig.NewDefaultValidationContext(store)
		sigHarnessInst = sigHarness{
			sign:     dsig.NewDefaultSigningContext(ks),
			validate: vc,
			ok:       true,
		}
	})
	return sigHarnessInst
}

// verifies reports whether el verifies under the harness (error -> does not verify).
func (h sigHarness) verifies(el *etree.Element) bool {
	_, err := h.validate.Validate(el)
	return err == nil
}

// serialiseRoot returns the bytes of a document whose root is a (deep copy of) el.
func serialiseRoot(el *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	return doc.WriteToBytes()
}

const goxmldsigSigBudgetPath = "testdata/resguard-goxmldsig-sig.json"

// tamperAttrName is a unique attribute the tamper step adds to the signed root. It is vanishingly
// unlikely to pre-exist in fuzz input and, being a real attribute, is included by exclusive-C14N
// in the signed digest, so adding it MUST break verification.
const tamperAttrName = "xm1TamperMarker"

// addTamperAttr is the production tamper: add an attribute to the signed root (included by
// exclusive-C14N in the digest), which MUST break verification.
func addTamperAttr(root *etree.Element) { root.CreateAttr(tamperAttrName, "1") }

// signAndMaybeTamper is the SIG-1 oracle body with the production tamper.
func signAndMaybeTamper(h sigHarness, data []byte) (before, after, exercised bool) {
	return signAndTamperWith(h, data, addTamperAttr)
}

// signAndTamperWith is the oracle body parameterised by the tamper mutation so the red/green
// proof can inject a NO-OP tamper (modelling a library that fails to detect modification) and
// confirm the before&&after condition the fuzz body fatals on actually fires.
// It returns (verifiedBeforeTamper, verifiedAfterTamper, exercised). exercised is false when the
// input never produced a verifying signature (the gate), so nothing is asserted.
func signAndTamperWith(h sigHarness, data []byte, tamper func(*etree.Element)) (before, after, exercised bool) {
	doc := etree.NewDocument()
	doc.ReadSettings.Permissive = true
	if err := doc.ReadFromBytes(data); err != nil {
		return false, false, false
	}
	root := doc.Root()
	if root == nil {
		return false, false, false
	}
	signed, err := h.sign.SignEnveloped(root)
	if err != nil {
		return false, false, false
	}
	// Serialise and re-parse so Validate sees an independent tree (as the live path does).
	sBytes, err := serialiseRoot(signed)
	if err != nil {
		return false, false, false
	}
	parsed := etree.NewDocument()
	parsed.ReadSettings.Permissive = true
	if err := parsed.ReadFromBytes(sBytes); err != nil {
		return false, false, false
	}
	pRoot := parsed.Root()
	if pRoot == nil {
		return false, false, false
	}
	if !h.verifies(pRoot) {
		return false, false, false // GATE: no verifying signature from this input — assert nothing.
	}
	// TAMPER: add an attribute to the signed root (included in the exclusive-C14N digest).
	parsed2 := etree.NewDocument()
	parsed2.ReadSettings.Permissive = true
	if err := parsed2.ReadFromBytes(sBytes); err != nil {
		return true, false, false
	}
	tRoot := parsed2.Root()
	tamper(tRoot)
	after = h.verifies(tRoot)
	return true, after, true
}

// FuzzGoxmldsigSignatureMetamorphic is oracle SIG-1. See the file header.
func FuzzGoxmldsigSignatureMetamorphic(f *testing.F) {
	seeds := []string{
		`<Assertion ID="_a" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Subject><NameID>u@x</NameID></Subject></Assertion>`,
		`<a><b x="1">t</b><c/></a>`,
		`<r xmlns:z="urn:z"><z:e a="1">x</z:e></r>`,
		`<doc><id>42</id><payload>data</payload></doc>`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	h := getSigHarness()
	if !h.ok {
		f.Skip("could not build goxmldsig signing harness")
	}
	probe := resguard.New(f, resguard.Options{SampleEvery: 32})
	budget, err := resguard.LoadBudget(goxmldsigSigBudgetPath)
	haveBudget := err == nil
	if !haveBudget {
		f.Logf("no committed budget at %s (run TestResguardGoxmldsigSigCalibrate with RESGUARD_CALIBRATE=1); metering without a ceiling", goxmldsigSigBudgetPath)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<18 { // signing is RSA-bounded; keep inputs modest
			return
		}
		var before, after, exercised bool
		cost := probe.Measure(len(data), func() {
			fuzzutil.Guard(t.Fatalf, "goxmldsig.SignEnveloped+Validate", func() {
				before, after, exercised = signAndMaybeTamper(h, data)
			})
		})
		resguard.FeedCoverage(cost)
		if haveBudget {
			budget.Check(t.Fatalf, cost)
		}
		if exercised && before && after {
			t.Fatalf("SIG-1 TAMPER-ACCEPTED: a signed document still verified after an attribute was added to the signed root\n input=%q", data)
		}
	})
}
