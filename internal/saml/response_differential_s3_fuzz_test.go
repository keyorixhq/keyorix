package saml

// Oracle S3 of the SAML response differential (task SD1): no panic / bounded time on
// hostile XML. Shares the diffFixture with response_differential_fuzz_test.go and the
// sortedKeys helper with response_differential_s2_fuzz_test.go.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// hostileXML builds a bounded hostile SAML response body: a depth bomb, an element-count
// bomb, an attribute bomb, or a comment flood, parameterised by fuzz integers (clamped so
// the HARNESS itself stays within bounded memory — the point is to prove Keyorix bounds
// its own work, not to OOM the fuzzer).
func hostileXML(depth, width, attrs int, mode uint8) []byte {
	clamp := func(v int) int {
		if v < 0 {
			return 0
		}
		if v > 20000 {
			return 20000
		}
		return v
	}
	depth, width, attrs = clamp(depth), clamp(width), clamp(attrs)
	var b strings.Builder
	b.WriteString(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">`)
	switch mode % 4 {
	case 0:
		for range depth {
			b.WriteString("<x>")
		}
		for range depth {
			b.WriteString("</x>")
		}
	case 1:
		for range width {
			b.WriteString("<y/>")
		}
	case 2:
		b.WriteString("<z")
		for i := range attrs {
			b.WriteString(fmt.Sprintf(` a%d="v"`, i))
		}
		b.WriteString("/>")
	case 3:
		for range width {
			b.WriteString("<!--c-->")
		}
	}
	b.WriteString(`</samlp:Response>`)
	return []byte(b.String())
}

// assertionBytes extracts the serialized signed Assertion element from the signed response,
// for the wrapSigned hostile case. Returns nil if it cannot be found.
func assertionBytes(signed []byte) []byte {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(signed); err != nil || doc.Root() == nil {
		return nil
	}
	a := doc.Root().FindElement(".//Assertion")
	if a == nil {
		return nil
	}
	d := etree.NewDocument()
	d.SetRoot(a.Copy())
	out, err := d.WriteToBytes()
	if err != nil {
		return nil
	}
	return out
}

// FuzzSAMLResponseHostileXML — ORACLE S3.
//
// Hostile XML (depth / element-count / attribute / comment bombs, optionally wrapping the
// genuinely-signed assertion) must not panic and must return within the fuzzutil.Guard
// wall-clock budget. If, despite the hostility, Keyorix still accepts, the S2 provenance
// invariant must continue to hold (so this never certifies a bypass as "just hostile").
func FuzzSAMLResponseHostileXML(f *testing.F) {
	fx := newDiffFixture(f)
	signed, err := base64.StdEncoding.DecodeString(fx.signedB64)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint16(2000), uint16(0), uint16(0), uint8(0), false)
	f.Add(uint16(0), uint16(5000), uint16(0), uint8(1), false)
	f.Add(uint16(0), uint16(0), uint16(5000), uint8(2), false)
	f.Add(uint16(0), uint16(5000), uint16(0), uint8(3), false)
	f.Add(uint16(100), uint16(100), uint16(100), uint8(0), true)

	f.Fuzz(func(t *testing.T, depth, width, attrs uint16, mode uint8, wrapSigned bool) {
		payload := hostileXML(int(depth), int(width), int(attrs), mode)
		if wrapSigned {
			// Embed the genuinely-signed assertion inside the hostile wrapper, so a bomb
			// cannot be used to smuggle a real identity past the work bounds.
			if idx := bytes.LastIndex(payload, []byte("</samlp:Response>")); idx >= 0 {
				if a := assertionBytes(signed); a != nil {
					payload = append(append(append([]byte{}, payload[:idx]...), a...), payload[idx:]...)
				}
			}
		}

		var kInfo *AssertionInfo
		var kErr error
		fuzzutil.Guard(t.Fatalf, "saml.diff.S3.keyorix", func() {
			kInfo, kErr = fx.p.ParseResponse(diffReq(payload), nil)
		})
		if kErr != nil {
			return // rejected fast — the expected outcome for hostile XML
		}
		if kInfo == nil {
			t.Fatalf("S3: Keyorix returned nil error AND nil identity (mode=%d)", mode)
		}
		// Accepted despite hostility: provenance must still hold.
		ids, n := fx.signedIdentities(payload)
		if n == 0 {
			t.Fatalf("S3 PROVENANCE BYPASS: Keyorix accepted hostile payload with identity %q but goxmldsig validated NO signed element (mode=%d wrap=%v)",
				kInfo.Subject, mode, wrapSigned)
		}
		if _, ok := ids[kInfo.Subject]; !ok {
			t.Fatalf("S3 XSW BYPASS: Keyorix identity %q not in validly-signed set %v (mode=%d wrap=%v)",
				kInfo.Subject, sortedKeys(ids), mode, wrapSigned)
		}
	})
}
