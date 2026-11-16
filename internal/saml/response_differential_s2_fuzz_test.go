package saml

// Oracle S2 of the SAML response differential (task SD1): identity provenance. Shares the
// diffFixture and diffMutate engine with response_differential_oracles_fuzz_test.go.

import (
	"encoding/base64"
	"sort"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FuzzSAMLResponseIdentityProvenance — ORACLE S2.
//
// When Keyorix accepts and returns an identity, goxmldsig (independently of crewjam) must
// have validated at least one signed element, and the identity Keyorix returns must be the
// Subject NameID of one of those validly-signed subtrees. An identity taken from an
// unsigned, wrapped, duplicated, or namespace-shifted element is an XSW bypass — a FINDING.
func FuzzSAMLResponseIdentityProvenance(f *testing.F) {
	fx := newDiffFixture(f)
	signed, err := base64.StdEncoding.DecodeString(fx.signedB64)
	if err != nil {
		f.Fatal(err)
	}
	addDiffSeeds(f)

	f.Fuzz(func(t *testing.T, op uint8, off uint16, blob []byte) {
		mutated := diffMutate(signed, op, off, blob)

		var kInfo *AssertionInfo
		var kErr error
		fuzzutil.Guard(t.Fatalf, "saml.diff.S2.keyorix", func() {
			kInfo, kErr = fx.p.ParseResponse(diffReq(mutated), nil)
		})
		if kErr != nil {
			return // rejected — nothing is trusted from a rejected response
		}
		if kInfo == nil {
			t.Fatalf("S2: Keyorix returned nil error AND nil identity (op=%d)", op)
		}

		ids, n := fx.signedIdentities(mutated)
		if n == 0 || len(ids) == 0 {
			t.Fatalf("S2 PROVENANCE BYPASS: Keyorix returned identity %q but goxmldsig validated NO signed element (op=%d off=%d)",
				kInfo.Subject, op, off)
		}
		if _, ok := ids[kInfo.Subject]; !ok {
			t.Fatalf("S2 XSW BYPASS: Keyorix returned identity %q, which is NOT the identity of any validly-signed element %v (op=%d off=%d)",
				kInfo.Subject, sortedKeys(ids), op, off)
		}
	})
}
