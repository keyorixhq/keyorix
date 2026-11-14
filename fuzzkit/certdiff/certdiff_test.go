package certdiff

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/fuzzkit/diffkit"
)

// mustComparator skips the whole test when openssl is unavailable (so CI without
// the binary is a clean skip, not a failure).
func mustComparator(t *testing.T) diffkit.Comparator[*chain, string] {
	t.Helper()
	c, err := NewComparator()
	if err != nil {
		t.Skipf("openssl unavailable: %v", err)
	}
	return c
}

// agree asserts the two libraries reach the same decision on the chain k
// describes (no divergence). Used for well-understood cases, to prove the oracle
// is GREEN where it should be.
func agree(t *testing.T, c diffkit.Comparator[*chain, string], k knobs) {
	t.Helper()
	ch, err := buildChain(k)
	if err != nil {
		t.Fatalf("buildChain: %v", err)
	}
	diverged, d := c.Compare(context.Background(), ch)
	if diverged {
		t.Fatalf("unexpected divergence: %v", d)
	}
}

func TestKnownCasesAgree(t *testing.T) {
	c := mustComparator(t)
	cases := []struct {
		name string
		k    knobs
	}{
		{"plain leaf under root", knobs{}},
		{"one intermediate", knobs{numInter: 1}},
		{"two intermediates", knobs{numInter: 2}},
		{"expired leaf (both reject)", knobs{leafExpired: true}},
		{"future leaf (both reject)", knobs{leafFuture: true}},
		{"non-CA intermediate (both reject)", knobs{numInter: 1, interNotCA: true}},
		{"forged leaf signature (both reject)", knobs{numInter: 1, wrongSigner: true}},
		{"pathlen:0 violated (both reject)", knobs{numInter: 2, interPathLenZero: true}},
		{"unknown critical ext on leaf (both reject)", knobs{unknownCritExt: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agree(t, c, tc.k)
		})
	}
}

// --- Red proof --------------------------------------------------------------
//
// The Keyorix-side analogue of this decision is internal/notary's chain-trust
// check (VerifyReceipt, internal/notary/notary.go:67): verify the leaf against a
// pool containing ONLY the configured root, with time pinned to the token's
// claimed instant. keyorixStrict models that decision. keyorixRelaxed is a
// SCRATCH copy with a single planted relaxation — it ignores NotAfter (accepts
// an expired leaf) — exactly the kind of regression a differential oracle must
// catch. The proof: strict agrees with openssl (GREEN) on an expired leaf, and
// the relaxed copy diverges from openssl (RED). No production code is touched.

type keyorixVerify struct {
	name           string
	ignoreNotAfter bool // the planted relaxation
}

func (k keyorixVerify) Name() string { return k.name }

func (k keyorixVerify) Run(_ context.Context, ch *chain) (string, error) {
	roots := x509.NewCertPool()
	roots.AddCert(ch.root)
	inter := x509.NewCertPool()
	for _, c := range ch.inters {
		inter.AddCert(c)
	}
	now := ch.now
	if k.ignoreNotAfter {
		// Relaxation: pretend "now" is always within validity by pinning it to the
		// leaf's own notBefore, so an expired leaf still verifies.
		now = ch.leaf.NotBefore
	}
	if _, err := ch.leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return "", err
	}
	return ch.leafFP, nil
}

func TestRedProof_PlantedRelaxationDiverges(t *testing.T) {
	if _, err := NewComparator(); err != nil {
		t.Skipf("openssl unavailable: %v", err)
	}
	expired, err := buildChain(knobs{leafExpired: true})
	if err != nil {
		t.Fatalf("buildChain: %v", err)
	}

	ossl := opensslVerify{bin: "openssl"}

	// GREEN: the faithful wrapper agrees with openssl (both reject the expired leaf).
	green := diffkit.Comparator[*chain, string]{
		Impls:   []diffkit.Impl[*chain, string]{keyorixVerify{name: "keyorix-strict"}, ossl},
		Timeout: perImplTimeout, Decide: decide,
	}
	if diverged, d := green.Compare(context.Background(), expired); diverged {
		t.Fatalf("strict wrapper should agree with openssl on expired leaf, got divergence: %v", d)
	}

	// RED: the planted relaxation (ignore NotAfter) now ACCEPTS the expired leaf
	// while openssl still rejects — the oracle must report the divergence.
	red := diffkit.Comparator[*chain, string]{
		Impls:   []diffkit.Impl[*chain, string]{keyorixVerify{name: "keyorix-relaxed", ignoreNotAfter: true}, ossl},
		Timeout: perImplTimeout, Decide: decide,
	}
	diverged, d := red.Compare(context.Background(), expired)
	if !diverged {
		t.Fatal("planted relaxation (accepts expired leaf) was NOT caught by the differential oracle")
	}
	t.Logf("red proof fired as expected: %v", d)
}

func TestBuildStructurallyStable(t *testing.T) {
	// Go injects entropy into ECDSA signing (randutil.MaybeReadByte), so two
	// builds of the same knobs are NOT byte-identical. That is fine: the trust
	// DECISION depends on structure, not signature bytes, so minimise/replay stay
	// stable. This asserts the structural invariants the oracle relies on.
	a, err := buildChain(knobs{numInter: 2})
	if err != nil {
		t.Fatal(err)
	}
	b, err := buildChain(knobs{numInter: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.inters) != len(b.inters) || a.leaf.Subject.CommonName != b.leaf.Subject.CommonName {
		t.Fatalf("structural drift across builds: %d/%q vs %d/%q",
			len(a.inters), a.leaf.Subject.CommonName, len(b.inters), b.leaf.Subject.CommonName)
	}
	_ = time.Now
}
