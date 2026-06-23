package license

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/trust"
)

func TestGate_Nil_IsBaseline(t *testing.T) {
	var g *Gate // a server with no license configured
	st := g.Status()
	if st.State != StateNone {
		t.Fatalf("nil gate state = %s, want none", st.State)
	}
	if g.HasFeature("airgap_updates") {
		t.Fatal("nil gate must grant nothing")
	}
}

func TestGate_EmptyToken_IsBaseline(t *testing.T) {
	g := NewGate("", trust.NewRegistry(), "", 0)
	if g.Status().State != StateNone || g.HasFeature("x") {
		t.Fatalf("empty token must be baseline: %+v", g.Status())
	}
}

func TestGate_ActiveToken_Grants(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeLicense, "license-2026", pub)

	// not_after well in the future so the gate's real-clock Status() is active.
	token, err := Issue(License{
		Licensee: "ACME", Plan: "enterprise", Features: []string{"airgap_updates"},
		IssuedAt: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyID: "license-2026",
	}, priv)
	if err != nil {
		t.Fatal(err)
	}

	g := NewGate(token, reg, "", 0)
	if !g.HasFeature("airgap_updates") {
		t.Fatalf("expected feature granted: %+v", g.Status())
	}
	if g.HasFeature("nope") {
		t.Fatal("ungranted feature reported present")
	}
}

func TestGate_FreshEvaluation_AcrossExpiry(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeLicense, "license-2026", pub)

	base := time.Unix(1_700_000_000, 0).UTC()
	notAfter := base.Add(100 * 24 * time.Hour) // 100d out — beyond the 30d expiring-soon window
	token, _ := Issue(License{
		Licensee: "ACME", Features: []string{"x"},
		IssuedAt: base.Add(-24 * time.Hour), NotAfter: notAfter,
		KeyID: "license-2026",
	}, priv)

	g := NewGate(token, reg, "", time.Minute) // tiny grace
	// Drive the gate's clock to prove it re-evaluates each call rather than caching.
	g.now = func() time.Time { return base } // 100d before expiry → active
	if g.Status().State != StateActive {
		t.Fatalf("pre-expiry: %s", g.Status().State)
	}
	g.now = func() time.Time { return notAfter.Add(10 * time.Minute) } // past expiry+grace → expired
	if st := g.Status(); st.State != StateExpired || st.Grants() {
		t.Fatalf("post-expiry: %s grants=%v (expected expired, no grant)", st.State, st.Grants())
	}
}

func TestGate_NilRegistry_Degrades(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = pub
	token, _ := Issue(License{Licensee: "ACME", NotAfter: time.Now().Add(time.Hour), Features: []string{"x"}, KeyID: "k"}, priv)
	// A gate with no registry (e.g. trust.DefaultRegistry failed) must not panic and must
	// degrade to baseline.
	g := NewGate(token, nil, "", 0)
	if g.Status().Grants() {
		t.Fatal("no registry must not grant features")
	}
}
