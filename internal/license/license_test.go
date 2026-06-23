package license

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/trust"
)

// signed mints a license + a registry that trusts its key under keyID.
func signed(t *testing.T, lic License) (string, *trust.KeyRegistry) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	if lic.KeyID == "" {
		lic.KeyID = "license-2026"
	}
	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	reg := trust.NewRegistry()
	if err := reg.Add(trust.PurposeLicense, lic.KeyID, pub); err != nil {
		t.Fatalf("reg.Add: %v", err)
	}
	return token, reg
}

func TestEvaluate_Active(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	token, reg := signed(t, License{
		Licensee: "ACME GmbH", Plan: "enterprise-airgap",
		Features: []string{"airgap_updates", "premium_connectors"},
		IssuedAt: now, NotAfter: now.Add(365 * 24 * time.Hour),
	})
	st := Evaluate(token, reg, "", now, 14*24*time.Hour)
	if st.State != StateActive {
		t.Fatalf("state = %s, want active (%s)", st.State, st.Reason)
	}
	if !st.HasFeature("airgap_updates") || !st.HasFeature("premium_connectors") {
		t.Fatalf("expected features granted: %+v", st)
	}
	if st.HasFeature("not_a_feature") {
		t.Fatal("ungranted feature reported as present")
	}
}

func TestEvaluate_NoLicense_DegradesToBaseline(t *testing.T) {
	st := Evaluate("", trust.NewRegistry(), "", time.Now(), time.Hour)
	if st.State != StateNone {
		t.Fatalf("state = %s, want none", st.State)
	}
	if st.Grants() || st.HasFeature("airgap_updates") {
		t.Fatal("no license must grant nothing")
	}
	if st.Reason == "" {
		t.Fatal("expected a reason to surface to the admin")
	}
}

func TestEvaluate_BadSignature_DegradesNotDenies(t *testing.T) {
	now := time.Now().UTC()
	token, _ := signed(t, License{Licensee: "ACME", NotAfter: now.Add(time.Hour), Features: []string{"x"}})
	// A registry that trusts a DIFFERENT key under the same id — signature won't verify.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeLicense, "license-2026", otherPub)

	st := Evaluate(token, reg, "", now, time.Hour)
	// Fail-SAFE: invalid signature degrades to baseline, it does NOT error or deny.
	if st.State != StateInvalid {
		t.Fatalf("state = %s, want invalid", st.State)
	}
	if st.Grants() {
		t.Fatal("an unverifiable license must not grant features")
	}
}

func TestEvaluate_UntrustedRegistry_Degrades(t *testing.T) {
	now := time.Now().UTC()
	token, _ := signed(t, License{Licensee: "ACME", NotAfter: now.Add(time.Hour), Features: []string{"x"}})
	// Empty registry (a plain non-release build) — no license keys at all.
	st := Evaluate(token, trust.NewRegistry(), "", now, time.Hour)
	if st.State != StateInvalid || st.Grants() {
		t.Fatalf("want invalid+no-grant, got %s grants=%v", st.State, st.Grants())
	}
}

func TestEvaluate_Expired_BeyondGrace_Baseline(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	token, reg := signed(t, License{
		Licensee: "ACME", Features: []string{"airgap_updates"},
		IssuedAt: now.Add(-400 * 24 * time.Hour), NotAfter: now.Add(-30 * 24 * time.Hour),
	})
	st := Evaluate(token, reg, "", now, 14*24*time.Hour) // expired 30d ago, grace 14d → expired
	if st.State != StateExpired {
		t.Fatalf("state = %s, want expired", st.State)
	}
	if st.Grants() || st.HasFeature("airgap_updates") {
		t.Fatal("a fully-expired license must drop to baseline")
	}
}

func TestEvaluate_Expired_WithinGrace_StillGrants(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	// Expired 3 days ago, grace 14 days → still grants (fail-safe), flagged expiring_soon.
	token, reg := signed(t, License{
		Licensee: "ACME", Features: []string{"airgap_updates"},
		IssuedAt: now.Add(-100 * 24 * time.Hour), NotAfter: now.Add(-3 * 24 * time.Hour),
	})
	st := Evaluate(token, reg, "", now, 14*24*time.Hour)
	if st.State != StateExpiringSoon {
		t.Fatalf("state = %s, want expiring_soon (in grace)", st.State)
	}
	if !st.HasFeature("airgap_updates") {
		t.Fatal("within grace, features must still be granted (availability is a security property)")
	}
	if st.Reason == "" {
		t.Fatal("grace period must warn")
	}
}

func TestEvaluate_ExpiringSoon_BeforeExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	// Expires in 10 days (< 30d window) → expiring_soon, still grants.
	token, reg := signed(t, License{
		Licensee: "ACME", Features: []string{"airgap_updates"},
		IssuedAt: now.Add(-355 * 24 * time.Hour), NotAfter: now.Add(10 * 24 * time.Hour),
	})
	st := Evaluate(token, reg, "", now, 14*24*time.Hour)
	if st.State != StateExpiringSoon || !st.HasFeature("airgap_updates") {
		t.Fatalf("want expiring_soon + granted, got %s grants=%v", st.State, st.Grants())
	}
}

func TestEvaluate_DeploymentBinding(t *testing.T) {
	now := time.Now().UTC()
	token, reg := signed(t, License{
		Licensee: "ACME", Features: []string{"x"},
		NotAfter: now.Add(time.Hour), DeploymentID: "kx-7f3a",
	})
	// Matching deployment → granted.
	if st := Evaluate(token, reg, "kx-7f3a", now, time.Hour); !st.HasFeature("x") {
		t.Fatalf("matching deployment should grant: %+v", st)
	}
	// Mismatched deployment → degrade (warn + audit), NOT shutdown.
	st := Evaluate(token, reg, "kx-other", now, time.Hour)
	if st.State != StateInvalid || st.Grants() {
		t.Fatalf("mismatch must degrade: %s grants=%v", st.State, st.Grants())
	}
	// No local deployment id supplied → binding not enforced (still grants).
	if st := Evaluate(token, reg, "", now, time.Hour); !st.HasFeature("x") {
		t.Fatal("unbound check should still grant")
	}
}

func TestEvaluate_MalformedToken_Degrades(t *testing.T) {
	for _, bad := range []string{"garbage", "only-one-part", "a.b.c", "!!.??"} {
		st := Evaluate(bad, trust.NewRegistry(), "", time.Now(), time.Hour)
		if st.State != StateInvalid || st.Grants() {
			t.Fatalf("token %q: want invalid+no-grant, got %s", bad, st.State)
		}
	}
}

func TestIssue_Validates(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	if _, err := Issue(License{NotAfter: time.Now(), KeyID: "k"}, priv); err == nil {
		t.Fatal("want error for missing licensee")
	}
	if _, err := Issue(License{Licensee: "x", KeyID: "k"}, priv); err == nil {
		t.Fatal("want error for missing not_after")
	}
	if _, err := Issue(License{Licensee: "x", NotAfter: time.Now()}, priv); err == nil {
		t.Fatal("want error for missing key-id")
	}
}

func TestParsePrivateKeyPEM_Rejects(t *testing.T) {
	if _, err := ParsePrivateKeyPEM([]byte("not a pem")); err == nil {
		t.Fatal("want error for non-PEM input")
	}
}
