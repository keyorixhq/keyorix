package bundle

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ilicense "github.com/keyorixhq/keyorix/internal/license"
	"github.com/keyorixhq/keyorix/internal/trust"
)

// licenseTok issues a license with the given features and writes it to a temp file,
// returning the path and a registry that trusts its key.
func licenseTok(t *testing.T, features []string) (string, *trust.KeyRegistry) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	token, err := ilicense.Issue(ilicense.License{
		Licensee: "ACME", Plan: "enterprise-airgap", Features: features,
		IssuedAt: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyID: "license-2026",
	}, priv)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	path := filepath.Join(t.TempDir(), "license.tok")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeLicense, "license-2026", pub)
	return path, reg
}

func TestRequireAirgapUpdates_Licensed(t *testing.T) {
	path, reg := licenseTok(t, []string{ilicense.FeatureAirgapUpdates})
	importLicense = path
	t.Cleanup(func() { importLicense = "" })
	if err := requireAirgapUpdates(reg); err != nil {
		t.Fatalf("a license with airgap_updates should pass: %v", err)
	}
}

func TestRequireAirgapUpdates_WrongFeature_Refused(t *testing.T) {
	path, reg := licenseTok(t, []string{"some_other_feature"})
	importLicense = path
	t.Cleanup(func() { importLicense = "" })
	err := requireAirgapUpdates(reg)
	if err == nil || !strings.Contains(err.Error(), "commercial feature") {
		t.Fatalf("a license without airgap_updates must be refused, got: %v", err)
	}
}

func TestRequireAirgapUpdates_NoLicense_Refused(t *testing.T) {
	importLicense = "" // no --license supplied
	err := requireAirgapUpdates(trust.NewRegistry())
	if err == nil {
		t.Fatal("no license must refuse import (fail-safe: feature off)")
	}
}

func TestRequireAirgapUpdates_Untrusted_Refused(t *testing.T) {
	// A valid token, but evaluated against a registry that doesn't trust its key.
	path, _ := licenseTok(t, []string{ilicense.FeatureAirgapUpdates})
	importLicense = path
	t.Cleanup(func() { importLicense = "" })
	if err := requireAirgapUpdates(trust.NewRegistry()); err == nil {
		t.Fatal("an untrusted license must be refused")
	}
}

// licenseTokBoundTo issues a license bound to the given deployment id (anti-copy binding),
// mirroring licenseTok above.
func licenseTokBoundTo(t *testing.T, deploymentID string, features []string) (string, *trust.KeyRegistry) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	token, err := ilicense.Issue(ilicense.License{
		Licensee: "ACME", Plan: "enterprise-airgap", Features: features,
		IssuedAt: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		DeploymentID: deploymentID,
		KeyID:        "license-2026",
	}, priv)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	path := filepath.Join(t.TempDir(), "license.tok")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeLicense, "license-2026", pub)
	return path, reg
}

// writeConfigWithDeploymentID writes a minimal keyorix.yaml configuring
// license.deployment_id and points KEYORIX_CONFIG_PATH at it for the duration of the test.
func writeConfigWithDeploymentID(t *testing.T, deploymentID string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	yaml := "license:\n  deployment_id: \"" + deploymentID + "\"\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("KEYORIX_CONFIG_PATH", path)
}

// Regression test for #286: `bundle import` used to hardcode Evaluate(token, reg, "", ...),
// so it never enforced an operator's own configured license.deployment_id anti-copy binding.
// It must now pass the configured value through.
func TestRequireAirgapUpdates_ConfiguredDeploymentID_PassedThrough(t *testing.T) {
	writeConfigWithDeploymentID(t, "deployment-a")

	// A license bound to the SAME deployment the operator configured must be granted.
	matchPath, matchReg := licenseTokBoundTo(t, "deployment-a", []string{ilicense.FeatureAirgapUpdates})
	importLicense = matchPath
	if err := requireAirgapUpdates(matchReg); err != nil {
		t.Fatalf("license bound to the configured deployment id should pass: %v", err)
	}

	// A license bound to a DIFFERENT deployment (e.g. copied from another customer) must now
	// be refused — this only happens if the configured deployment id actually reaches Evaluate.
	mismatchPath, mismatchReg := licenseTokBoundTo(t, "deployment-b", []string{ilicense.FeatureAirgapUpdates})
	importLicense = mismatchPath
	t.Cleanup(func() { importLicense = "" })
	err := requireAirgapUpdates(mismatchReg)
	if err == nil {
		t.Fatal("a license bound to a different deployment must be refused once deployment_id is configured")
	}
}

// Regression test for #286: with NO configured license.deployment_id (the default, unopted-in
// posture), behavior must be exactly what it was before the fix — Evaluate still receives "".
func TestRequireAirgapUpdates_UnconfiguredDeploymentID_BehaviorUnchanged(t *testing.T) {
	// Point at a config path that does not exist, so configuredDeploymentID() falls back to
	// "" exactly as the old hardcoded call site did, regardless of the host's real environment.
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "does-not-exist.yaml"))

	// An unbound license (no deployment_id on the token) still passes — unaffected either way.
	unboundPath, unboundReg := licenseTok(t, []string{ilicense.FeatureAirgapUpdates})
	importLicense = unboundPath
	if err := requireAirgapUpdates(unboundReg); err != nil {
		t.Fatalf("an unbound license must still pass with no deployment configured: %v", err)
	}

	// A license bound to a specific deployment is refused when this deployment has no
	// deployment_id configured — same fail-closed anti-bypass behavior as before the fix
	// (internal/license/license.go's Evaluate: "no deployment_id configured" degrades).
	boundPath, boundReg := licenseTokBoundTo(t, "deployment-a", []string{ilicense.FeatureAirgapUpdates})
	importLicense = boundPath
	t.Cleanup(func() { importLicense = "" })
	if err := requireAirgapUpdates(boundReg); err == nil {
		t.Fatal("a deployment-bound license must still be refused when no deployment_id is configured")
	}
}
