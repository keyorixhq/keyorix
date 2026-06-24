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
