package core

import (
	"os/exec"
	"strings"
	"testing"
)

// coreIntegrationDeps is the exact set of integration packages
// internal/core's production files may still import, one entry per ADR-109
// decoupling step (docs/adr-109-core-depends-on-interfaces.md, "Order of
// work": notary, saml, rotation, dynamic, connect, encryption/KMS). A step
// that moves its integration behind internal/core/ports and wires the real
// implementation from server/main.go deletes its own entry here.
//
// notary and saml were removed at step 1, rotation at step 2: internal/core
// now depends only on ports.TimestampNotary/ports.VerifyReceiptFunc,
// ports.SAMLServiceProvider, and ports.RotationExecutorResolver/
// ports.RotationPartialError, wired from server/main.go's DefaultIntegrations.
// All three prefixes stay in the scan below (see present's HasPrefix checks)
// so a regression back to any of them is still caught by the "not on the
// allowlist" branch, not silently dropped from the scan.
//
// The comparison below is an EXACT match, not a ceiling: it also fails if an
// entry is deleted from this list without the corresponding import actually
// being removed from internal/core, or vice versa — so a step that forgets
// to touch this file when it's done (or claims done before it actually is)
// is caught, not just growth beyond what's listed.
//
// internal/connect/connecttypes is deliberately NOT on this list — it is a
// types-only sibling package with no SDK dependency (see the identical
// carve-out in internal/i18n/deps_guard_test.go), and ADR-109 has no reason
// to ever remove it from internal/core.
var coreIntegrationDeps = map[string]bool{
	"github.com/keyorixhq/keyorix/internal/connect":    true,
	"github.com/keyorixhq/keyorix/internal/dynamic":    true,
	"github.com/keyorixhq/keyorix/internal/encryption": true,
}

// TestCoreIntegrationDepsMatchADR109Allowlist fails if internal/core's
// production dependency graph drifts from coreIntegrationDeps in either
// direction. It runs `go list -deps` (production deps only, test files
// excluded) and skips when the go tool isn't available.
func TestCoreIntegrationDepsMatchADR109Allowlist(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not in PATH")
	}
	out, err := exec.Command("go", "list", "-deps", "github.com/keyorixhq/keyorix/internal/core").Output()
	if err != nil {
		t.Fatalf("go list -deps internal/core: %v", err)
	}
	present := map[string]bool{}
	for _, dep := range strings.Fields(string(out)) {
		if dep == "github.com/keyorixhq/keyorix/internal/connect/connecttypes" {
			continue
		}
		if strings.HasPrefix(dep, "github.com/keyorixhq/keyorix/internal/connect") ||
			strings.HasPrefix(dep, "github.com/keyorixhq/keyorix/internal/rotation") ||
			strings.HasPrefix(dep, "github.com/keyorixhq/keyorix/internal/dynamic") ||
			strings.HasPrefix(dep, "github.com/keyorixhq/keyorix/internal/encryption") ||
			strings.HasPrefix(dep, "github.com/keyorixhq/keyorix/internal/notary") ||
			strings.HasPrefix(dep, "github.com/keyorixhq/keyorix/internal/saml") {
			present[dep] = true
		}
	}
	for dep := range coreIntegrationDeps {
		if !present[dep] {
			t.Errorf("internal/core no longer imports %s: an ADR-109 step finished it — shrink coreIntegrationDeps to match", dep)
		}
	}
	for dep := range present {
		if !coreIntegrationDeps[dep] {
			t.Errorf("internal/core imports %s, which is not on the ADR-109 allowlist (coreIntegrationDeps)", dep)
		}
	}
}
