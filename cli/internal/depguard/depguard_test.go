// Package depguard mechanically enforces ADR-108 Decision A: this module must not import
// the main module's server-side internal packages, or any cloud SDK. The compiler already
// makes this hard by construction -- cli/go.mod carries no dependency on the main module at
// all, so the ONLY way it could happen is a future "replace" directive pointing back into
// this repo's own tree plus a real import. This test is the tripwire for that: it walks the
// module's actual dependency graph via `go list -deps`, not a source grep, so it also
// catches an indirect import (module A imports module B which imports a forbidden package).
//
// Proven red/green on a scratch branch before being committed here (see the PR description
// for the exact forbidden import added, the resulting failure, and its removal) -- per
// CLAUDE.md's "a guard nobody has watched fail is not a guard."
package depguard

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenPrefixes are import-path prefixes this module's dependency graph must never
// contain. Server-side internal packages first (ADR-108 Decision A's "no core/storage/
// server config"), then every cloud SDK the old, thick CLI pulled in (docs/adr-108-cli-
// server-split.md's Context table: 90 cloud-SDK packages linked).
var forbiddenPrefixes = []string{
	"github.com/keyorixhq/keyorix/internal/core",
	"github.com/keyorixhq/keyorix/internal/storage",
	"github.com/keyorixhq/keyorix/internal/config",
	"github.com/keyorixhq/keyorix/server/",
	"github.com/aws/aws-sdk-go",
	"github.com/Azure/azure-sdk-for-go",
	"cloud.google.com/go",
	"github.com/hashicorp/vault/api",
}

func TestNoServerOrCloudSDKDependencies(t *testing.T) {
	root := moduleRoot(t)

	// GOWORK=off: this module is deliberately excluded from the repo's go.work (matching
	// operator/'s existing precedent) -- an ambient go.work at the repo root would make
	// `go list` fail outright ("directory ... is contained in a module that is not one of
	// the workspace modules"), not silently succeed with the wrong graph, but pinning the
	// env here makes that failure mode impossible rather than merely loud.
	cmd := exec.Command("go", "list", "-deps", "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off")

	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go list -deps failed: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("go list -deps failed: %v", err)
	}

	deps := strings.Split(strings.TrimSpace(string(out)), "\n")
	var violations []string
	for _, d := range deps {
		for _, prefix := range forbiddenPrefixes {
			if strings.HasPrefix(d, prefix) {
				violations = append(violations, d)
			}
		}
	}
	if len(violations) > 0 {
		t.Fatalf("cli module's dependency graph contains forbidden server/cloud-SDK packages (ADR-108 Decision A):\n  %s", strings.Join(violations, "\n  "))
	}
}

// moduleRoot returns this module's root directory (the directory containing cli/go.mod),
// derived via `go env GOMOD` rather than assumed from the test's own package path -- this
// test must keep working if depguard ever moves to a different subdirectory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == "/dev/null" {
		t.Fatalf("go env GOMOD returned no module (got %q) -- is this test running inside the cli module?", gomod)
	}
	return filepath.Dir(gomod)
}
