// Package depguard enforces docs/design-keyorix-migrate.md's "Module boundaries" section:
// keyorix-migrate must never import internal/core, internal/storage, or anything else under
// the main module's internal/ tree, nor the cli/ module. Both would reintroduce exactly the
// dependency weight (and, for internal/, the direct-DB-access risk) this tool exists to stay
// clear of -- it talks to Keyorix only through the public REST API. This is a compiler-
// enforced ceiling checked against the actual import graph (go list), not a comment asserting
// the property -- CLAUDE.md's "prefer the machine-checked over the asserted" principle applied
// to an architectural boundary rather than an authz one.
package depguard

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// forbiddenPrefixes are import paths no package under this module may depend on, directly or
// transitively.
var forbiddenPrefixes = []string{
	"github.com/keyorixhq/keyorix/internal/",
	"github.com/keyorixhq/keyorix/server/",
	"github.com/keyorixhq/keyorix/cli/",
	"github.com/keyorixhq/keyorix/operator/",
}

func TestNoForbiddenImports(t *testing.T) {
	// GOWORK=off matches every other invocation of this module (Makefile, CI) -- without it,
	// `go list` run from inside a checkout of the full monorepo would resolve against the
	// root go.work instead of this module, defeating the point of the guard.
	cmd := exec.Command("go", "list", "-deps", "-json", "./...")
	cmd.Env = append(cmd.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps -json ./...: %v", err)
	}

	dec := json.NewDecoder(strings.NewReader(string(out)))
	seen := map[string]bool{}
	for dec.More() {
		var pkg struct {
			ImportPath string
		}
		if err := dec.Decode(&pkg); err != nil {
			t.Fatalf("decode go list output: %v", err)
		}
		for _, forbidden := range forbiddenPrefixes {
			if strings.HasPrefix(pkg.ImportPath, forbidden) && !seen[pkg.ImportPath] {
				seen[pkg.ImportPath] = true
				t.Errorf("forbidden import: %s (matches boundary %s — see docs/design-keyorix-migrate.md's Module boundaries section)", pkg.ImportPath, forbidden)
			}
		}
	}
}
