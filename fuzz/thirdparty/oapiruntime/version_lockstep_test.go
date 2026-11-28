package oapiruntime

import (
	"os"
	"regexp"
	"testing"
)

var runtimeRequire = regexp.MustCompile(`(?m)^\s*(?:require\s+)?github\.com/oapi-codegen/runtime\s+(v\S+)`)

func requiredRuntimeVersion(t *testing.T, gomod string) string {
	t.Helper()
	b, err := os.ReadFile(gomod)
	if err != nil {
		t.Fatalf("read %s: %v", gomod, err)
	}
	m := runtimeRequire.FindSubmatch(b)
	if m == nil {
		t.Fatalf("%s does not require github.com/oapi-codegen/runtime", gomod)
	}
	return string(m[1])
}

// TestRuntimeVersionMatchesShippedModules keeps the harness on the version the
// shipped CLI and migrate tool use: the root module only requires the library
// for this harness, so a cli or migrate bump must bump it too.
func TestRuntimeVersionMatchesShippedModules(t *testing.T) {
	root := requiredRuntimeVersion(t, "../../../go.mod")
	for _, mod := range []string{"../../../cli/go.mod", "../../../migrate/go.mod"} {
		if got := requiredRuntimeVersion(t, mod); got != root {
			t.Errorf("%s requires oapi-codegen/runtime %s, root go.mod requires %s: the fuzz harness would test a version that does not ship", mod, got, root)
		}
	}
}
