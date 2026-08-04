package contracttest

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// handlersPkgDir is server/http/handlers itself, resolved the same way
// specPath is (relative to this source file, not process cwd) -- see
// spec.go's comment for why.
var handlersPkgDir = func() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("contracttest: runtime.Caller(0) failed -- cannot locate server/http/handlers")
	}
	return filepath.Join(filepath.Dir(thisFile), "..")
}()

// CheckExercisingTestsExist asserts every test name referenced in
// exercisingTests (registry.go) actually exists as a top-level Test function
// in server/http/handlers, verified by literally listing them via
// `go test -list` (the same mechanism ci.yml itself uses to compute the
// handlers-1..4 shards) rather than trusting the map.
//
// exercisingTests is itself a hand-maintained mapping -- exactly the kind of
// second place to update that ADR-074's requirement 5 warns against. Nothing
// else in this package catches it going stale: if a named test is renamed or
// deleted, CheckAllEnforcedExercised's shard-eligibility check (checks.go)
// can't tell "this test isn't in this shard" apart from "this test doesn't
// exist anywhere" -- the operation becomes ineligible in every shard, gets
// asserted on in none of them, and the build stays green while it is
// silently unenforced. This check is what actually catches that: it doesn't
// care about sharding or eligibility, it only asks whether the named test
// exists at all.
func CheckExercisingTestsExist() error {
	real, err := realTestNames()
	if err != nil {
		return fmt.Errorf("contracttest: listing real test names in %s: %w", handlersPkgDir, err)
	}

	var missing []string
	for opID, names := range exercisingTests {
		for _, name := range names {
			if !real[name] {
				missing = append(missing, fmt.Sprintf("%s -> %s", opID, name))
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf(
		"contracttest: %d exercisingTests entr(ies) (registry.go) name a test function that "+
			"does not exist in %s -- a renamed or deleted test would otherwise silently make its "+
			"operation's coverage check ineligible in every shard rather than failing "+
			"(operationId -> missing test name): %s",
		len(missing), handlersPkgDir, strings.Join(missing, "; "),
	)
}

// realTestNames shells out to `go test -list`, the ground truth ci.yml
// itself uses to compute shard membership -- not go/ast or any other
// derived source, so this check verifies against exactly what a real test
// run would see.
func realTestNames() (map[string]bool, error) {
	// "go" resolves via PATH (S4036), but it's the same toolchain binary
	// already trusted to compile and run this very test process -- if PATH
	// were compromised enough to shadow it, that trust boundary was already
	// crossed one level up, by the `go test` invocation that started this
	// process in the first place. Same treatment as this repo's existing
	// PATH-resolved `git` calls (internal/cli/secret/scan.go).
	cmd := exec.Command("go", "test", "-list", "^Test", ".") // #nosec G204 -- NOSONAR go:S4036
	cmd.Dir = handlersPkgDir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, out.String())
	}

	names := map[string]bool{}
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "ok ") || strings.HasPrefix(line, "FAIL") {
			continue
		}
		names[line] = true
	}
	return names, nil
}
