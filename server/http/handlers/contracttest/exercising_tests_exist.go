package contracttest

import (
	"bytes"
	"fmt"
	"os"
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

// goBinary locates the "go" binary without searching PATH (Sonar S4036):
// runtime.GOROOT() is the toolchain root baked into this very binary at
// build time, not a runtime PATH lookup, so there is no PATH-shadowing
// surface to resolve against in the first place -- a stronger property
// than preferring a fixed, unwriteable PATH directory (which is what a
// PATH search resolves down to anyway).
func goBinary() (string, error) {
	return goBinaryFrom(runtime.GOROOT())
}

// goBinaryFrom is goBinary's logic against an arbitrary goroot, kept
// separate so its error branch is directly testable -- runtime.GOROOT()
// itself is fixed at build time (Go 1.20+ no longer reads GOROOT from the
// environment at call time), so there is no way to make goBinary() itself
// observe a bad root without this split.
func goBinaryFrom(goroot string) (string, error) {
	candidate := filepath.Join(goroot, "bin", "go")
	if _, err := os.Stat(candidate); err != nil {
		return "", fmt.Errorf("\"go\" not found at %s (from runtime.GOROOT()): %w", candidate, err)
	}
	return candidate, nil
}

// realTestNames shells out to `go test -list`, the ground truth ci.yml
// itself uses to compute shard membership -- not go/ast or any other
// derived source, so this check verifies against exactly what a real test
// run would see.
func realTestNames() (map[string]bool, error) {
	goPath, err := goBinary()
	if err != nil {
		return nil, fmt.Errorf("contracttest: %w", err)
	}

	cmd := exec.Command(goPath, "test", "-list", "^Test", ".") // #nosec G204 // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command // goPath is derived entirely from runtime.GOROOT() (goBinary above), not attacker input
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
