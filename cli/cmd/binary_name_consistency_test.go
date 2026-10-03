// binary_name_consistency_test.go -- guards against the exact defect DEMO-1 found:
// this module's binary is built and shipped as `keyorix` (root Makefile's BINARY_CLI,
// release.yml's asset names, QUICK_START.md's `./bin/keyorix ...`), but dozens of this
// module's own help texts, Example blocks, and runtime "next steps"/error messages
// still told the user to run the pre-rename working name `keyorix-next` -- a real
// first-run failure: `keyorix system init --server ...`'s own printed "Next steps"
// said `keyorix-next login`, which does not exist as a command.
//
// Scope, stated so a green run is not read as more than it is: this only catches the
// literal token "keyorix-next" reappearing in this module's own Go source. It says
// nothing about other stale-name drift (e.g. a doc outside this module, or a renamed
// flag) -- see quickstart_commands_test.go for the doc-vs-code side of that.
package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// staleBinaryName is built via concatenation so this guard's own source doesn't trip
// itself when walked.
var staleBinaryName = "keyorix" + "-next"

// allowedStaleBinaryNameMentions names the only files, and how many times each, that
// may still mention staleBinaryName -- a deliberate historical note, not a leftover.
// Any other occurrence, anywhere in this module, fails the test.
var allowedStaleBinaryNameMentions = map[string]int{
	"main.go": 1, // cli/main.go's package comment: "it was called keyorix-next before that"
}

func TestNoStaleBinaryNameInCLISource(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	cliRoot := filepath.Join(wd, "..") // cli/cmd -> cli/

	seen := map[string]int{}
	err = filepath.Walk(cliRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			if info.Name() == "bin" || info.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || info.Name() == "binary_name_consistency_test.go" {
			return nil
		}
		b, readErr := os.ReadFile(path) // #nosec G304 -- fixed repo-relative walk, not user input
		if readErr != nil {
			return readErr
		}
		count := strings.Count(string(b), staleBinaryName)
		if count == 0 {
			return nil
		}
		rel, relErr := filepath.Rel(cliRoot, path)
		if relErr != nil {
			rel = path
		}
		seen[rel] = count
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", cliRoot, err)
	}

	for rel, count := range seen {
		if allowedStaleBinaryNameMentions[rel] == count {
			continue
		}
		t.Errorf("%s mentions %q %d time(s) (allowed: %d) -- this module ships as `keyorix`, "+
			"not `%s`; a user-visible string using the old name sends a customer to run a "+
			"command that doesn't exist", rel, staleBinaryName, count, allowedStaleBinaryNameMentions[rel], staleBinaryName)
	}
}
