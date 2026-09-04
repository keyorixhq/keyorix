/*
Keyorix Server - Enterprise Secret Management System
Copyright (C) 2025 Keyorix Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

// mlockall_removal_guard_test.go asserts ADR-100's removal of mlockall stays
// removed: nothing in this repo's tracked Go source reaches the mlockall
// syscall from process startup. This is the "cannot be silently undone" half
// of ADR-100's closure -- a future contributor re-adding `unix.Mlockall` (to
// "fix" a swap-related incident, for example) would reintroduce exactly the
// unbounded, non-shrinking RSS growth ADR-100 measured and removed, without
// necessarily reading ADR-100 or ADR-098 first. A guard that fails loudly at
// review/CI time is cheaper than that repeating in production.
package hardening

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// scanRepoForMlockall reports every *.go file (repo-relative path)
// containing the literal identifier "Mlockall", excluding this guard file
// itself -- which necessarily spells out that identifier in the string
// literals below and would otherwise self-match on every run regardless of
// whether the real syscall is actually gone. Mirrors
// server/http/g80_triage_doc_closure_guard_test.go's repoContains, scoped to
// list every match rather than a single found/not-found bool (so a failure
// message can name the offending file(s) directly), and additionally passes
// --untracked --no-exclude-standard so a locally-created-but-not-yet-staged
// reintroduction is caught too, not just one already added to the index --
// confirmed empirically these two flags are both required: plain `git grep`
// is invisible to files under .scratch/ (gitignored), which is exactly
// where TestMlockallRemovalGuard_FiresOnADeliberateReintroduction below
// plants its synthetic violation.
func scanRepoForMlockall(t *testing.T, root string) []string {
	t.Helper()
	out, err := exec.Command("git", "-C", root, "grep", "-l", "-F", "--untracked", "--no-exclude-standard", "Mlockall", "--",
		"*.go", ":!internal/hardening/mlockall_removal_guard_test.go").CombinedOutput()
	if err == nil {
		return strings.Split(strings.TrimSpace(string(out)), "\n")
	}
	// git grep exits 1 (not an error) when nothing matches -- distinguish
	// that from a real failure (e.g. not a git repo, bad pathspec) by
	// checking for output; a real error with no output is unexpected here
	// and should fail loud rather than be silently read as "no matches".
	if len(out) == 0 {
		return nil
	}
	t.Fatalf("git grep failed unexpectedly while scanning for Mlockall: %v (%s)", err, string(out))
	return nil
}

// TestMlockallRemovalGuard_NoMlockallSyscallReachableFromStartup is the
// green case: confirms the current working tree contains no reference to
// unix.Mlockall (or any other identifier literally named "Mlockall")
// anywhere in tracked Go source. If this ever fails, ADR-100's removal has
// been reverted or reintroduced elsewhere and needs the same design
// discussion ADR-100 itself required, not a silent re-add.
func TestMlockallRemovalGuard_NoMlockallSyscallReachableFromStartup(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available on PATH")
	}
	matches := scanRepoForMlockall(t, "../..")
	if len(matches) > 0 {
		t.Errorf("found %d file(s) referencing Mlockall -- ADR-100 removed this syscall from the startup path "+
			"(unbounded, non-shrinking RSS growth measured against the shipped Helm chart's memory limit); "+
			"re-adding it needs the same design decision ADR-100 required, not a silent reintroduction: %v",
			len(matches), matches)
	}
}

// TestMlockallRemovalGuard_FiresOnADeliberateReintroduction is the red case:
// proves scanRepoForMlockall actually detects the identifier it exists to
// catch, using a real (untracked, git-ignored by .scratch/ convention)
// throwaway file written to and immediately removed from the repo root --
// not just an assertion that today's tree is clean, which would pass
// identically even if the scan itself were broken (e.g. a typo'd pathspec
// that matches nothing).
func TestMlockallRemovalGuard_FiresOnADeliberateReintroduction(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available on PATH")
	}
	repoRoot, err := exec.Command("git", "rev-parse", "--show-toplevel").CombinedOutput()
	if err != nil {
		t.Fatalf("resolving repo root: %v (%s)", err, string(repoRoot))
	}
	root := strings.TrimSpace(string(repoRoot))

	violationPath := root + "/.scratch/mlockall_reintroduction_synthetic_test.go"
	violationSrc := "package scratch\n\nimport \"golang.org/x/sys/unix\"\n\nfunc poison() error {\n\treturn unix.Mlockall(unix.MCL_CURRENT)\n}\n"
	if err := os.WriteFile(violationPath, []byte(violationSrc), 0600); err != nil {
		t.Fatalf("writing synthetic violation file: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(violationPath) })

	// git grep only sees files git itself is aware of; -F/-l against an
	// untracked file still matches because `git grep` (unlike `git log`
	// based commands) searches the working tree by default, not just
	// committed content -- confirmed by this test actually passing below,
	// not assumed.
	matches := scanRepoForMlockall(t, root)
	found := false
	for _, m := range matches {
		if strings.HasSuffix(m, ".scratch/mlockall_reintroduction_synthetic_test.go") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("scanRepoForMlockall did not flag a deliberately reintroduced unix.Mlockall call -- "+
			"the guard above would not catch a real reintroduction either; matches seen: %v", matches)
	}
}
