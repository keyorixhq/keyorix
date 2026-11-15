// single_file_allowlist_guard_test.go — GUARD-COLLISION-NOV-1 item 3. Makes the
// "one hand-kept allowlist, compared with a scan of the whole repo, edited by many
// PRs" class visible (flake class #3687, #4237): the merge queue tests main and the
// PR together, so when guard A compares a shared list with a scan, a PR that adds,
// renames or removes a scanned site breaks every other PR in the same merge group.
//
// The cure is one file per entry (a `<name>.d/` directory) or a marker at the site,
// so each PR edits only its own line. This guard fails when a NEW shared list of
// that shape appears without one:
//
//   - a flat data file named *exempt*, *exception(s)*, *allowlist* or *waiver(s)*
//     (.tsv or .txt) outside a `*.d/` fragment directory, and
//   - a non-empty package-level allowlist map literal in a guard test under
//     internal/core/guards (the empty literals the registries keep on purpose are
//     fine).
//
// The existing ones are frozen in the two legacy lists below. The check is
// one-directional on purpose: a legacy entry whose file is gone does NOT fail, so
// the PR that converts one cannot collide with another PR through this list (that
// would be the bug this guard exists to stop). Shrink the lists when you convert
// an entry; never add to them: a new list gets a per-entry layout, see
// internal/core/guards/testdata/errtext_classification_exceptions.d/README.md.
//
// What it does not catch: a list kept under another name, in another extension, or
// as a Go map outside internal/core/guards. It is a tripwire for the common shapes,
// not a proof that no shared list exists.
package guards

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// singleFileAllowlistReason is what the failure tells the author to do.
const singleFileAllowlistReason = "a shared allowlist compared with a repo scan fails the merge queue for PRs that are " +
	"green alone: give each entry its own file under a <name>.d/ directory (loader rejects a name that does not " +
	"match the key) or a marker comment at the site; do not add to the legacy lists in single_file_allowlist_guard_test.go"

// legacyFlatAllowlistFiles are the flat data files that predate the guard
// (repo-root-relative, slash-separated). Frozen: only ever shrinks.
var legacyFlatAllowlistFiles = map[string]bool{
	"docs/atomicity-exempt.tsv":                                 true,
	"docs/besteffort-exempt.tsv":                                true,
	"docs/check-then-act-lock-exempt.reviewed.tsv":              true,
	"docs/check-then-act-lock-exempt.tsv":                       true,
	"docs/child-parent-liveness-exempt.tsv":                     true,
	"docs/full-row-write-exempt.tsv":                            true,
	"docs/security/egress-allowlist.tsv":                        true,
	"internal/docsdrift/testdata/code_path_refs_exceptions.txt": true,
	"internal/docsdrift/testdata/demo_cli_exemptions.tsv":       true,
	"internal/docsdrift/testdata/doc_cli_exemptions.tsv":        true,
	"internal/statemap/testdata/test_tempdir_allowlist.txt":     true,
	"internal/testutil/sqlitetest/driver_import_allowlist.tsv":  true,
	"scripts/fuzzing/invariant-map/allowlist.txt":               true,
	"scripts/release/docs-version-exceptions.txt":               true,
}

// legacyGuardAllowlistMaps are the non-empty allowlist map literals in guard
// tests that predate the guard ("file.go:varName"). Frozen: only ever shrinks.
var legacyGuardAllowlistMaps = map[string]bool{
	"actor_kind_literal_completeness_test.go:actorKindLiteralAllowlist":                 true,
	"audit_walk_racing_purge_guard_test.go:allowedPlainAuditWalkSites":                  true,
	"audit_writer_recover_guard_test.go:auditWriterRecoverExempt":                       true,
	"authorize_before_target_lookup_guard_test.go:targetLookupBeforeAuthorizeAllowlist": true,
	"exempt_ledger_review_test.go:exemptLedgers":                                        true,
	"named_source_files_guard_test.go:namedFileAllowlist":                               true,
	"notify_recipients_guard_test.go:listProjectMembersAllowed":                         true,
	"project_membership_definition_guard_test.go:journalReadAllowedCallers":             true,
	"second_factor_clearer_callers_guard_test.go:allowedSecondFactorClearerSites":       true,
	"secret_ownership_guard_test.go:ownerIDMutationAllowlist":                           true,
	"share_list_cap_guard_test.go:shareListCapExempt":                                   true,
}

var flatAllowlistNameRe = regexp.MustCompile(`(?i)(^|[-_.])(exempt|exemptions?|exceptions?|allowlist|waivers?)([-_.].*)?\.(tsv|txt)$`)

// nonEmptyAllowlistMapRe matches `var xAllowlist = map[K]V{` with the opening brace
// at the end of the line, i.e. a literal that has entries on the following lines.
var nonEmptyAllowlistMapRe = regexp.MustCompile(`^var\s+(\w*(?i:allow|exempt|exception|waiver)\w*)\s*=\s*map\[[^\]]+\][^{]*\{\s*$`)

// scanSingleFileAllowlists returns the flat allowlist data files and the non-empty
// guard allowlist maps found under root, as sorted keys.
func scanSingleFileAllowlists(t *testing.T, root string) (files, maps []string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			name := d.Name()
			switch {
			case name == ".git", name == "node_modules", name == ".scratch", name == ".task", name == ".semgrep", rel == "web":
				return filepath.SkipDir
			case strings.HasSuffix(name, ".d"):
				return filepath.SkipDir // a fragment directory is the cure, not the disease
			}
			return nil
		}
		if flatAllowlistNameRe.MatchString(d.Name()) {
			files = append(files, rel)
		}
		// This file's own legacy lists are the frozen baseline, not a finding.
		if strings.HasPrefix(rel, "internal/core/guards/") && strings.HasSuffix(rel, "_test.go") &&
			!strings.Contains(strings.TrimPrefix(rel, "internal/core/guards/"), "/") &&
			d.Name() != "single_file_allowlist_guard_test.go" {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(string(b), "\n") {
				if m := nonEmptyAllowlistMapRe.FindStringSubmatch(line); m != nil {
					maps = append(maps, d.Name()+":"+m[1])
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s for shared allowlists: %v", root, err)
	}
	sort.Strings(files)
	sort.Strings(maps)
	return files, maps
}

// newSingleFileAllowlists returns the found entries that are not in the legacy list.
func newSingleFileAllowlists(found []string, legacy map[string]bool) []string {
	var out []string
	for _, k := range found {
		if !legacy[k] {
			out = append(out, k)
		}
	}
	return out
}

// TestNoNewSingleFileAllowlist fails when a new shared allowlist of the #3687 shape
// is added without a per-entry layout.
func TestNoNewSingleFileAllowlist(t *testing.T) {
	t.Parallel()
	files, maps := scanSingleFileAllowlists(t, srcpath.RepoRoot())
	if bad := newSingleFileAllowlists(files, legacyFlatAllowlistFiles); len(bad) > 0 {
		t.Errorf("new flat allowlist data file(s) %v: %s", bad, singleFileAllowlistReason)
	}
	if bad := newSingleFileAllowlists(maps, legacyGuardAllowlistMaps); len(bad) > 0 {
		t.Errorf("new non-empty allowlist map(s) %v: %s", bad, singleFileAllowlistReason)
	}
}

// TestSingleFileAllowlistScannerCalibration is the scanner's red/green proof, so a
// scanner that matches nothing (or everything) fails here, not silently.
func TestSingleFileAllowlistScannerCalibration(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeAuditFixture(t, root, "docs/new-thing-exempt.tsv", "k\tv\n")                                                                                                                            // red: flat ledger
	writeAuditFixture(t, root, "pkg/testdata/known_exceptions.txt", "k\n")                                                                                                                       // red: flat list
	writeAuditFixture(t, root, "docs/other-exempt.d/one.tsv", "k\tv\n")                                                                                                                          // green: fragment dir
	writeAuditFixture(t, root, "docs/permission-matrix.tsv", "k\tv\n")                                                                                                                           // green: not an allowlist name
	writeAuditFixture(t, root, "web/src/exempt.txt", "ignored\n")                                                                                                                                // green: web is skipped
	writeAuditFixture(t, root, "internal/core/guards/x_guard_test.go", "package guards\n\nvar fooAllowlist = map[string]string{\n\t\"a\": \"r\",\n}\nvar barExceptions = map[string]string{}\n") // red: fooAllowlist only
	files, maps := scanSingleFileAllowlists(t, root)
	if got := strings.Join(files, ","); got != "docs/new-thing-exempt.tsv,pkg/testdata/known_exceptions.txt" {
		t.Errorf("flat files = %q; want the two non-fragment allowlist-named files", got)
	}
	if got := strings.Join(maps, ","); got != "x_guard_test.go:fooAllowlist" {
		t.Errorf("maps = %q; want only the non-empty fooAllowlist (the empty barExceptions literal is allowed)", got)
	}
	if bad := newSingleFileAllowlists(files, map[string]bool{"docs/new-thing-exempt.tsv": true}); len(bad) != 1 {
		t.Errorf("legacy-listed file must be skipped and the other reported, got %v", bad)
	}
	if bad := newSingleFileAllowlists(files, map[string]bool{"gone/removed.tsv": true}); len(bad) != 2 {
		t.Errorf("a legacy entry whose file is gone must not mask or fail anything, got %v", bad)
	}
}
