// remote_storage_importer_allowlist_test.go — PR 14 prep (docs/cli-split-inventory.md §10):
// RemoteStorage and the whole /system proxy tier it talks to are scheduled for deletion. This
// guard keeps the blast radius from growing while that deletion is pending: it fails the build
// the moment a NEW non-test file outside this package starts referencing store.RemoteStorage /
// store.NewRemoteStorage, so nobody builds fresh functionality on top of a type already
// scheduled for removal. The allowlist below is every current real reference, found by a
// repo-wide grep (`store\.RemoteStorage\b|store\.NewRemoteStorage\b`) — deliberately package-
// qualified: from outside package store, Go has no other syntactically valid way to name this
// type or constructor (no dot-import is used anywhere in this repo), so this pattern has no
// false negatives for a genuine new external caller. It also, deliberately, has no false
// positives on the many internal/core/*.go doc comments that discuss "RemoteStorage" in prose
// (security reasoning about storage.type: remote) without an actual package-qualified reference
// — a bare-word sweep would flag dozens of those and drown the real signal.
package store

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// remoteStorageImporterAllowlist is every non-test file, outside this package, that references
// store.RemoteStorage/store.NewRemoteStorage today. Must only shrink toward PR 14, never grow.
var remoteStorageImporterAllowlist = map[string]string{
	"internal/storage/factory.go":                     "production wiring: CreateStorage's \"remote\" case constructs store.NewRemoteStorage. Deleted in PR 14's storage/store step, alongside remote_*.go.",
	"scripts/analysis/remote_storage_stub_rewrite.go": "one-off dev tool (//go:build ignore, never compiled by `go build ./...`) used during the G80 full-classification pass to mechanically rewrite dead RemoteStorage method bodies into stubs. Its job is done; a candidate for deletion in the same wave as remote_*.go, not before.",
}

var remoteStorageQualifiedRefRe = regexp.MustCompile(`\bstore\.(NewRemoteStorage|RemoteStorage)\b`)

// remoteStorageMentioned is deliberately broader than remoteStorageQualifiedRefRe -- used only
// to verify the (small, hand-vetted) allowlist itself hasn't gone stale, never for the repo-wide
// sweep. A plain substring check, not a \b-bounded regex: "RemoteStorage" is itself a suffix of
// "NewRemoteStorage" with no word boundary between "New" and "Remote" (both are letters), so a
// \bRemoteStorage\b regex would silently miss factory.go's own "store.NewRemoteStorage" call --
// confirmed by this test failing red against exactly that file before switching to Contains.
// scripts/analysis/remote_storage_stub_rewrite.go separately needs this looser check because it
// matches "RemoteStorage" as an AST identifier string, not a package-qualified Go reference (it
// doesn't import package store at all).
func remoteStorageMentioned(data []byte) bool {
	return strings.Contains(string(data), "RemoteStorage")
}

func remoteStorageGuardRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller must resolve this test file's path")
	}
	// this file lives at internal/storage/store/remote_storage_importer_allowlist_test.go
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// skipDirs are subtrees this sweep never descends into: VCS metadata, the frontend (a different
// language entirely), and vendored/generated trees with no bearing on a Go import guard.
var remoteStorageSweepSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "web": true, ".scratch": true,
}

// TestNoNewRemoteStorageImportersOutsideAllowlist is the guard itself: every .go file in the
// repo except this package's own files and _test.go files anywhere must not package-qualify-
// reference RemoteStorage unless it's in the allowlist above.
func TestNoNewRemoteStorageImportersOutsideAllowlist(t *testing.T) {
	root := remoteStorageGuardRepoRoot(t)
	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if remoteStorageSweepSkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "internal/storage/store/") {
			return nil // this package's own non-test files (remote_*.go itself) are expected to reference RemoteStorage.
		}
		if _, ok := remoteStorageImporterAllowlist[rel]; ok {
			return nil
		}
		data, err := os.ReadFile(path) // #nosec G304 -- repo-relative path from a controlled filepath.Walk, not user/network input
		if err != nil {
			return err
		}
		if remoteStorageQualifiedRefRe.Match(data) {
			offenders = append(offenders, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	for _, o := range offenders {
		t.Errorf("new RemoteStorage reference outside the allowlist: %s -- add it to remoteStorageImporterAllowlist with a reason if this is genuinely intentional (the allowlist should only shrink toward PR 14, never grow)", o)
	}
}

// TestRemoteStorageAllowlistEntriesStillExistAndStillReference guards the allowlist itself
// against staleness in both directions: an entry for a file that no longer exists, or that no
// longer actually references RemoteStorage, would silently widen what the guard above accepts
// without anyone noticing -- matching this repo's other allowlist-with-reasoning sweeps
// (server/http/permission_sweep_test.go's TestPermissionSweepAllowlistEntriesStillExist).
func TestRemoteStorageAllowlistEntriesStillExistAndStillReference(t *testing.T) {
	root := remoteStorageGuardRepoRoot(t)
	for rel, reason := range remoteStorageImporterAllowlist {
		if reason == "" {
			t.Errorf("allowlist entry %q has no reason", rel)
		}
		data, err := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- fixed allowlist keys, not user/network input
		if err != nil {
			t.Errorf("allowlist entry %q: %v", rel, err)
			continue
		}
		if !remoteStorageMentioned(data) {
			t.Errorf("allowlist entry %q no longer references RemoteStorage -- remove it (the guard should shrink toward PR 14)", rel)
		}
	}
}
