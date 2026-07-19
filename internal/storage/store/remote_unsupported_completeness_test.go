package store

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// remoteUnsupportedStatus categorizes why a RemoteStorage method is still an
// unconditional remoteUnsupported(...) stub.
type remoteUnsupportedStatus int

const (
	// statusIntentional means the stub is permanent by design — verified (not
	// assumed) to have no reachable caller under storage.type: remote, or to be
	// already superseded by a different mechanism. See Reason for the specific
	// citation.
	statusIntentional remoteUnsupportedStatus = iota
	// statusKnownGap means the stub is a confirmed, currently-reachable bug —
	// something breaks under storage.type: remote today. Tracked in
	// docs/security/HARDENING-BACKLOG.md; see Reason for the finding reference.
	//
	// Round 119's entire genuine-gap list is closed as of #531, so no allowlist
	// entry currently uses this value — kept (not deleted) since the NEXT stub a
	// future round finds needs it immediately; deleting and re-adding it every
	// time the count round-trips through zero would just be churn.
	statusKnownGap //nolint:unused
)

type remoteUnsupportedEntry struct {
	status remoteUnsupportedStatus
	reason string
}

// remoteUnsupportedAllowlist is the exhaustive, reasoned inventory of every
// RemoteStorage method that still returns ErrRemoteUnsupported. Entries are
// populated via addRemoteUnsupported() called from init() functions in
// per-feature *_completeness_test.go files alongside each remote_*.go, so
// parallel feature branches never conflict on a shared registry file.
//
// The initial population lives in remote_unsupported_registry_test.go.
// New features: create remote_<feature>_completeness_test.go and call
// addRemoteUnsupported in an init() there — do NOT edit the registry file.
//
// TestRemoteUnsupportedStubsAreAllowlisted below asserts this map is an EXACT
// match against the current source: a PR that adds a new unlisted
// remoteUnsupported(...) call fails immediately; a PR that fixes a listed
// method but forgets to remove its entry also fails.
var remoteUnsupportedAllowlist = map[string]remoteUnsupportedEntry{}

// addRemoteUnsupported merges entries into remoteUnsupportedAllowlist. Called
// from init() functions in per-feature *_completeness_test.go files.
func addRemoteUnsupported(entries map[string]remoteUnsupportedEntry) {
	for k, v := range entries {
		remoteUnsupportedAllowlist[k] = v
	}
}

// remoteUnsupportedCallRe matches the exact, 100%-consistent call pattern every
// stub in this package uses: remoteUnsupported("MethodName"). Verified by hand
// against every remote_*.go file before writing this test — no stub deviates
// from this literal-string-argument form.
var remoteUnsupportedCallRe = regexp.MustCompile(`remoteUnsupported\("([A-Za-z0-9_]+)"\)`)

// actualRemoteUnsupportedStubs scans every non-test remote_*.go source file in
// this package (except remote_unsupported.go itself, which only defines the
// helper) and returns the set of method names currently implemented as an
// unconditional remoteUnsupported(...) stub.
func actualRemoteUnsupportedStubs(t *testing.T) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading internal/storage/store: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "remote_") || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") || name == "remote_unsupported.go" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		for _, m := range remoteUnsupportedCallRe.FindAllStringSubmatch(string(b), -1) {
			found[m[1]] = true
		}
	}
	return found
}

// TestRemoteUnsupportedStubsAreAllowlisted is the completeness guard: every
// RemoteStorage method that still returns ErrRemoteUnsupported must be an
// EXACT match against remoteUnsupportedAllowlist above — no more, no less.
//
//   - A method that becomes a NEW unconditional stub (or is discovered and never
//     classified) fails this test immediately, forcing the same real-caller-
//     tracing investigation this list was built from before it can be merged —
//     preventing the silent, piecemeal rediscovery this campaign has repeated
//     for ~10 rounds (#503-class, #513, #517-520, and this round-119 audit
//     that found 55 more).
//   - A method that gets FIXED (proxied for real) but whose allowlist entry is
//     forgotten also fails this test, keeping the list from accumulating stale
//     "known gap" entries that no longer reflect reality — remove the entry in
//     the same PR that lands the fix.
func TestRemoteUnsupportedStubsAreAllowlisted(t *testing.T) {
	actual := actualRemoteUnsupportedStubs(t)

	var missingFromAllowlist []string // real stub, no allowlist entry — a new/forgotten gap
	for name := range actual {
		if _, ok := remoteUnsupportedAllowlist[name]; !ok {
			missingFromAllowlist = append(missingFromAllowlist, name)
		}
	}
	sort.Strings(missingFromAllowlist)

	var staleAllowlistEntries []string // allowlisted, but no longer an actual stub — fixed and forgotten
	for name := range remoteUnsupportedAllowlist {
		if !actual[name] {
			staleAllowlistEntries = append(staleAllowlistEntries, name)
		}
	}
	sort.Strings(staleAllowlistEntries)

	if len(missingFromAllowlist) > 0 {
		t.Errorf("found %d RemoteStorage method(s) returning ErrRemoteUnsupported with NO allowlist entry "+
			"in remoteUnsupportedAllowlist (internal/storage/store/remote_unsupported_completeness_test.go): %v\n"+
			"Every remoteUnsupported(...) call site must be classified as statusIntentional (verified permanent, "+
			"with a real reason) or statusKnownGap (a real, currently-reachable bug, referencing a backlog finding) "+
			"before it can be merged — trace the method's actual internal/core caller(s) and HTTP/gRPC reachability "+
			"under storage.type: remote, don't guess.", len(missingFromAllowlist), missingFromAllowlist)
	}
	if len(staleAllowlistEntries) > 0 {
		t.Errorf("found %d remoteUnsupportedAllowlist entr(y/ies) that are no longer actual "+
			"remoteUnsupported(...) stubs (they were fixed): %v\n"+
			"Remove these entries from remoteUnsupportedAllowlist — if the fix closed a tracked backlog "+
			"finding, this test failing is your reminder to also update docs/security/BUGS.md.", len(staleAllowlistEntries), staleAllowlistEntries)
	}
}
