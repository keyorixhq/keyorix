// g80_1530_machine_actor_attribution_guard_test.go — #1530's guard: every
// audit-emitting path funnels through emitAudit (service.go), the single
// choke point that stamps MachineIdentityID from context when an event is
// actor-typed "machine_identity", and (#1626/#1628) unconditionally clears
// UserID for the same events. A call site that bypasses emitAudit and writes
// storage.LogAuditEvent directly skips BOTH corrections -- if such a site
// ever sets ActorType to "machine_identity" (or leaves it derivable from a
// machine-authenticated context) without also setting MachineIdentityID
// itself and leaving UserID unset, it silently reintroduces #1530's and
// #1626's gaps at once.
//
// Repo-wide, not internal/core-only (#1626 verification pass, 2026-08-30):
// this guard used to scan only internal/core's own directory, and its own
// doc comment claimed "there is exactly one direct storage.LogAuditEvent
// caller outside emitAudit" -- true for that one package, false for the
// repo. server/main.go's auditConnectorProjectBindingCreate is one such
// direct caller outside internal/core entirely, safe on inspection but
// invisible to the old package-scoped scan -- an enumeration is only as
// complete as the directories it looks in. (A second one,
// server/http/handlers/audit_ingest_proxy.go's IngestAuditEventProxy, was
// removed in ADR-108 Phase 6 step 14c along with the rest of the /system
// proxy tier.) Still marker-shaped, not a full AST walk (a `.LogAuditEvent(`
// substring match per function, not real parsing), but now walks every
// non-test *.go file in the repository.
//
// Inline markers, not a hand-kept list (ALLOWLIST-INLINE-NOV-1, #3687): the
// merge queue tests main + the PR together, so a guard that compares a
// hand-kept "path:func" list against a scan of the whole repo fails a PR that
// is green alone whenever another PR adds, renames or removes a site (the
// list was edited about 9 times in 2026-10-19..25 and failed the queue 5
// times). Each direct caller now carries its own justification:
//
//	// audit-direct-ok: <reason>
//
// either as a trailing comment on the call line or in the comment block that
// ends on the line directly above it (a blank line or code line breaks the
// block). A PR that adds a caller adds its marker in the same hunk; a PR that
// removes one removes the marker with it; no unrelated PR has to touch this
// file. The guard fails on (a) a direct caller with no marker, (b) a marker
// with no reason text, and (c) a stale marker that does not annotate a direct
// caller. Skipped by design, stated here so it is not mistaken for coverage:
// calls inside emitAudit itself (the funnel), calls in _test.go files, calls
// in a comment line, and a call outside any func (the scan keys on the
// enclosing func).
package guards

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// auditDirectOKMarker is the per-site justification marker.
const auditDirectOKMarker = "audit-direct-ok:"

// auditStoreAllowlistPrefix is the one subtree that may still use the
// hand-kept auditStoreAllowlist below instead of inline markers: the store
// package holds the audit write path and the audit flusher, which
// OPT-AUDIT-RT-1 owns while it is running.
const auditStoreAllowlistPrefix = "internal/storage/store/"

// auditStoreAllowlist is the small remaining hand-kept block, for direct
// LogAuditEvent callers under internal/storage/store/ ONLY (the audit write
// path and flusher). Keys are repo-root-relative "path:func".
//
// TODO(OPT-AUDIT-RT-1): move to inline markers after OPT-AUDIT-RT-1 merges,
// then delete this block and auditStoreAllowlistPrefix. It is empty today:
// no direct caller exists under the store package on main. An entry outside
// the prefix is rejected, so this cannot grow back into the old repo-wide list.
var auditStoreAllowlist = map[string]string{}

var logAuditEventFuncRe = regexp.MustCompile(`^func\s+(?:\([^)]*\)\s*)?([A-Za-z0-9_]+)\(`)

// repoRootG1626 locates the repository root relative to this file's own
// location on disk (internal/core/guards), so the guard works regardless of the
// test runner's working directory.
func repoRootG1626() string {
	thisFile := filepath.Join(srcpath.PkgDir(), "g80_1530_machine_actor_attribution_guard_test.go")
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
}

// auditDirectCall is one direct `.LogAuditEvent(` call outside emitAudit.
type auditDirectCall struct {
	key    string // repo-root-relative "path:func"
	file   string
	line   int // 1-based
	marked bool
}

// auditMarker is one `// audit-direct-ok:` comment.
type auditMarker struct {
	file   string
	line   int // 1-based
	reason string
	used   bool // annotates a direct call
}

type auditDirectScan struct {
	calls   []auditDirectCall
	markers []auditMarker
}

// callerKeys returns the "path:func" set of every direct caller.
func (s auditDirectScan) callerKeys() map[string]bool {
	keys := map[string]bool{}
	for _, c := range s.calls {
		keys[c.key] = true
	}
	return keys
}

// markerIndex returns the position of the marker in a line's trailing or
// full-line `//` comment, or -1. A `//` preceded by an odd number of `"` on
// the line sits inside a double-quoted string literal (a code generator that
// emits the marker text, for one) and is not a comment; raw (backtick)
// strings spanning lines are not tracked.
func markerIndex(line string) int {
	for from := 0; ; {
		c := strings.Index(line[from:], "//")
		if c < 0 {
			return -1
		}
		c += from
		if strings.Count(line[:c], `"`)%2 == 0 {
			m := strings.Index(line[c:], auditDirectOKMarker)
			if m < 0 {
				return -1
			}
			return c + m
		}
		from = c + 2
	}
}

// scanAuditDirectCallers scans every non-test *.go file under root for a
// `.LogAuditEvent(` call NOT inside emitAudit itself (service.go's own funnel
// implementation is the one legitimate direct caller of the storage interface
// method) and for every audit-direct-ok marker, and pairs them: a call is
// marked when the marker is a trailing comment on its line or in the
// contiguous `//` block ending on the line above it.
func scanAuditDirectCallers(t *testing.T, root string) auditDirectScan {
	t.Helper()
	var scan auditDirectScan
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "web", ".scratch", ".task", ".semgrep":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		lines := strings.Split(string(b), "\n")
		markerAt := map[int]*auditMarker{} // 0-based line -> marker
		var fileMarkers []*auditMarker
		for i, line := range lines {
			if m := markerIndex(line); m >= 0 {
				mk := &auditMarker{
					file:   rel,
					line:   i + 1,
					reason: strings.TrimSpace(line[m+len(auditDirectOKMarker):]),
				}
				markerAt[i] = mk
				fileMarkers = append(fileMarkers, mk)
			}
		}
		// findMarker: trailing marker on line i, else a marker in the
		// contiguous // block ending on line i-1.
		findMarker := func(i int) *auditMarker {
			if mk, ok := markerAt[i]; ok {
				return mk
			}
			for j := i - 1; j >= 0 && strings.HasPrefix(strings.TrimSpace(lines[j]), "//"); j-- {
				if mk, ok := markerAt[j]; ok {
					return mk
				}
			}
			return nil
		}

		currentFunc := ""
		for i, line := range lines {
			if m := logAuditEventFuncRe.FindStringSubmatch(line); m != nil {
				currentFunc = m[1]
			}
			if currentFunc == "emitAudit" {
				continue // the funnel itself, not a bypass
			}
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if strings.Contains(line, ".LogAuditEvent(") && currentFunc != "" {
				call := auditDirectCall{key: rel + ":" + currentFunc, file: rel, line: i + 1}
				if mk := findMarker(i); mk != nil {
					mk.used = true
					call.marked = true
				}
				scan.calls = append(scan.calls, call)
			}
		}
		for _, mk := range fileMarkers {
			scan.markers = append(scan.markers, *mk)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking repo for direct LogAuditEvent callers: %v", err)
	}
	return scan
}

// auditDirectVerdict turns a scan into the guard's two failure lists.
//
//   - unjustified: a direct caller with neither a marker nor an entry in the
//     store allowlist.
//   - stale: a marker without a reason, a marker that annotates no direct
//     caller, a store-allowlist entry that no longer matches a caller, or a
//     store-allowlist entry outside auditStoreAllowlistPrefix.
func auditDirectVerdict(scan auditDirectScan, storeAllowlist map[string]string) (unjustified, stale []string) {
	callers := scan.callerKeys()
	for _, c := range scan.calls {
		if c.marked {
			continue
		}
		if _, ok := storeAllowlist[c.key]; ok {
			continue
		}
		unjustified = append(unjustified, fmt.Sprintf("%s:%d (%s)", c.file, c.line, c.key))
	}
	for _, mk := range scan.markers {
		switch {
		case mk.reason == "":
			stale = append(stale, fmt.Sprintf("%s:%d marker has no reason text", mk.file, mk.line))
		case !mk.used:
			stale = append(stale, fmt.Sprintf("%s:%d marker does not sit on or directly above a direct LogAuditEvent call", mk.file, mk.line))
		}
	}
	for key := range storeAllowlist {
		switch {
		case !strings.HasPrefix(key, auditStoreAllowlistPrefix):
			stale = append(stale, key+" (store allowlist entries must be under "+auditStoreAllowlistPrefix+"; use an inline marker elsewhere)")
		case !callers[key]:
			stale = append(stale, key+" (no longer calls LogAuditEvent directly)")
		}
	}
	sort.Strings(unjustified)
	sort.Strings(stale)
	return unjustified, stale
}

// writeAuditFixture writes one fixture file under root.
func writeAuditFixture(t *testing.T, root, rel, src string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatalf("creating fixture dir: %v", err)
	}
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatalf("writing fixture %s: %v", rel, err)
	}
}

// TestDirectLogAuditEventCallersScannerDetectsBypass is this guard's
// red-proof for the scanner.
//
// TestDirectLogAuditEventCallersAreSafe has no total-collapse tripwire at
// all (unlike several sibling guards in this campaign) -- if
// logAuditEventFuncRe stopped matching, or the emitAudit exclusion or the
// "//"-comment skip became too permissive, the scan would just come back
// smaller or noisier and the verdict would report either nothing (a false
// "all safe") or unrelated staleness, never "the scanner broke."
func TestDirectLogAuditEventCallersScannerDetectsBypass(t *testing.T) {
	root := t.TempDir()
	// Line-scanned as plain text (scanAuditDirectCallers is a substring
	// scanner, not go/ast), so this fixture is never compiled either way --
	// undefined identifiers (storage, ev, ctx's type) are fine and deliberate.
	const src = `package fixture

// emitAudit is the funnel itself -- its own LogAuditEvent call must never
// be reported as a bypass.
func emitAudit(ctx context.Context) {
	storage.LogAuditEvent(ctx, ev)
}

// directBypass is the planted violation: a direct call outside emitAudit.
func directBypass(ctx context.Context) {
	storage.LogAuditEvent(ctx, ev)
}

// commentedOut's call is text inside a comment and must not be reported.
func commentedOut(ctx context.Context) {
	// storage.LogAuditEvent(ctx, ev)
}
`
	writeAuditFixture(t, root, "fixture.go", src)
	// A _test.go file with an otherwise-matching bypass must be excluded —
	// the scanner only walks non-test files, matching every real caller site.
	const testSrc = `package fixture

func shouldNotAppear(ctx context.Context) {
	storage.LogAuditEvent(ctx, ev)
}
`
	writeAuditFixture(t, root, "fixture_test.go", testSrc)

	found := scanAuditDirectCallers(t, root).callerKeys()

	if !found["fixture.go:directBypass"] {
		t.Errorf("scanAuditDirectCallers must find fixture.go:directBypass; got %v", found)
	}
	if found["fixture.go:emitAudit"] {
		t.Errorf("scanAuditDirectCallers reported emitAudit's own call as a bypass — the funnel "+
			"exclusion has stopped working, got %v", found)
	}
	if found["fixture.go:commentedOut"] {
		t.Errorf("scanAuditDirectCallers reported a commented-out call — the \"//\" skip has "+
			"stopped working, got %v", found)
	}
	if len(found) != 1 {
		t.Errorf("expected exactly 1 direct caller (fixture_test.go's shouldNotAppear must be excluded), "+
			"got %d: %v", len(found), found)
	}
}

// TestDirectLogAuditEventMarkerCalibration is the marker rules' calibration:
// every red case must produce the named failure and every green case must
// produce none, so a verdict that silently accepts everything (or rejects
// everything) fails here instead of in somebody else's merge queue.
func TestDirectLogAuditEventMarkerCalibration(t *testing.T) {
	t.Parallel()
	const (
		wantUnjustified = "unjustified"
		wantStale       = "stale"
		wantClean       = "clean"
	)
	cases := []struct {
		name      string
		files     map[string]string
		allowlist map[string]string
		want      string // wantUnjustified | wantStale | wantClean
	}{
		{
			name: "red: direct caller with no marker",
			files: map[string]string{"pkg/a.go": `package pkg

func record(ctx context.Context) {
	st.LogAuditEvent(ctx, ev)
}
`},
			want: wantUnjustified,
		},
		{
			name: "red: stale marker on a line with no direct caller",
			files: map[string]string{"pkg/a.go": `package pkg

func record(ctx context.Context) {
	// audit-direct-ok: this site used to write directly
	emitAudit(ctx, ev)
}
`},
			want: wantStale,
		},
		{
			name: "red: marker with no reason text",
			files: map[string]string{"pkg/a.go": `package pkg

func record(ctx context.Context) {
	// audit-direct-ok:
	st.LogAuditEvent(ctx, ev)
}
`},
			want: wantStale,
		},
		{
			name: "red: blank line separates the marker from the call",
			files: map[string]string{"pkg/a.go": `package pkg

func record(ctx context.Context) {
	// audit-direct-ok: system actor, never machine-typed

	st.LogAuditEvent(ctx, ev)
}
`},
			want: wantUnjustified,
		},
		{
			name: "red: code line separates the marker from the call",
			files: map[string]string{"pkg/a.go": `package pkg

func record(ctx context.Context) {
	// audit-direct-ok: system actor, never machine-typed
	x := 1
	st.LogAuditEvent(ctx, ev)
}
`},
			want: wantUnjustified,
		},
		{
			name: "red: marker above emitAudit's own call annotates nothing",
			files: map[string]string{"pkg/service.go": `package pkg

func emitAudit(ctx context.Context) {
	// audit-direct-ok: the funnel
	st.LogAuditEvent(ctx, ev)
}
`},
			want: wantStale,
		},
		{
			name: "red: marker in a _test.go file is not scanned, caller beside it still needs one",
			files: map[string]string{
				"pkg/a.go": `package pkg

func record(ctx context.Context) {
	st.LogAuditEvent(ctx, ev)
}
`,
				"pkg/a_test.go": `package pkg

// audit-direct-ok: wrong file
func helper() {}
`},
			want: wantUnjustified,
		},
		{
			name: "red: store allowlist entry outside the store prefix",
			files: map[string]string{"pkg/a.go": `package pkg

func record(ctx context.Context) {
	// audit-direct-ok: system actor
	st.LogAuditEvent(ctx, ev)
}
`},
			allowlist: map[string]string{"pkg/a.go:record": "must use a marker"},
			want:      wantStale,
		},
		{
			name: "red: store allowlist entry whose caller is gone",
			files: map[string]string{"internal/storage/store/x.go": `package store

func other() {}
`},
			allowlist: map[string]string{"internal/storage/store/x.go:flush": "gone"},
			want:      wantStale,
		},
		{
			name: "green: marker in the comment block directly above the call",
			files: map[string]string{"pkg/a.go": `package pkg

func record(ctx context.Context) {
	ev := &models.AuditEvent{ActorType: "system"}
	// audit-direct-ok: ActorType is system, never machine-typed, so
	// emitAudit's stamp would never apply (reason continues here).
	st.LogAuditEvent(ctx, ev)
}
`},
			want: wantClean,
		},
		{
			name: "green: trailing marker on the call line",
			files: map[string]string{"pkg/a.go": `package pkg

func record(ctx context.Context) {
	st.LogAuditEvent(ctx, ev) // audit-direct-ok: system actor
}
`},
			want: wantClean,
		},
		{
			name: "green: two sites in one file each carry their own marker",
			files: map[string]string{"pkg/a.go": `package pkg

func one(ctx context.Context) {
	// audit-direct-ok: first site
	st.LogAuditEvent(ctx, ev)
}

func two(ctx context.Context) {
	// audit-direct-ok: second site
	st.LogAuditEvent(ctx, ev)
}
`},
			want: wantClean,
		},
		{
			name: "green: marker text inside a string literal is not a marker (code generators emit it)",
			files: map[string]string{"gen/main.go": `package main

func emit(buf *bytes.Buffer) {
	fmt.Fprintf(buf, "%s// audit-direct-ok: emitted into generated code\n", indent)
}
`},
			want: wantClean,
		},
		{
			name: "green: emitAudit's own call needs no marker",
			files: map[string]string{"pkg/service.go": `package pkg

func emitAudit(ctx context.Context) {
	st.LogAuditEvent(ctx, ev)
}
`},
			want: wantClean,
		},
		{
			name: "green: store caller covered by the store allowlist",
			files: map[string]string{"internal/storage/store/x.go": `package store

func flush(ctx context.Context) {
	st.LogAuditEvent(ctx, ev)
}
`},
			allowlist: map[string]string{"internal/storage/store/x.go:flush": "OPT-AUDIT-RT-1"},
			want:      wantClean,
		},
		{
			name: "green: store caller may also use an inline marker",
			files: map[string]string{"internal/storage/store/x.go": `package store

func flush(ctx context.Context) {
	// audit-direct-ok: flusher writes already-attributed rows
	st.LogAuditEvent(ctx, ev)
}
`},
			want: wantClean,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			for rel, src := range tc.files {
				writeAuditFixture(t, root, rel, src)
			}
			unjustified, stale := auditDirectVerdict(scanAuditDirectCallers(t, root), tc.allowlist)
			switch tc.want {
			case wantUnjustified:
				if len(unjustified) == 0 {
					t.Errorf("expected an unjustified caller to be reported; got none (stale=%v)", stale)
				}
			case wantStale:
				if len(stale) == 0 {
					t.Errorf("expected a stale marker/entry to be reported; got none (unjustified=%v)", unjustified)
				}
			case wantClean:
				if len(unjustified) != 0 || len(stale) != 0 {
					t.Errorf("expected a clean verdict; got unjustified=%v stale=%v", unjustified, stale)
				}
			}
		})
	}
}

// TestDirectLogAuditEventCallersAreSafe is #1530's guard: every direct
// storage.LogAuditEvent caller (bypassing emitAudit's MachineIdentityID
// stamp) must carry an `// audit-direct-ok: <reason>` marker on or directly
// above the call (or, under internal/storage/store/ only, an entry in
// auditStoreAllowlist), and every marker must annotate such a caller -- a new
// bypass site is exactly how this gap would reappear, and the justification
// travels in the PR that adds the site.
func TestDirectLogAuditEventCallersAreSafe(t *testing.T) {
	t.Parallel()
	scan := scanAuditDirectCallers(t, repoRootG1626())
	unjustified, stale := auditDirectVerdict(scan, auditStoreAllowlist)

	if len(unjustified) > 0 {
		t.Errorf("%d direct storage.LogAuditEvent caller(s) bypass emitAudit's MachineIdentityID stamp with no "+
			"`// %s <reason>` marker: %v\nEither route through emitAudit instead, or add the marker on the call "+
			"line or in the comment block directly above it, explaining why this site can never emit a "+
			"machine-identity-typed event without attribution.", len(unjustified), auditDirectOKMarker, unjustified)
	}
	if len(stale) > 0 {
		t.Errorf("stale or malformed audit-direct-ok marker(s)/entries: %v\nRemove the marker -- it's either "+
			"been fixed to route through emitAudit, or the direct call was removed or moved away from it.", stale)
	}
}
