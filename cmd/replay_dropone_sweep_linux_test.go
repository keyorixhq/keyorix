//go:build linux

package cmd

// DRP1 — deterministic, EXHAUSTIVE replay drop/truncate/corrupt sweep.
//
// This is the drop-one sibling hunt for the DD3 recording-gap false-OK. Where the
// DD2 harness SAMPLES a bounded, rotating subset of (blob, mutation) cases and the
// DD2 fuzz target explores RANDOMLY, this sweep is DETERMINISTIC and EXHAUSTIVE: it
// enumerates EVERY recorded input of a bundle (every file blob, every command
// blob, every derived-cache blob, and every index entry) crossed with EVERY damage
// class, with no sampling, and replays each damaged bundle through the full
// `dsd replay` pipeline (source.Load -> replayBundle -> render).
//
// Damage classes (the three groups the DRP1 remit names):
//   DROP-ONE  : drop the blob+its index entry (recording gap); drop the index entry
//               only (orphaned blob).
//   TRUNCATE  : cut a blob at each boundary class — empty, first line only, mid-line,
//               last byte removed, last line removed.
//   CORRUPT   : replace a blob with empty, with whitespace, with one garbage line
//               (garbage = only non-alphanumeric bytes, so it can never form a
//               parseable record — the DD2 soundness guarantee, inherited).
//
// ORACLE (per damaged replay):
//   - NO PANIC.
//   - BOUNDED WORK (resource oracle): wall-clock AND heap allocation per case stay
//     under a loose blow-up ceiling. Meters enabled: time (hang/accumulation
//     backstop) and allocation (memory-blow-up backstop). Disk is bounded by the
//     bundle size; the Replay source performs NO network and NO sleep (every probe
//     is served from the bundle), so those meters would be vacuous and are not
//     enabled — stated for completeness.
//   - ANTI-FALSE-OK: a check that the intact baseline reported WARN/CRIT/ERROR must
//     stay non-OK or degrade to Unverified/not_recorded — it must never read OK.
//
// WHY THIS FINDS WHAT DD3 DID NOT. The runner sets Result.NotRecorded from the gap
// counter (runner.go:55). DROP makes the replay source refuse the read -> a gap ->
// NotRecorded -> DD3's ApplyThresholds fix surfaces not_recorded. But TRUNCATE and
// CORRUPT leave the blob PRESENT: the read succeeds, no gap is counted,
// NotRecorded stays false, and DD3 never fires. A collector that parses the
// emptied/garbled bytes into a healthy zero value then flips a baseline non-OK
// check to OK with no gap to catch it — the sibling class.
//
// WHAT THIS DOES NOT VERIFY: a fixture is one host at one instant, not a spec. The
// sweep proves no damage bleaches a non-OK verdict to OK on THESE bundles; it does
// not prove the baseline verdicts are correct, nor that other hosts behave the same
// (those are the env-gated captures / LEFTOVERS). It damages one input at a time;
// multi-input corruption is out of scope. It cannot protect a check the baseline
// already reports OK (no non-OK verdict there to guard).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// drp1AllocCeiling is the per-case heap-allocation blow-up backstop. Replaying a
// small in-memory bundle allocates a few MiB; a case that allocates this much is a
// blow-up (e.g. an unbounded buffer driven by garbled length bytes), not jitter.
const drp1AllocCeiling = 512 << 20 // 512 MiB

// drp1Class is one damage class. apply rewrites a COPY of the base tree in place and
// returns the rel path of the thing it damaged (for the matrix), or "" if the class
// did not apply to this target (e.g. drop-entry on a blob with no index reference).
type drp1Class struct {
	id    int
	name  string
	group string // drop | truncate | corrupt
}

var drp1Classes = []drp1Class{
	{0, "empty", "corrupt"},        // also the truncate-to-empty boundary
	{1, "whitespace", "corrupt"},   //
	{2, "garbage-line", "corrupt"}, //
	{3, "first-line", "truncate"},  //
	{4, "mid-line", "truncate"},    //
	{5, "last-byte", "truncate"},   //
	{6, "last-line", "truncate"},   //
	{7, "drop-blob", "drop"},       // remove blob + its index entry (recording gap)
	{8, "drop-entry", "drop"},      // remove index entry only (orphan the blob)
}

// drp1Whitespace replaces every byte with a space (present, no information).
func drp1Whitespace(d []byte) []byte {
	out := make([]byte, len(d))
	for i := range out {
		out[i] = ' '
	}
	return out
}

// drp1GarbageLine is a single provably-non-data line: only non-alphanumeric bytes,
// so it can never parse as "nameserver 8.8.8.8" / "MemTotal: 16 kB" / a JSON number.
func drp1GarbageLine() []byte { return []byte("\x00\x7f \t --- \x00\n") }

// drp1FirstLine keeps only the first line (through the first newline).
func drp1FirstLine(d []byte) []byte {
	if i := bytes.IndexByte(d, '\n'); i >= 0 {
		return append([]byte(nil), d[:i+1]...)
	}
	return append([]byte(nil), d...)
}

// drp1LastByte removes the final byte.
func drp1LastByte(d []byte) []byte {
	if len(d) == 0 {
		return d
	}
	return append([]byte(nil), d[:len(d)-1]...)
}

// drp1LastLine removes the final line (everything after the last interior newline),
// including a sole line (-> empty).
func drp1LastLine(d []byte) []byte {
	t := d
	if len(t) > 0 && t[len(t)-1] == '\n' {
		t = t[:len(t)-1] // drop a trailing newline so we remove the real last line
	}
	if i := bytes.LastIndexByte(t, '\n'); i >= 0 {
		return append([]byte(nil), t[:i+1]...)
	}
	return []byte{}
}

// drp1MidLine cuts at the midpoint.
func drp1MidLine(d []byte) []byte { return append([]byte(nil), d[:len(d)/2]...) }

// drp1ByteDamage applies a byte-level class (0..6) to blob bytes.
func drp1ByteDamage(class int, d []byte) []byte {
	switch class {
	case 0:
		return []byte{}
	case 1:
		return drp1Whitespace(d)
	case 2:
		return drp1GarbageLine()
	case 3:
		return drp1FirstLine(d)
	case 4:
		return drp1MidLine(d)
	case 5:
		return drp1LastByte(d)
	case 6:
		return drp1LastLine(d)
	}
	return d
}

// drp1IndexNameFor returns the index.json that references a blob rel path.
func drp1IndexNameFor(blobRel string) string {
	if strings.HasPrefix(blobRel, "commands/blobs/") {
		return "commands/index.json"
	}
	return "files/index.json"
}

// drp1ApplyDamage builds a damaged COPY of baseTree for (target blob, class) and
// returns the new tree. For drop classes it rewrites the index; for byte classes it
// rewrites the blob bytes. Returns (tree, applied) — applied is false when the class
// could not touch the target (e.g. drop-entry found no referencing entry).
func drp1ApplyDamage(baseTree map[string][]byte, target string, class int) (map[string][]byte, bool) {
	tree := make(map[string][]byte, len(baseTree))
	for k, v := range baseTree {
		tree[k] = v
	}
	switch class {
	case 7: // drop blob + index entry
		idxName := drp1IndexNameFor(target)
		if idx, ok := tree[idxName]; ok {
			if newIdx, dropped := dropFromIndex(idx, target); dropped {
				tree[idxName] = newIdx
				delete(tree, target)
				return tree, true
			}
		}
		return tree, false
	case 8: // drop index entry only (orphan the blob)
		idxName := drp1IndexNameFor(target)
		if idx, ok := tree[idxName]; ok {
			if newIdx, dropped := dropFromIndex(idx, target); dropped {
				tree[idxName] = newIdx
				return tree, true
			}
		}
		return tree, false
	default: // byte-level damage 0..6
		tree[target] = drp1ByteDamage(class, baseTree[target])
		return tree, true
	}
}

// drp1AllBlobs returns EVERY file and command blob — INCLUDING the derived-cache
// namespace that DD2's blobList excludes (the DRP1 remit names "each cached key").
func drp1AllBlobs(tree map[string][]byte) []string {
	var blobs []string
	for rel := range tree {
		if strings.HasPrefix(rel, "files/blobs/") || strings.HasPrefix(rel, "commands/blobs/") {
			blobs = append(blobs, rel)
		}
	}
	sort.Strings(blobs)
	return blobs
}

// drp1BlobIsCached reports whether a blob is in the source.Cached() namespace (its
// files/index.json path starts with the cached sentinel). Used only to LABEL the
// matrix (cache-derived vs raw input), never to exclude.
func drp1CachedBlobSet(tree map[string][]byte) map[string]string {
	out := map[string]string{}
	idx, ok := tree["files/index.json"]
	if !ok {
		return out
	}
	var entries []map[string]any
	if json.Unmarshal(idx, &entries) != nil {
		return out
	}
	for _, e := range entries {
		path, _ := e["path"].(string)
		blob, _ := e["blob"].(string)
		if blob != "" && strings.HasPrefix(path, cacheKeyPrefixSentinel) {
			out[blob] = strings.TrimPrefix(path, cacheKeyPrefixSentinel)
		}
	}
	return out
}

// drp1DamageInPlace applies (target, class) to an already-materialized bundle dir
// by touching only the one or two files involved, and returns a restore func that
// puts the original bytes back. This avoids rewriting the whole 100s-of-files tree
// per case (the dominant cost of a naive sweep). Safe because replays are serial
// (the active source is process-global). Returns applied=false when the class does
// not touch this target (e.g. drop-entry with no referencing index entry).
func drp1DamageInPlace(dir string, baseTree map[string][]byte, target string, class int) (restore func(), applied bool) {
	full := filepath.Join(dir, filepath.FromSlash(target))
	switch class {
	case 7, 8: // structural: rewrite index (+ remove blob for drop-blob)
		idxName := drp1IndexNameFor(target)
		idxOrig, ok := baseTree[idxName]
		if !ok {
			return func() {}, false
		}
		newIdx, dropped := dropFromIndex(idxOrig, target)
		if !dropped {
			return func() {}, false
		}
		idxFull := filepath.Join(dir, filepath.FromSlash(idxName))
		_ = os.WriteFile(idxFull, newIdx, 0o600)
		if class == 7 {
			_ = os.Remove(full)
		}
		return func() {
			_ = os.WriteFile(idxFull, idxOrig, 0o600)
			if class == 7 {
				_ = os.WriteFile(full, baseTree[target], 0o600)
			}
		}, true
	default: // byte-level 0..6
		_ = os.WriteFile(full, drp1ByteDamage(class, baseTree[target]), 0o600)
		return func() { _ = os.WriteFile(full, baseTree[target], 0o600) }, true
	}
}

// drp1Replay loads a damaged on-disk tree and returns its verdict map + whether it
// panicked, recovering any panic so the sweep can report rather than crash.
func drp1Replay(dir string) (verdicts map[string]string, panicMsg string, loadErr error) {
	defer func() {
		if r := recover(); r != nil {
			panicMsg = fmt.Sprintf("%v", r)
		}
	}()
	b, err := source.Load(dir)
	if err != nil {
		return nil, "", err
	}
	results, insights, _ := replayBundle(b, false, true, false, false)
	return verdictMap(results, insights), "", nil
}

// drp1Case is one (target, class) cell of the matrix for one fixture.
type drp1Case struct {
	target, label string
	class         int
	className     string
	cached        bool
	cacheKey      string
}

// drp1Cases enumerates the full exhaustive case list for a base tree.
func drp1Cases(baseTree map[string][]byte) []drp1Case {
	blobs := drp1AllBlobs(baseTree)
	cachedSet := drp1CachedBlobSet(baseTree)
	var cases []drp1Case
	for _, blob := range blobs {
		ck, isCached := cachedSet[blob]
		for _, cl := range drp1Classes {
			cases = append(cases, drp1Case{
				target: blob, label: blob, class: cl.id, className: cl.name,
				cached: isCached, cacheKey: ck,
			})
		}
	}
	return cases
}

// drp1Protected reports whether a baseline status is one the DRP1 anti-false-OK
// oracle guards against flipping to OK. Per the task spec it is the PROBLEM states
// — WARN, CRIT, ERROR. A baseline INFO (an advisory or an already-Unverified
// couldn't-measure note) is neither OK nor a problem verdict; an INFO->OK change
// is tracked and reported for triage but is not a protected violation (losing an
// advisory when its source is removed is usually an EXPECTED-DIFFERENCE).
func drp1Protected(status string) bool {
	return status == "WARN" || status == "CRIT" || status == "ERROR"
}

// drp1Baseline replays the intact tree and returns (allVerdicts, protected subset,
// baseline INFO subset).
func drp1Baseline(t *testing.T, dir string) (all, protected, infos map[string]string) {
	t.Helper()
	v, pm, le := drp1Replay(dir)
	if pm != "" {
		t.Fatalf("baseline panicked: %s", pm)
	}
	if le != nil {
		t.Fatalf("baseline load error: %v", le)
	}
	protected = map[string]string{}
	infos = map[string]string{}
	for n, s := range v {
		switch {
		case drp1Protected(s):
			protected[n] = s
		case s == "INFO":
			infos[n] = s
		}
	}
	return v, protected, infos
}

// drp1Flip records one non-OK -> OK violation.
type drp1Flip struct {
	fixture, check, baseStatus, blob, class string
	cached                                  bool
	cacheKey                                string
}

// TestDRP1ReplayDamageSweep is the deterministic, exhaustive sweep over the two
// committed replay-fidelity fixtures. It writes the full (input x damage) matrix and
// the complete violation list to .scratch/out, hard-fails on any PANIC or
// resource-bound breach, and records every anti-false-OK flip. Flips are reported
// (and asserted by the dedicated guards once classified), not hard-failed here, so
// the matrix is always produced for triage even when a real defect is present.
func TestDRP1ReplayDamageSweep(t *testing.T) {
	dd2CapParallelism()
	out := dd2OutDir(t)

	var report strings.Builder
	fmt.Fprintf(&report, "# DRP1 deterministic exhaustive damage matrix\n\n")
	fmt.Fprintf(&report, "Two committed replay-fidelity fixtures. Classes: ")
	for i, c := range drp1Classes {
		if i > 0 {
			report.WriteString(", ")
		}
		fmt.Fprintf(&report, "%d=%s", c.id, c.name)
	}
	report.WriteString(".\n\n")

	var allFlips []drp1Flip     // protected violations across fixtures
	var allInfoFlips []drp1Flip // INFO->OK observations across fixtures
	var worstWall time.Duration
	var worstAlloc uint64
	var totalCases int

	for _, fx := range dd2CommittedFixtures(t) {
		name := baseName(fx)
		b0, err := loadBundle(fx)
		if err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
		baseDir := t.TempDir()
		if err := b0.Save(baseDir); err != nil {
			t.Fatalf("save %s: %v", name, err)
		}
		baseTree, err := readTree(baseDir)
		if err != nil {
			t.Fatalf("readTree %s: %v", name, err)
		}
		_, baselineProtected, baselineInfos := drp1Baseline(t, baseDir)
		cases := drp1Cases(baseTree)

		fmt.Fprintf(&report, "## %s\n\n", name)
		fmt.Fprintf(&report, "Blobs: %d | damage classes: %d | cases: %d | protected (WARN/CRIT/ERROR) checks: %d (%s) | baseline INFO checks: %d (%s)\n\n",
			len(drp1AllBlobs(baseTree)), len(drp1Classes), len(cases),
			len(baselineProtected), strings.Join(sortedKeys(baselineProtected), ", "),
			len(baselineInfos), strings.Join(sortedKeys(baselineInfos), ", "))

		// Materialize the base bundle ONCE; damage one or two files in place per
		// case and restore after. Replays are serial (global active source), so the
		// shared dir is race-free.
		workDir := t.TempDir()
		if err := writeTree(workDir, baseTree); err != nil {
			t.Fatalf("writeTree base: %v", err)
		}

		var fxFlips []drp1Flip   // protected (WARN/CRIT/ERROR) -> OK : hard violations
		var fxInfoFlips []drp1Flip // INFO -> OK : reported observations
		var panics, loadFails, applied int
		for _, c := range cases {
			restore, ok := drp1DamageInPlace(workDir, baseTree, c.target, c.class)
			if !ok {
				continue
			}
			applied++
			totalCases++
			var verdicts map[string]string
			var panicMsg string
			var loadErr error
			var m0, m1 runtime.MemStats
			// Allocation is sampled every 16th case: ReadMemStats is a stop-the-world
			// pause, so metering every case would itself dominate the sweep.
			meterAlloc := applied%16 == 0
			if meterAlloc {
				runtime.ReadMemStats(&m0)
			}
			start := time.Now()
			verdicts, panicMsg, loadErr = drp1Replay(workDir)
			wall := time.Since(start)
			restore()
			var alloc uint64
			if meterAlloc {
				runtime.ReadMemStats(&m1)
				alloc = m1.TotalAlloc - m0.TotalAlloc
			}
			if wall > worstWall {
				worstWall = wall
			}
			if alloc > worstAlloc {
				worstAlloc = alloc
			}
			// Resource oracle (hard).
			if wall > mutationWorkCeiling {
				t.Errorf("BOUNDED WORK (time): %s blob=%s class=%s took %s (> %s)",
					name, c.target, c.className, wall, mutationWorkCeiling)
			}
			if alloc > drp1AllocCeiling {
				t.Errorf("BOUNDED WORK (alloc): %s blob=%s class=%s allocated %d bytes (> %d)",
					name, c.target, c.className, alloc, uint64(drp1AllocCeiling))
			}
			if panicMsg != "" {
				panics++
				t.Errorf("PANIC: %s blob=%s class=%s: %s", name, c.target, c.className, panicMsg)
				continue
			}
			if loadErr != nil {
				loadFails++ // fail-closed load error is fine (not a false-OK)
				continue
			}
			// PROTECTED (WARN/CRIT/ERROR) -> OK is a hard anti-false-OK violation.
			for ck, bs := range baselineProtected {
				if got, present := verdicts[ck]; present && got == "OK" {
					f := drp1Flip{name, ck, bs, c.target, c.className, c.cached, c.cacheKey}
					fxFlips = append(fxFlips, f)
					t.Errorf("FALSE-OK: %s check %q was %s on the intact baseline but replayed OK after blob=%s class=%s (cached=%v %s) — a WARN/CRIT check must not go OK on information loss",
						name, ck, bs, c.target, c.className, c.cached, c.cacheKey)
				}
			}
			// INFO -> OK is recorded for triage, not failed (see drp1Protected).
			for ck, bs := range baselineInfos {
				if got, present := verdicts[ck]; present && got == "OK" {
					fxInfoFlips = append(fxInfoFlips, drp1Flip{name, ck, bs, c.target, c.className, c.cached, c.cacheKey})
				}
			}
		}
		allFlips = append(allFlips, fxFlips...)
		allInfoFlips = append(allInfoFlips, fxInfoFlips...)
		fmt.Fprintf(&report, "Applied cases: %d | panics: %d | load-fails: %d | PROTECTED (WARN/CRIT/ERROR)->OK violations: %d | INFO->OK observations: %d\n\n",
			applied, panics, loadFails, len(fxFlips), len(fxInfoFlips))
		writeFlipTable := func(title string, flips []drp1Flip) {
			if len(flips) == 0 {
				return
			}
			fmt.Fprintf(&report, "**%s**\n\n", title)
			report.WriteString("| check | baseline | blob | class | cached key |\n|---|---|---|---|---|\n")
			for _, f := range flips {
				ck := f.cacheKey
				if !f.cached {
					ck = "(raw input)"
				}
				fmt.Fprintf(&report, "| %s | %s | %s | %s | %s |\n", f.check, f.baseStatus, f.blob, f.class, ck)
			}
			report.WriteString("\n")
		}
		writeFlipTable("PROTECTED violations (WARN/CRIT/ERROR -> OK)", fxFlips)
		writeFlipTable("INFO -> OK observations (not protected; triaged)", fxInfoFlips)
	}

	fmt.Fprintf(&report, "## Resource meters\n\nWorst per-case wall: %s (ceiling %s). Worst per-case heap alloc: %s (ceiling %s). Total cases: %d.\n\n",
		worstWall, mutationWorkCeiling, byteCount(worstAlloc), byteCount(uint64(drp1AllocCeiling)), totalCases)

	// Group flips by (check, class, cached) to separate systematic fail-opens from one-offs.
	group := func(flips []drp1Flip) map[string]int {
		m := map[string]int{}
		for _, f := range flips {
			kind := "raw"
			if f.cached {
				kind = "cached:" + f.cacheKey
			}
			m[fmt.Sprintf("%s | class=%s | %s", f.check, f.class, kind)]++
		}
		return m
	}
	report.WriteString("## Flip summary (grouped)\n\n### PROTECTED (WARN/CRIT/ERROR -> OK)\n\n")
	protKey := group(allFlips)
	if len(protKey) == 0 {
		report.WriteString("None — no WARN/CRIT/ERROR check flipped to OK on either committed fixture across the exhaustive set.\n")
	} else {
		for _, k := range sortedMapKeys(protKey) {
			fmt.Fprintf(&report, "- %s: %d\n", k, protKey[k])
		}
	}
	report.WriteString("\n### INFO -> OK observations (not protected)\n\n")
	infoKey := group(allInfoFlips)
	if len(infoKey) == 0 {
		report.WriteString("None.\n")
	} else {
		for _, k := range sortedMapKeys(infoKey) {
			fmt.Fprintf(&report, "- %s: %d\n", k, infoKey[k])
		}
	}

	p := filepath.Join(out, "drp1-damage-matrix.md")
	if err := os.WriteFile(p, []byte(report.String()), 0o644); err != nil {
		t.Fatalf("write matrix: %v", err)
	}
	t.Logf("DRP1 matrix written: %s (%d cases, %d protected violations, %d info flips)",
		p, totalCases, len(allFlips), len(allInfoFlips))
}

func sortedKeys(m map[string]string) []string {
	var k []string
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}

func sortedMapKeys(m map[string]int) []string {
	var k []string
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}

func byteCount(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
