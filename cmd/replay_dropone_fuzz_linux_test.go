//go:build linux

package cmd

// FuzzReplayDropOneSweep is the continuous explorer behind the deterministic
// DRP1 sweep (TestDRP1ReplayDamageSweep). Where the sweep enumerates every
// (input x damage) cell once, this fuzz target keeps re-exercising that space
// (and, via libFuzzer's byte-level mutation of the two inputs, nearby cells) over
// the committed unsynced fixture, which carries a rich non-OK verdict set
// (Clock/Network CRIT; Hardening/KernelSec/VMware WARN).
//
// It differs from DD2's FuzzCaptureReplayMutationRobustness in two deliberate
// ways that make it the drop-one SIBLING hunt rather than the original:
//   - It damages the FULL recorded-input set INCLUDING the source.Cached()
//     derived-state namespace (clock/state, net/connectivity, ...) that DD2's
//     blobList excludes. That namespace is where the DD3 recording-gap fix does
//     NOT reach on a TRUNCATE/CORRUPT (the blob is present, no gap is counted,
//     Result.NotRecorded stays false), so a parsed-empty healthy default can
//     flip a baseline non-OK check to OK — the sibling class.
//   - Its damage classes are the DRP1 boundary/corruption set (empty, first
//     line, mid-line, last byte, last line, whitespace, garbage line, drop blob,
//     drop index entry), all strictly information-destroying.
//
// ORACLE (identical in spirit to DD2's): no panic, bounded wall-clock, and no
// baseline non-OK check may read OK after damage (it may stay non-OK or degrade
// to Unverified/not_recorded). Soundness: every class only removes or blanks
// recorded bytes (garbage = non-alphanumeric only), so a non-OK->OK flip is a
// genuine fail-open, never harness-fed valid data.

import (
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
)

func FuzzReplayDropOneSweep(f *testing.F) {
	dd2CapParallelism()

	b0, err := loadBundle(dd2MutationFixture())
	if err != nil {
		f.Fatalf("loading fixture: %v", err)
	}
	baseDir := f.TempDir()
	if err := b0.Save(baseDir); err != nil {
		f.Fatalf("saving baseline: %v", err)
	}
	baseTree, err := readTree(baseDir)
	if err != nil {
		f.Fatalf("reading baseline tree: %v", err)
	}
	blobs := drp1AllBlobs(baseTree)
	if len(blobs) == 0 {
		f.Fatalf("positive control: no blobs to damage")
	}
	// Protect the PROBLEM states (WARN/CRIT/ERROR) per the DRP1 spec — a baseline
	// INFO (advisory / already-unverified note) is neither OK nor a problem verdict,
	// and an INFO->OK change when its source is removed is usually an
	// EXPECTED-DIFFERENCE (see TestDRP1ReplayDamageSweep's INFO observations), not a
	// fail-open; including it would make the fuzz oracle fire on benign advisories.
	baselineProtected := map[string]string{}
	for name, status := range dd2BaselineNonOK(f, baseDir) {
		if status == "WARN" || status == "CRIT" || status == "ERROR" {
			baselineProtected[name] = status
		}
	}
	if len(baselineProtected) == 0 {
		f.Fatalf("positive control: no WARN/CRIT/ERROR baseline check — oracle vacuous")
	}

	// Seed corpus: every damage class on the first blob, plus the two strongest
	// info-removal classes (empty=0, drop-blob=7) on a stride of blobs, plus the
	// cached derived-state blobs (the sibling-bug locus) with empty+drop. Keeps
	// the committed corpus small; the fuzzer explores the rest.
	cachedSet := drp1CachedBlobSet(baseTree)
	seeded := map[[2]int]bool{}
	add := func(bi, class int) {
		k := [2]int{bi, class}
		if !seeded[k] {
			seeded[k] = true
			f.Add(uint16(bi), uint8(class))
		}
	}
	for _, cl := range drp1Classes {
		add(0, cl.id)
	}
	stride := len(blobs)/24 + 1
	for bi := 0; bi < len(blobs); bi += stride {
		add(bi, 0)
		add(bi, 7)
	}
	for bi, blob := range blobs {
		if _, ok := cachedSet[blob]; ok {
			add(bi, 0) // truncate-to-empty: the class DD3 does not catch
			add(bi, 1) // whitespace
			add(bi, 7) // drop
		}
	}

	f.Fuzz(func(t *testing.T, selRaw uint16, classRaw uint8) {
		target := blobs[int(selRaw)%len(blobs)]
		class := int(classRaw) % len(drp1Classes)

		dir := t.TempDir()
		tree, applied := drp1ApplyDamage(baseTree, target, class)
		if !applied {
			return
		}
		if err := writeTree(dir, tree); err != nil {
			t.Fatalf("writeTree: %v", err)
		}

		var verdicts map[string]string
		var panicMsg string
		start := time.Now()
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicMsg = "panic"
					t.Fatalf("PANIC replaying damaged bundle (blob=%s class=%d): %v", target, class, r)
				}
			}()
			b, e := source.Load(dir)
			if e != nil {
				return // fail-closed load error — not a false-OK
			}
			r, i, _ := replayBundle(b, false, true, false, false)
			verdicts = verdictMap(r, i)
		}()
		if el := time.Since(start); el > mutationWorkCeiling {
			t.Fatalf("BOUNDED WORK: replay took %s (> %s) blob=%s class=%d", el, mutationWorkCeiling, target, class)
		}
		if panicMsg != "" || verdicts == nil {
			return
		}
		for name, baseStatus := range baselineProtected {
			if got, present := verdicts[name]; present && got == "OK" {
				t.Fatalf("FALSE-OK: check %q was %s on the undamaged baseline but replayed OK after damaging blob=%s class=%d — lost information must surface as unknown/not_recorded, not healthy",
					name, baseStatus, target, class)
			}
		}
	})
}
