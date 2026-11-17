package backupfmt

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// RSG1 pilot #1: the backupfmt archive loader as a DISK + PARSER resource
// target. ExtractArchive takes attacker-controlled gzip/tar bytes and writes
// files under a staging directory. Its own byte caps bound the worst case, but
// resguard is an INDEPENDENT oracle: with generous caps passed here, a
// compressible payload that ExtractArchive would accept and write to disk still
// trips the calibrated disk/alloc budget, so an amplification that stays under
// the product cap but is wildly out of proportion to the input is caught.
//
// What this target does NOT verify: it does not re-check path-traversal or
// hash-consistency (FuzzExtractArchive and TestExtractArchive_RefusesPathTraversal
// own those); it meters resource cost only. The disk meter is the TempDir walk
// (reliable on the tmpfs TMPDIR, where /proc/self/io write_bytes reads ~0);
// alloc_bytes/mallocs are measured only on the SampleEvery cadence (one input
// in 16 here), so a one-off alloc spike on an off-cadence input is not judged,
// even when it is slow: a slow input is promoted to a live-heap sample only,
// and live_heap is not judged in the fuzz target (see FuzzResguardExtractArchive).

const (
	// Generous caps so resguard, not ExtractArchive's own cap, is the oracle.
	// Still bounded so a genuine bomb cannot exhaust the tmpfs mid-run.
	pilotCapEntry = 1 << 23 // 8 MiB
	pilotCapTotal = 1 << 24 // 16 MiB

	pilotBudgetPath = "testdata/resguard-backupfmt.json"
)

// realArchiveBytes returns a valid v2 archive (the accepted shape), mirroring
// seedRealArchive. Used as the benign calibration corpus and as the GREEN case.
func realArchiveBytes(tb testing.TB) []byte {
	tb.Helper()
	db := openTestDB(tb)
	var buf bytes.Buffer
	if _, err := writeBackupModels(db, testSeedModels(), 1, "", testManifestKey(), nil, nil, &buf); err != nil {
		tb.Fatalf("build real archive: %v", err)
	}
	return buf.Bytes()
}

// largeBenignArchiveBytes returns a LEGITIMATELY-large archive: ~1 MiB of
// low-compressibility content (input ≈ output, ratio ~1 — a real large backup,
// NOT a bomb). It is in the calibration corpus so the AbsMax ceiling reflects the
// real maximum disk a legitimate archive can produce, not just the tiny real
// archive. Without such a sample AbsMax is calibrated too small and the
// decompression FP persists (INV-RES-absmax-for-decompression, guard rail 1).
// The content is deterministic pseudo-random bytes so gzip barely shrinks it.
func largeBenignArchiveBytes(tb testing.TB) []byte {
	tb.Helper()
	payload := make([]byte, 1<<20)
	// A cheap deterministic LCG — incompressible enough that the archive stays
	// ~1 MiB, so this is a genuine ~1:1 large archive, not a hidden amplifier.
	var x uint32 = 0x9e3779b9
	for i := range payload {
		x = x*1664525 + 1013904223
		payload[i] = byte(x >> 24)
	}
	return craftArchive(tb, "tables/large.ndjson", payload)
}

func measureExtract(tb testing.TB, p *resguard.Probe, data []byte) resguard.Cost {
	tb.Helper()
	dir := tb.TempDir()
	p.WatchDir(dir)
	return p.Measure(len(data), func() {
		_, _ = ExtractArchive(bytes.NewReader(data), dir, pilotCapEntry, pilotCapTotal)
	})
}

// calibrateBackupfmt derives a budget from the benign corpus and switches the
// byte-volume disk meters to ModeAbsolute (AbsMax), the correct model for a
// decompression target (INV-RES-absmax-for-decompression). The corpus is the
// small real archive repeated (to average GC/alloc noise into p99) PLUS one
// legitimately-large benign archive, so AbsMax reflects the real maximum disk a
// benign archive produces — not just the tiny real one, which is what made RSG1's
// per-byte slope false-positive at 144×. alloc/live-heap stay on the per-byte
// slope: that IS the right model for the parser work, which does not scale with
// the decompressed output volume.
func calibrateBackupfmt(tb testing.TB) resguard.Budget {
	tb.Helper()
	real := realArchiveBytes(tb)
	var costs []resguard.Cost
	for range 8 {
		p := resguard.New(tb, resguard.Options{SampleEvery: 1})
		costs = append(costs, measureExtract(tb, p, real))
	}
	// One legitimately-large benign archive lifts the absolute disk ceiling.
	pl := resguard.New(tb, resguard.Options{SampleEvery: 1})
	costs = append(costs, measureExtract(tb, pl, largeBenignArchiveBytes(tb)))

	b := resguard.Calibrate("backupfmt_extract", costs, resguard.DefaultFactor)
	// Disk byte-volume meters are decompression-shaped: judge them by an absolute,
	// input-size-independent ceiling so a padded archive cannot buy more disk
	// budget. disk_files/dirs keep the slope (bounded by archive structure).
	b.UseAbsolute("disk_bytes", "disk_blocks", "write_bytes")
	return b
}

// TestResguardBackupfmtCalibrate regenerates the committed budget when
// RESGUARD_CALIBRATE=1; otherwise it just asserts calibration produces a disk
// and alloc budget. Deterministic (the real archive is deterministic).
func TestResguardBackupfmtCalibrate(t *testing.T) {
	b := calibrateBackupfmt(t)
	if _, ok := b.Meters["disk_bytes"]; !ok {
		t.Fatalf("disk_bytes should be calibrated; meters=%v", b.Summary())
	}
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes should be calibrated; meters=%v", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(pilotBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", pilotBudgetPath, b.Summary())
	}
}

// TestResguardBackupfmtDiskRedGreen is the committed red/green proof for the
// disk/alloc oracle. GREEN: the benign real archive passes the calibrated
// budget. RED: a tiny, highly-compressible archive that ExtractArchive accepts
// and expands to ~8 MiB on disk trips the disk budget — the amplifier is
// attacker INPUT, so no production code is modified. (A scratch-copy production
// plant was not needed because the amplification is expressible as a fuzz input.)
func TestResguardBackupfmtDiskRedGreen(t *testing.T) {
	b := calibrateBackupfmt(t)

	// GREEN
	p := resguard.New(t, resguard.Options{SampleEvery: 1})
	green := measureExtract(t, p, realArchiveBytes(t))
	var greenFired bool
	b.Check(func(string, ...any) { greenFired = true }, green)
	if greenFired {
		t.Fatalf("benign archive tripped the budget: disk=%d alloc=%d", green.DiskBytes, green.AllocBytes)
	}

	// RED: 8 MiB of a single byte compresses to a few KB; ExtractArchive writes
	// the 8 MiB back out under staging (within the 16 MiB cap we passed).
	bomb := craftArchive(t, "tables/bomb.ndjson", bytes.Repeat([]byte{'a'}, 8<<20))
	p2 := resguard.New(t, resguard.Options{SampleEvery: 1})
	red := measureExtract(t, p2, bomb)
	if red.DiskBytes < 4<<20 {
		t.Fatalf("expected the bomb to write megabytes to disk, got %d bytes (input %d bytes)", red.DiskBytes, len(bomb))
	}
	var redMsg string
	fired := b.Check(func(f string, a ...any) { redMsg = fmt.Sprintf(f, a...) }, red)
	if !fired {
		t.Fatalf("disk amplification (%d bytes on disk for a %d-byte input) did not trip the budget", red.DiskBytes, len(bomb))
	}
	t.Logf("RED tripped as expected (input %d bytes -> %d bytes on disk): %s", len(bomb), red.DiskBytes, redMsg)
}

// TestResguardBackupfmtAbsMaxRedGreen is the committed proof for RSG2's AbsMax
// conversion: the 144×-shape false positive RSG1 documented DISAPPEARS under the
// RSG2 absolute budget while the 8 MiB disk bomb still fires. The RSG2 budget
// differs from RSG1's in TWO ways, both part of "convert to AbsMax": the corpus
// gains a representative large benign archive (so any absolute ceiling is sized
// right — the dominant reason the FP goes away) AND the disk meters switch to
// ModeAbsolute (the unique added value of which — resistance to input-padding
// evasion that still defeats a slope — is isolated and proven in
// resguard.TestBudgetAbsMaxForDecompression Part C, not re-proven here).
// `calibrateBackupfmtSlopeOnly` is RSG1's exact small-corpus slope budget, used
// only to reproduce the original FP as the precondition.
func TestResguardBackupfmtAbsMaxRedGreen(t *testing.T) {
	abs := calibrateBackupfmt(t) // disk meters in ModeAbsolute

	// The same calibration corpus, but WITHOUT UseAbsolute — RSG1's per-byte slope.
	slope := calibrateBackupfmtSlopeOnly(t)

	// The 144× shape: a tiny, highly-compressible archive expanding to ~64 KiB on
	// disk — harmless (far under the 16 MiB product cap) but high-ratio.
	super := craftArchive(t, "tables/super.ndjson", bytes.Repeat([]byte{'a'}, 64<<10))
	ps := resguard.New(t, resguard.Options{SampleEvery: 1})
	superCost := measureExtract(t, ps, super)
	if superCost.DiskBytes < 32<<10 {
		t.Fatalf("expected the 144× archive to write tens of KiB, got %d (input %d)", superCost.DiskBytes, len(super))
	}

	// RED under the SLOPE (reproduces RSG1's false positive): the harmless 64 KiB
	// archive trips the per-byte disk budget calibrated where input≈output.
	if !slope.Check(func(string, ...any) {}, superCost) {
		t.Fatalf("precondition: the 144× archive must trip the SLOPE budget (that is the FP being fixed) — input %d disk %d", len(super), superCost.DiskBytes)
	}
	// GREEN under ABSOLUTE: the same input passes — the FP is gone.
	if abs.Check(func(string, ...any) {}, superCost) {
		t.Fatalf("ABSMAX: the 144×-shape archive (%d bytes on disk) must NOT trip the absolute ceiling; FP should be gone", superCost.DiskBytes)
	}

	// RED still fires for a genuine bomb under ABSOLUTE: 8 MiB on disk > AbsMax.
	bomb := craftArchive(t, "tables/bomb.ndjson", bytes.Repeat([]byte{'a'}, 8<<20))
	pb := resguard.New(t, resguard.Options{SampleEvery: 1})
	bombCost := measureExtract(t, pb, bomb)
	var bombMsg string
	if !abs.Check(func(f string, a ...any) { bombMsg = fmt.Sprintf(f, a...) }, bombCost) {
		t.Fatalf("ABSMAX: the 8 MiB bomb (input %d) must still trip the absolute ceiling", len(bomb))
	}
	t.Logf("super-ratio (input %d -> %d disk) passes abs; bomb (input %d -> %d disk) fires abs: %s",
		len(super), superCost.DiskBytes, len(bomb), bombCost.DiskBytes, bombMsg)
}

// calibrateBackupfmtSlopeOnly is calibrateBackupfmt without UseAbsolute — RSG1's
// per-byte model, used only by the red/green test to show the FP under the slope.
func calibrateBackupfmtSlopeOnly(tb testing.TB) resguard.Budget {
	tb.Helper()
	real := realArchiveBytes(tb)
	var costs []resguard.Cost
	for range 8 {
		p := resguard.New(tb, resguard.Options{SampleEvery: 1})
		costs = append(costs, measureExtract(tb, p, real))
	}
	return resguard.Calibrate("backupfmt_extract", costs, resguard.DefaultFactor)
}

// FuzzResguardExtractArchive is the pilot fuzz target: it meters every input and
// fails one whose disk/alloc cost exceeds the calibrated budget. It also feeds
// the cost buckets so the engine retains cost-raising inputs.
func FuzzResguardExtractArchive(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not gzip"))
	f.Add(realArchiveBytes(f))
	// A small, realistic (low compression-ratio) archive: a benign seed must have
	// input ~ output. A highly-compressible payload is NOT seeded here because it
	// is itself the decompression-bomb shape the disk/alloc oracle exists to flag
	// — seeding it would assert "an amplifier must pass", contradicting the guard.
	f.Add(craftArchive(f, "tables/x.ndjson", []byte(`{"id":1,"name":"alice"}`+"\n")))

	budget, err := resguard.LoadBudget(pilotBudgetPath)
	if err != nil {
		f.Fatalf("no usable committed budget at %s (regenerate with RESGUARD_CALIBRATE=1): %v", pilotBudgetPath, err)
	}
	// live_heap is the whole-process HeapAlloc after a forced GC. Under `go test
	// -fuzz` the worker also holds the engine's coverage and corpus state (~100 MiB
	// observed), so a 5-byte input reads 14x over a budget calibrated in a plain
	// test process (1.8 MiB). It is not attributable to the input here, so it is
	// not judged in this target; alloc_bytes/mallocs (per-input deltas) and the
	// disk meters still are.
	delete(budget.Meters, "live_heap")
	p := resguard.New(f, resguard.Options{SampleEvery: 16})

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		p.WatchDir(dir)
		c := p.Measure(len(data), func() {
			_, _ = ExtractArchive(bytes.NewReader(data), dir, pilotCapEntry, pilotCapTotal)
		})
		resguard.FeedCoverage(c)
		budget.Check(t.Fatalf, c)
	})
}
