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
// alloc/live-heap are sampled (SampleEvery), so a one-off alloc spike on an
// unsampled input is seen only if it was also slow.

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

func measureExtract(tb testing.TB, p *resguard.Probe, data []byte) resguard.Cost {
	tb.Helper()
	dir := tb.TempDir()
	p.WatchDir(dir)
	return p.Measure(len(data), func() {
		_, _ = ExtractArchive(bytes.NewReader(data), dir, pilotCapEntry, pilotCapTotal)
	})
}

// calibrateBackupfmt derives a budget from the benign corpus. The corpus is
// small (the real archive is the only reliably-accepted benign shape available
// in-package); the factor absorbs that, and the report names the limitation.
func calibrateBackupfmt(tb testing.TB) resguard.Budget {
	tb.Helper()
	real := realArchiveBytes(tb)
	var costs []resguard.Cost
	for range 8 { // repeat the same benign input to average GC/alloc noise into p99
		p := resguard.New(tb, resguard.Options{SampleEvery: 1})
		costs = append(costs, measureExtract(tb, p, real))
	}
	return resguard.Calibrate("backupfmt_extract", costs, resguard.DefaultFactor)
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
	haveBudget := err == nil
	if !haveBudget {
		f.Logf("no committed budget at %s (run with RESGUARD_CALIBRATE=1); metering without a ceiling", pilotBudgetPath)
	}
	p := resguard.New(f, resguard.Options{SampleEvery: 16})

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		p.WatchDir(dir)
		c := p.Measure(len(data), func() {
			_, _ = ExtractArchive(bytes.NewReader(data), dir, pilotCapEntry, pilotCapTotal)
		})
		resguard.FeedCoverage(c)
		if haveBudget {
			budget.Check(t.Fatalf, c)
		}
	})
}
