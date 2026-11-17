//go:build !windows

package encryption_test

// resguard_keylifecycle_crash_test.go -- FuzzKeyLifecycleCrashKeyLeak (task KL1).
//
// This EXTENDS the real-SIGKILL process-crash world used by
// FuzzProcessCrashRecovery (process_crash_recovery_*_test.go); it reuses that
// harness's fork/kill/world machinery verbatim (same package, so it calls the
// unexported pcrash* helpers directly) and adds the two things that harness does
// not do, both of which are on the KL1 oracle/meter list:
//
//  K1  No plaintext KEY MATERIAL is left in files. After a key-lifecycle
//      operation (DEK rotation, or KEK rotation == passphrase change) is
//      SIGKILLed at a random write seam and then recovered, AND a backup is
//      taken of the recovered install, no file anywhere under the install tree
//      OR inside the produced backup archive may contain, byte-for-byte, any of
//      the KEK-derived key-material values (evidence-sign key [KEK-derived],
//      audit-checkpoint key [KEK-derived], backup-manifest key [KEK-derived]).
//      All three are documented as held only in application memory and never
//      persisted, so ANY on-disk occurrence is a leak. Both the pre-rotation and
//      the post-recovery values are used as needles, so neither the retired nor
//      the freshly-minted key material may spill.
//
//  Meters. The recover-then-backup region is wrapped in a resguard Probe. The
//      disk meter (disk_bytes/disk_blocks/write_bytes, absolute mode) is the
//      load-bearing fatal meter: a crash-recovery or backup that writes an
//      unbounded amount (a runaway re-encryption loop, a duplicating sweep) is a
//      real key-lifecycle failure even when the bytes decrypt. wall and
//      goroutines are reported as ADVISORY meters only (resguard never fails an
//      input on them alone — they are noisy under a shared, oversubscribed host;
//      cross-input leaks are Drift's job, not Budget's).
//
// What this target does NOT re-verify (already covered elsewhere, not
// duplicated): the I1-I5 availability/integrity/authz/rerun oracles
// (FuzzProcessCrashRecovery), the raw-DEK-on-disk scan under in-process
// ENOSPC/EIO (FuzzFaultInjectedOperations' scanForPlaintext(dir, dek0)), and the
// per-checkpoint DEK/KEK/rewrap crash-consistency fuzzers. It adds the
// key-material leak oracle specifically under REAL SIGKILL + a post-kill backup,
// which none of those exercise.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const (
	kleakBudgetPath = "testdata/resguard-keylifecycle-crash.json"
	kleakInputLen   = 64 // the attacker input is the (op,killAt,state) tuple, not bytes; disk is judged in absolute mode
	kleakArchive    = "kl.tar.gz"
	kleakMinNeedle  = 16 // never scan for a key shorter than this (avoid trivial matches)
)

// kleakOps is the KL1 op set: the two operations that change on-disk key
// material. "rotate-kek" is Keyorix's passphrase change (the password KEK
// provider re-derives the KEK from the new passphrase), so the brief's "KEK
// rotation" and "passphrase change" are the same operation here.
var kleakOps = []pcrashOp{pcrashOps[0], pcrashOps[1]} // rotate-dek, rotate-kek

// kleakReadKeyMaterial opens the install at dir with pass and returns copies of
// the three KEK-derived key-material values (needles), or ok=false if the
// install does not open (a documented refusal after a kill — then there is no
// live key material to read, and the pre-rotation needles still guard the tree).
func kleakReadKeyMaterial(dir, pass string) (needles [][]byte, ok bool) {
	o := pcrashOpenGuarded(dir, pass)
	if o.pnc != nil || o.err != nil || o.inst == nil {
		return nil, false
	}
	defer o.inst.close()
	add := func(k []byte, _ string, present bool) {
		if present && len(k) >= kleakMinNeedle {
			needles = append(needles, append([]byte(nil), k...))
		}
	}
	add(o.inst.svc.EvidenceSignKey())
	add(o.inst.svc.AuditCheckpointKey())
	add(o.inst.svc.BackupManifestKey())
	return needles, len(needles) > 0
}

// kleakWorkingPass returns the passphrase that opens the install after the kill
// (pcrashPass, or pcrashPass2 for a completed KEK rotation), and any I1
// violation (an open that panicked or failed without a documented refusal).
func kleakWorkingPass(dir string, op pcrashOp) (pass string, opened bool, violation string) {
	passes := []string{pcrashPass}
	if op.kek {
		passes = []string{pcrashPass, pcrashPass2}
	}
	for _, p := range passes {
		o := pcrashOpenGuarded(dir, p)
		if o.pnc != nil {
			return "", false, fmt.Sprintf("K1 reopen panicked: %v", o.pnc)
		}
		if o.err != nil {
			if !pcrashExplicitOpenError(o.err) {
				return "", false, fmt.Sprintf("K1 reopen failed without a documented refusal: %v", o.err)
			}
			continue
		}
		o.inst.close()
		return p, true, ""
	}
	return "", false, "" // no passphrase opens: a documented refusal for every one (I1-ok)
}

// kleakScanTree walks every regular file under root and returns a description of
// any file whose bytes contain any needle. needleName maps a needle index to a
// label for the message.
func kleakScanTree(root string, needles [][]byte, needleName func(int) string) []string {
	var hits []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		data, rerr := os.ReadFile(path) //nolint:gosec // test-generated tree
		if rerr != nil {
			return nil
		}
		for i, n := range needles {
			if bytes.Contains(data, n) {
				rel, _ := filepath.Rel(root, path)
				hits = append(hits, fmt.Sprintf("%s in %s", needleName(i), rel))
			}
		}
		return nil
	})
	return hits
}

// kleakScanArchive decompresses a gzip-tar backup archive and returns any entry
// whose content contains a needle. The archive legitimately carries the WRAPPED
// dek.key and the (non-secret) kek.salt; neither equals a raw derived key, so a
// hit here is a genuine leak of key material into a backup.
func kleakScanArchive(archivePath string, needles [][]byte, needleName func(int) string) []string {
	f, err := os.Open(archivePath) //nolint:gosec // test-generated path
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil
	}
	defer func() { _ = gz.Close() }()
	var hits []string
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			return hits
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			continue
		}
		for i, n := range needles {
			if bytes.Contains(data, n) {
				hits = append(hits, fmt.Sprintf("%s in archive entry %s", needleName(i), h.Name))
			}
		}
	}
}

// kleakRun is one full iteration: copy the template, add state, kill the op,
// (measured) recover + back up, then scan for leaked key material. plant, when
// set, runs inside the install after recovery and is used only by the red-proof.
func kleakRun(t *testing.T, w *pcrashWorld, probe *resguard.Probe, budget resguard.Budget, haveBudget bool,
	op pcrashOp, killAt int64, stateRaw uint16, plant func(dir string)) ([]string, resguard.Cost) {
	t.Helper()
	dir := t.TempDir()
	if err := pcrashCopyTree(w.dir, dir); err != nil {
		t.Fatalf("copy template: %v", err)
	}
	if _, err := w.prepare(dir, stateRaw); err != nil {
		t.Fatalf("prepare: %v", err)
	}

	// Pre-rotation key material: always readable from the pristine copy.
	preNeedles, ok := kleakReadKeyMaterial(dir, pcrashPass)
	if !ok {
		t.Fatalf("harness: could not read pre-rotation key material")
	}

	run, err := op.run(dir, pcrashPass, killAt)
	if err != nil {
		t.Fatalf("run %s: %v", op.name, err)
	}
	pcrashRecordStat("kleak-"+op.name, killAt, run)
	if !run.killed && run.exit != 0 {
		return []string{fmt.Sprintf("the operation failed without being killed (exit %d): %s", run.exit, pcrashTail(run.output))}, resguard.Cost{}
	}

	var (
		violations  []string
		postNeedles [][]byte
		backupOK    bool
	)
	probe.WatchDir(dir) // the disk meter watches THIS install's tree (archive + staging growth)
	cost := probe.Measure(kleakInputLen, func() {
		pass, opened, v := kleakWorkingPass(dir, op)
		if v != "" {
			violations = append(violations, v)
			return
		}
		if !opened {
			// Every passphrase was refused with a documented error: I1-ok, and
			// there is no recovered install to back up. The pre-rotation needles
			// still guard the tree below.
			return
		}
		if pn, ok := kleakReadKeyMaterial(dir, pass); ok {
			postNeedles = pn
		}
		b, err := runPCrashChild(dir, pass, "admin",
			[]string{"backup", "--config", "./keyorix.yaml", "--output", "./" + kleakArchive}, 0)
		if err != nil {
			violations = append(violations, "backup child failed to start: "+err.Error())
			return
		}
		if b.panicked() {
			violations = append(violations, "backup after a killed "+op.name+" panicked: "+pcrashTail(b.output))
			return
		}
		backupOK = b.exit == 0
		if !backupOK {
			t.Logf("outcome: backup refused after killed %s at %s: %s", op.name, run.label, pcrashTail(b.output))
		}
	})
	if len(violations) > 0 {
		return violations, cost
	}
	if plant != nil {
		plant(dir)
	}

	// K1: scan for any leaked key material (pre + post).
	needles := append(append([][]byte(nil), preNeedles...), postNeedles...)
	name := func(i int) string {
		if i < len(preNeedles) {
			return fmt.Sprintf("pre-rotation key-material #%d", i)
		}
		return fmt.Sprintf("post-recovery key-material #%d", i-len(preNeedles))
	}
	if hits := kleakScanTree(dir, needles, name); len(hits) > 0 {
		violations = append(violations, "K1 PLAINTEXT KEY MATERIAL on disk: "+strings.Join(hits, "; "))
	}
	if backupOK {
		if hits := kleakScanArchive(filepath.Join(dir, kleakArchive), needles, name); len(hits) > 0 {
			violations = append(violations, "K1 PLAINTEXT KEY MATERIAL in backup archive: "+strings.Join(hits, "; "))
		}
	}

	// Meters: disk is fatal (absolute), wall/goroutines advisory.
	if haveBudget {
		var meter []string
		budget.Check(func(format string, args ...any) { meter = append(meter, fmt.Sprintf(format, args...)) }, cost)
		if len(meter) > 0 {
			violations = append(violations, "METER "+strings.Join(meter, "; "))
		}
	}
	resguard.FeedCoverage(cost)
	t.Logf("meters: op=%s killAt=%d wall=%s goroutines=%d disk_bytes=%d backupOK=%v",
		op.name, killAt, cost.Wall, cost.Goroutines, cost.DiskBytes, backupOK)
	return violations, cost
}

// kleakCalibrate derives the disk budget from the SAME recover-then-backup
// region the fuzz target measures, driven over a REPRESENTATIVE corpus: both
// ops, killed mid-rotation and past the last seam, at a couple of states. Only
// disk_bytes (net TempDir tree growth == the backup archive size) is kept, in
// absolute mode: the archive is bounded by the install, not by any fuzz input
// (the RSG2 decompression lesson), so the per-byte slope is the wrong model, and
// a runaway recovery/backup shows up as a flat multiple of that ceiling.
// write_bytes and disk_blocks are deliberately NOT kept: they are block-layer
// write traffic (SQLite WAL/fsync during RecoverInterruptedRotation rewriting
// existing files), which is noisy and not a net-growth / runaway signal --
// calibrating on clean rotations alone made that meter false-positive 3x on a
// legitimate mid-KEK-rotation recovery (observed, 2026-11-16), which is exactly
// why only net-growth disk_bytes is load-bearing here.
func kleakCalibrate(t *testing.T, w *pcrashWorld) resguard.Budget {
	t.Helper()
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	var costs []resguard.Cost
	for _, op := range kleakOps {
		cal := w.calibrate(t, op)
		for _, frac := range []int64{2, 1, 0} { // seams/2, seams, past-last
			killAt := cal.seams + 1
			if frac > 0 {
				killAt = max(cal.seams/frac, 1)
			}
			v, cost := kleakRun(t, w, probe, resguard.Budget{}, false, op, killAt, uint16(killAt), nil)
			if len(v) > 0 {
				t.Fatalf("calibration run reported a real violation (op=%s killAt=%d): %s", op.name, killAt, strings.Join(v, "; "))
			}
			costs = append(costs, cost)
		}
	}
	b := resguard.Calibrate("keylifecycle_crash", costs, resguard.DefaultFactor)
	b.KeepOnly("disk_bytes")
	b.UseAbsolute("disk_bytes")
	return b
}

func TestResguardKeyLeakCalibrate(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real child processes")
	}
	w := pcrashWorldFor(t)
	b := kleakCalibrate(t, w)
	t.Logf("budget: %s", b.Summary())
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(kleakBudgetPath); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", kleakBudgetPath)
	}
}

// TestResguardKeyLeakRedGreen proves both oracles fire.
//   - K1: a scratch file holding the raw key-material bytes makes the tree scan
//     fire; without it the same run is clean.
//   - Meter: a 64 MiB file written inside the measured region trips the absolute
//     disk ceiling; the benign run does not.
func TestResguardKeyLeakRedGreen(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real child processes")
	}
	w := pcrashWorldFor(t)
	b := kleakCalibrate(t, w)
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	cal := w.calibrate(t, kleakOps[0])

	// GREEN: benign killed rotation, no plant.
	if v, _ := kleakRun(t, w, probe, b, true, kleakOps[0], cal.seams, 7, nil); len(v) > 0 {
		t.Fatalf("GREEN run reported violations: %v", v)
	}

	// RED (K1): plant the real key material into a scratch file in the tree.
	plantKey := func(dir string) {
		needles, ok := kleakReadKeyMaterial(dir, pcrashPass)
		if !ok || len(needles) == 0 {
			t.Fatalf("red-proof: could not read key material to plant")
		}
		if err := os.WriteFile(filepath.Join(dir, "LEAKED.scratch"), needles[0], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	v, _ := kleakRun(t, w, probe, b, true, kleakOps[0], cal.seams, 11, plantKey)
	if !kleakHas(v, "K1 PLAINTEXT KEY MATERIAL on disk") {
		t.Fatalf("RED(K1) did not fire; violations=%v", v)
	}

	// RED (meter): blow the disk inside the measured region.
	red := kleakMeterRedProof(t, w, probe, b)
	if !kleakHas(red, "METER") {
		t.Fatalf("RED(meter) did not fire; violations=%v", red)
	}
}

// kleakMeterRedProof writes a 64 MiB file inside the measured region (a stand-in
// for a runaway recovery/backup) and returns the violations, which must name the
// disk meter.
func kleakMeterRedProof(t *testing.T, w *pcrashWorld, probe *resguard.Probe, b resguard.Budget) []string {
	t.Helper()
	dir := t.TempDir()
	if err := pcrashCopyTree(w.dir, dir); err != nil {
		t.Fatalf("copy template: %v", err)
	}
	probe.WatchDir(dir)
	cost := probe.Measure(kleakInputLen, func() {
		big := make([]byte, 64<<20)
		if err := os.WriteFile(filepath.Join(dir, "runaway.bin"), big, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	var meter []string
	b.Check(func(format string, args ...any) { meter = append(meter, fmt.Sprintf(format, args...)) }, cost)
	if len(meter) == 0 {
		return nil
	}
	return []string{"METER " + strings.Join(meter, "; ")}
}

func kleakHas(violations []string, substr string) bool {
	for _, v := range violations {
		if strings.Contains(v, substr) {
			return true
		}
	}
	return false
}

func FuzzKeyLifecycleCrashKeyLeak(f *testing.F) {
	for i := range len(kleakOps) {
		f.Add(uint8(i), uint16(3), uint16(i)*5)
		f.Add(uint8(i), uint16(1), uint16(i)*9)
	}
	w := pcrashWorldFor(f)
	budget, lerr := resguard.LoadBudget(kleakBudgetPath)
	haveBudget := lerr == nil
	probe := resguard.New(f, resguard.Options{SampleEvery: 8})
	f.Fuzz(func(t *testing.T, opRaw uint8, killRaw, stateRaw uint16) {
		op := kleakOps[int(opRaw)%len(kleakOps)]
		cal := w.calibrate(t, op)
		killAt := 1 + int64(killRaw)%(cal.seams+1)
		if v, _ := kleakRun(t, w, probe, budget, haveBudget, op, killAt, stateRaw, nil); len(v) > 0 {
			t.Fatalf("op=%s killAt=%d state=%d (of %d seams): %s", op.name, killAt, stateRaw, cal.seams, strings.Join(v, "; "))
		}
	})
}
