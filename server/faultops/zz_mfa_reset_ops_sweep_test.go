package faultops

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

const (
	// mfaResetSweepManifestPath lists every (op, storage method, call, fault kind) the
	// sweep runs. TestMFAResetOpsFaultSweep fails before sweeping if the derived list
	// differs, so an input cannot silently drop out of the sweep.
	mfaResetSweepManifestPath = "testdata/mfa_reset_sweep_manifest.txt"
	// mfaResetSweepManifestUpdateEnv set to 1 rewrites the manifest instead of checking
	// it. Use it only for a change that is meant to alter what the ops call in storage.
	mfaResetSweepManifestUpdateEnv = "KEYORIX_UPDATE_MFA_SWEEP_MANIFEST"
)

// buildMFAResetSweepWorlds is the reference and faulted world pair of the sweep and of
// its reuse gate. See keepEncryptionAcrossResets for why the key service is kept.
func buildMFAResetSweepWorlds(t *testing.T) (ref, w *faultWorld) {
	t.Helper()
	ref = buildReusableFaultWorld(t, nil)
	ref.keepEncryptionAcrossResets(t)
	w = buildReusableFaultWorld(t, nil)
	w.keepEncryptionAcrossResets(t)
	return ref, w
}

// mfaResetSweepInputs runs op key once unfaulted in w and returns one fuzz input per
// (called storage method, call 1..min(count, 5), fault kind).
func mfaResetSweepInputs(t *testing.T, w *faultWorld, key string) [][]byte {
	t.Helper()
	opIdx := slices.IndexFunc(opCatalog, func(o operation) bool { return o.Key == key })
	if opIdx < 0 || opIdx > 255 {
		t.Fatalf("op %q not addressable by one fuzz byte (index %d)", key, opIdx)
	}
	counts := probeExecuteCalls(t, w, opCatalog[opIdx])
	if len(counts) == 0 {
		t.Fatalf("op %q: the unfaulted run called no storage method", key)
	}
	var inputs [][]byte
	for mi, name := range storageInterfaceMethodNames() {
		n := min(counts[name], 5)
		for nth := 1; nth <= n; nth++ {
			for kind := range 3 {
				inputs = append(inputs, []byte{byte(opIdx), byte(mi >> 8), byte(mi), byte(nth - 1), byte(kind)})
			}
		}
	}
	return inputs
}

// mfaResetSweepManifestRows names each input as the iteration body decodes it. Method
// names rather than the raw bytes, because a method's index moves whenever the storage
// interface gains a method.
func mfaResetSweepManifestRows(t *testing.T, inputs [][]byte) []string {
	t.Helper()
	rows := make([]string, 0, len(inputs))
	for _, data := range inputs {
		d, ok := decodeFuzzOpAny(data)
		if !ok {
			t.Fatalf("input %x does not decode", data)
		}
		rows = append(rows, fmt.Sprintf("%s\t%s\t%d\t%s", opCatalog[d.opIndex].Key, d.methodName, d.nthCall, d.kind))
	}
	slices.Sort(rows)
	return rows
}

// checkMFAResetSweepManifest compares rows with the committed manifest and fails with
// the difference. It reports true when it rewrote the manifest, so nothing was checked.
func checkMFAResetSweepManifest(t *testing.T, rows []string) (updated bool) {
	t.Helper()
	if os.Getenv(mfaResetSweepManifestUpdateEnv) == "1" {
		if err := os.WriteFile(mfaResetSweepManifestPath, []byte(strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
		t.Logf("%s rewritten with %d rows", mfaResetSweepManifestPath, len(rows))
		return true
	}
	data, err := os.ReadFile(mfaResetSweepManifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	want := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	var missing, extra []string
	for _, r := range want {
		if !slices.Contains(rows, r) {
			missing = append(missing, r)
		}
	}
	for _, r := range rows {
		if !slices.Contains(want, r) {
			extra = append(extra, r)
		}
	}
	if len(rows) != len(want) || len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("the sweep would run %d inputs, the manifest lists %d.\nmissing from the sweep:\n%s\nnot in the manifest:\n%s\n"+
			"If the op's storage calls changed on purpose, run this test with %s=1 and review the manifest diff.",
			len(rows), len(want), strings.Join(missing, "\n"), strings.Join(extra, "\n"), mfaResetSweepManifestUpdateEnv)
	}
	t.Logf("manifest: %d inputs, identical to %s", len(rows), mfaResetSweepManifestPath)
	return false
}

// TestMFAResetOpsFaultSweep is TestSCIMOpsFaultSweep for mfaResetOps (oracle (g)
// and the fuzzer's other oracles): each op is run once unfaulted to learn which
// storage methods Execute calls and how often, then every (method, call 1..5,
// fault kind) is injected through the fuzzer's own iteration body.
func TestMFAResetOpsFaultSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("exhaustive sweep; run without -short")
	}
	ref, w := buildMFAResetSweepWorlds(t)
	inputsByOp := make([][][]byte, len(mfaResetOps))
	var all [][]byte
	for i, key := range mfaResetOps {
		inputsByOp[i] = mfaResetSweepInputs(t, w, key)
		all = append(all, inputsByOp[i]...)
	}
	if checkMFAResetSweepManifest(t, mfaResetSweepManifestRows(t, all)) {
		t.Skip("manifest rewritten, sweep not run")
	}
	for i, key := range mfaResetOps {
		fired, total := 0, 0
		for _, data := range inputsByOp[i] {
			total++
			t.Run(fmt.Sprintf("%s/%x", key, data), func(t *testing.T) {
				runOneFuzzIterationWithWorlds(t, data, ref, w, func(oracleInput) { fired++ })
			})
		}
		if fired == 0 {
			t.Fatalf("op %q: none of the %d probed inputs fired a fault, the sweep checks nothing", key, total)
		}
		t.Logf("SWEEP %s: %d of %d probed inputs fired a fault and were checked by the oracles", key, fired, total)
	}
}
