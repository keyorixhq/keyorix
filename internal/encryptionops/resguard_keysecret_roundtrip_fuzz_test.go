package encryptionops

// SP1 target: the key-Secret manifest serializer (renderKeySecret) and its
// inverse parser (UnpackKeySecret) as a ROUND-TRIP target over actual key
// material.
//
// Reachability: `keyorix-server admin encryption key-secret` renders a DEK/salt/
// wrapped-key set to a Kubernetes Secret manifest (renderKeySecret ->
// writeKeySecret); the operator stores it, and later restores the key files with
// `… key-secret unpack` (UnpackKeySecret), which base64-decodes the manifest's
// data map back onto disk. These files ARE the key material that decrypts the
// database, so a render/unpack round-trip that corrupts or drops a byte is silent
// key loss — the strongest possible correctness property for this code.
//
// Oracle (REAL round-trip): for any set of validly-named key files with
// arbitrary byte contents, renderKeySecret -> UnpackKeySecret must (a) succeed
// (a manifest we rendered from a valid set must parse back — fail-closed in the
// wrong direction is a defect), and (b) reproduce exactly the same file name set
// with byte-identical contents. This exercises the YAML quoting/escaping of the
// names and the base64 encode/decode of the contents across every byte pattern
// the fuzzer can reach (the code quotes data values precisely because an
// unquoted all-digit base64 string would be misread — this oracle is what proves
// that defense holds for every input).
//
// Resource angle (why resguard): UnpackKeySecret WRITES the decoded files to
// disk, so the disk meter (TempDir walk) and the parser's alloc are the
// bounded-work signals. Output size is bounded by the 1 MiB manifest cap and is
// ~0.75x the manifest (base64), so this is not a decompression bomb — the
// per-byte slope on disk_bytes/alloc_bytes is the right model; a manifest that
// writes disproportionately more disk than its size would still fail it. Meters
// enabled: disk_bytes/disk_files + alloc_bytes/mallocs (per-input attributable,
// fatal); cpu/wall advisory. No net/sleep/db seam is used.
//
// What this target does NOT verify: it does not fuzz the manifest parser against
// adversarial YAML that renderKeySecret never emits (path traversal, symlink
// components and the non-empty-dir refusal are owned by UnpackKeySecret's own
// tests + securefiles); it round-trips only the file-name set and contents, not
// the fingerprint annotation or metadata; names are constrained to the
// secretKeyRE domain (what a real key file name is) — an operator cannot name a
// key file outside it, and UnpackKeySecret already refuses such names
// fail-closed. No production code is modified.

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const keySecretBudgetPath = "testdata/resguard-keysecret.json"

// sanitizeKeyName maps an arbitrary fuzz string to a valid secretKeyRE key
// (`^[-._a-zA-Z0-9]+$`, never "." / ".."), or "" if nothing valid remains. This
// keeps the round-trip inside the reachable domain (a real key file name), while
// still letting the fuzzer explore name shapes — including all-digit and
// dot/dash names, the YAML-quoting edge cases.
func sanitizeKeyName(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' || c == '.' || c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b = append(b, c)
		}
	}
	name := string(b)
	if name == "" || name == "." || name == ".." {
		return ""
	}
	if !secretKeyRE.MatchString(name) {
		return ""
	}
	return name
}

// buildValidKeySet turns up to two fuzzed (name, data) pairs into a key set with
// unique valid names and copied contents. Returns nil if no valid file remains.
func buildValidKeySet(n1 string, d1 []byte, n2 string, d2 []byte) []keySetFile {
	var files []keySetFile
	seen := map[string]bool{}
	add := func(name string, data []byte) {
		k := sanitizeKeyName(name)
		if k == "" || seen[k] {
			return
		}
		seen[k] = true
		files = append(files, keySetFile{key: k, data: slices.Clone(data)})
	}
	add(n1, d1)
	add(n2, d2)
	return files
}

// unpackIntoFreshDir writes manifest to a fresh empty dir via UnpackKeySecret and
// returns the dir (so the caller can read the files back) and the error.
func unpackIntoFreshDir(t *testing.T, manifest []byte) (string, error) {
	// A directory that does not yet exist (UnpackKeySecret mkdirs it); its parent
	// is t.TempDir(), removed per fuzz input.
	dir := filepath.Join(t.TempDir(), "unpacked")
	return dir, UnpackKeySecret("-", dir, bytes.NewReader(manifest), io.Discard)
}

// readBackFiles reads every regular file in dir into a name->bytes map.
func readBackFiles(t *testing.T, dir string) map[string][]byte {
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read unpack dir: %v", err)
	}
	got := make(map[string][]byte, len(entries))
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read back %s: %v", e.Name(), err)
		}
		got[e.Name()] = data
	}
	return got
}

// roundTripKeySet is the shared oracle: render files, unpack, and compare. It
// uses the supplied render function (the real renderKeySecret for the fuzzer, a
// deliberately-broken copy for the RED proof) and returns a violation string or
// "". probe/budget may be nil (the red/green test passes nil).
func roundTripKeySet(t *testing.T, files []keySetFile, render func([]keySetFile) []byte) string {
	// Snapshot the wanted contents BEFORE render (defensive against any wipe).
	want := make(map[string][]byte, len(files))
	for _, f := range files {
		want[f.key] = slices.Clone(f.data)
	}

	manifest := render(files)
	dir, err := unpackIntoFreshDir(t, manifest)
	if err != nil {
		return "rendered manifest failed to unpack: " + err.Error()
	}
	got := readBackFiles(t, dir)

	if len(got) != len(want) {
		return "file count changed: wrote " + itoa(len(want)) + ", unpacked " + itoa(len(got))
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			return "file dropped across round-trip: " + name
		}
		if !bytes.Equal(g, w) {
			return "contents changed across round-trip for file " + name
		}
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// realRender renders with production renderKeySecret and fixed metadata.
func realRender(files []keySetFile) []byte {
	return renderKeySecret(KeySecretOpts{Name: "fuzz", Out: "-"}, files, "sha256:0000000000000000", "unpack")
}

// FuzzKeySecretRoundTrip drives the render/unpack round-trip, metered by
// resguard (disk + alloc).
func FuzzKeySecretRoundTrip(f *testing.F) {
	f.Add("dek.bin", []byte("0123456789abcdef0123456789abcdef"), "salt.bin", []byte("saltsaltsaltsalt"))
	f.Add("0", []byte{0xD3, 0x4D, 0x34}, "wrapped.key", []byte{}) // base64 "0000" — the all-digit edge
	f.Add("a.b-c_d", []byte{0x00, 0xff, 0x0a, 0x0d, 0x09}, "KEY", []byte("y"))
	f.Add("x", []byte("null"), "yes", []byte("true")) // YAML-magic contents/names

	probe := resguard.New(f, resguard.Options{SampleEvery: 32})
	budget, err := resguard.LoadBudget(keySecretBudgetPath)
	haveBudget := err == nil
	if !haveBudget {
		f.Logf("no committed budget at %s (run TestResguardKeySecretCalibrate with RESGUARD_CALIBRATE=1); metering without a ceiling", keySecretBudgetPath)
	} else {
		// disk_bytes/disk_files + alloc_bytes/mallocs are per-input attributable.
		budget.KeepOnly("disk_bytes", "disk_files", "alloc_bytes", "mallocs")
	}

	// Real key files are small (DEK 32 B, salt 16 B, a wrapped key a few hundred
	// B). Bound the fuzzed contents so a mutator-grown multi-hundred-KiB blob does
	// not turn every input into a large-file fsync storm on the disk-backed TMPDIR
	// (which starves the fuzz worker to ~0 exec/s under shared-host contention) —
	// the round-trip property is about byte-exactness, not volume, and is fully
	// exercised at small sizes. The large-manifest path (the 1 MiB cap) is its own
	// concern, covered by UnpackKeySecret's own size-cap tests.
	const maxFuzzFileBytes = 8 << 10 // 8 KiB per file

	f.Fuzz(func(t *testing.T, n1 string, d1 []byte, n2 string, d2 []byte) {
		if len(d1) > maxFuzzFileBytes || len(d2) > maxFuzzFileBytes {
			return
		}
		files := buildValidKeySet(n1, d1, n2, d2)
		if len(files) == 0 {
			return // no validly-named file in this input
		}

		// Snapshot want before render; render under the disk+alloc meter.
		want := make(map[string][]byte, len(files))
		for _, fl := range files {
			want[fl.key] = slices.Clone(fl.data)
		}
		manifest := realRender(files)

		dir := filepath.Join(t.TempDir(), "unpacked")
		probe.WatchDir(dir)
		var uerr error
		cost := probe.Measure(len(manifest), func() {
			fuzzutil.Guard(t.Fatalf, "UnpackKeySecret", func() {
				uerr = UnpackKeySecret("-", dir, bytes.NewReader(manifest), io.Discard)
			})
		})
		resguard.FeedCoverage(cost)
		if haveBudget {
			budget.Check(t.Fatalf, cost)
		}

		if uerr != nil {
			t.Fatalf("ROUND-TRIP: manifest rendered from a valid key set failed to unpack: %v\n  manifest=%q", uerr, manifest)
		}
		got := readBackFiles(t, dir)
		if len(got) != len(want) {
			t.Fatalf("ROUND-TRIP: file count changed: wrote %d, unpacked %d\n  manifest=%q", len(want), len(got), manifest)
		}
		for name, w := range want {
			g, ok := got[name]
			if !ok {
				t.Fatalf("ROUND-TRIP: file %q dropped\n  manifest=%q", name, manifest)
			}
			if !bytes.Equal(g, w) {
				t.Fatalf("ROUND-TRIP: contents of %q changed:\n  want=%x\n  got =%x\n  manifest=%q", name, w, g, manifest)
			}
		}
	})
}

// --- calibration -----------------------------------------------------------

func calibrateKeySecret(tb testing.TB) resguard.Budget {
	tb.Helper()
	// A representative corpus: the DEK+salt pair at realistic sizes, plus one
	// larger file set so the per-byte disk/alloc slope is calibrated against a
	// legitimately-large (but benign) manifest, not only tiny ones.
	seeds := [][]keySetFile{
		{{key: "dek.bin", data: bytes.Repeat([]byte("k"), 32)}, {key: "salt.bin", data: bytes.Repeat([]byte("s"), 16)}},
		{{key: "wrapped.key", data: bytes.Repeat([]byte{0xab}, 256)}},
		{{key: "big.bin", data: bytes.Repeat([]byte{0xcd}, 64*1024)}}, // ~64 KiB -> ~88 KiB manifest
	}
	var costs []resguard.Cost
	for i, files := range seeds {
		p := resguard.New(tb, resguard.Options{SampleEvery: 1})
		manifest := realRender(files)
		dir := filepath.Join(tb.TempDir(), "cal"+itoa(i))
		p.WatchDir(dir)
		var uerr error
		c := p.Measure(len(manifest), func() {
			uerr = UnpackKeySecret("-", dir, bytes.NewReader(manifest), io.Discard)
		})
		if uerr != nil {
			tb.Fatalf("calibration seed %d failed to unpack: %v", i, uerr)
		}
		costs = append(costs, c)
	}
	return resguard.Calibrate("keysecret_roundtrip", costs, resguard.DefaultFactor)
}

// TestResguardKeySecretCalibrate regenerates the committed budget under
// RESGUARD_CALIBRATE=1; otherwise asserts a disk budget was produced.
func TestResguardKeySecretCalibrate(t *testing.T) {
	b := calibrateKeySecret(t)
	if _, ok := b.Meters["disk_bytes"]; !ok {
		t.Fatalf("disk_bytes should be calibrated; meters=%v", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(keySecretBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", keySecretBudgetPath, b.Summary())
	}
}

// --- red/green proof -------------------------------------------------------

// brokenRender is a deliberately-defective copy of renderKeySecret that
// base64-encodes a MUTATED copy of each file's bytes (first byte flipped, or a
// zero appended when empty) — a plausible "corrupt the key material on export"
// bug. It exists ONLY in this test so the round-trip oracle is watched red (a
// guard nobody has watched fail is not a guard). Production renderKeySecret is
// unchanged.
func brokenRender(files []keySetFile) []byte {
	mutated := make([]keySetFile, len(files))
	for i, f := range files {
		d := slices.Clone(f.data)
		if len(d) == 0 {
			d = []byte{0x00}
		} else {
			d[0] ^= 0xff
		}
		mutated[i] = keySetFile{key: f.key, data: d}
	}
	return realRender(mutated)
}

// TestResguardKeySecretRoundTripRedGreen is the committed red/green proof.
//   - GREEN: a representative key set round-trips through the REAL renderer.
//   - RED: the same set through brokenRender (corrupted contents) violates the
//     oracle — the unpacked bytes differ. The guard fires.
func TestResguardKeySecretRoundTripRedGreen(t *testing.T) {
	sets := [][]keySetFile{
		{{key: "dek.bin", data: []byte("0123456789abcdef0123456789abcdef")}, {key: "salt.bin", data: []byte("saltsaltsaltsalt")}},
		{{key: "0", data: []byte{0xD3, 0x4D, 0x34}}}, // base64 "0000" — all-digit edge
		{{key: "wrapped.key", data: []byte{0x00, 0x01, 0x02, 0xff, 0xfe}}},
	}
	for _, files := range sets {
		if v := roundTripKeySet(t, files, realRender); v != "" {
			t.Fatalf("GREEN failed — real render should round-trip %v: %s", keyNames(files), v)
		}
		if v := roundTripKeySet(t, files, brokenRender); v == "" {
			t.Fatalf("RED failed — brokenRender should have violated the round-trip for %v but the oracle was silent", keyNames(files))
		}
	}
}

func keyNames(files []keySetFile) []string {
	ns := make([]string, len(files))
	for i, f := range files {
		ns[i] = f.key
	}
	return ns
}
