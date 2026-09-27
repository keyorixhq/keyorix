// decompression_bomb_fuzz_test.go -- FUZZ-MECH M7b: bundle decompression-bomb
// bounded work. Generalizes two existing fixed-value unit tests
// (bundle_test.go's oversized-manifest/oversized-component-entry cases,
// which use writeRawBundleOversizedEntry to craft a tar header that DECLARES
// a size with NO body bytes actually present) into a fuzzed one: the
// declared size is fuzzed across the full range, for both the manifest
// entry and an ordinary component entry, and Verify must reject any
// declared size past the respective cap (maxManifestBytes / maxComponentBytes)
// WITHOUT the time or memory cost scaling with the declared value -- proving
// the check reads the tar header's Size field alone, never attempts to read
// (let alone decompress) that many bytes. This is the concrete form
// "decompression work is bounded by input size, not by an attacker-declared
// value" takes in this codebase: the compressed input here is always a few
// hundred bytes (a bare header, no body), regardless of whether the declared
// size is 1000 or 2^63-1.
//
//   - fuzzutil.Guard bounds TIME (a hang or size-proportional slowdown fails).
//   - A fixed, input-size-independent allocation ceiling (boundedBundleWorkLimit)
//     bounds MEMORY via TotalAlloc delta -- deliberately NOT scaled by the
//     fuzzed declared size, since that is exactly the value under test: an
//     amplification regression would make this scale with declaredSize, not
//     with the actual (tiny) compressed input.
//   - Whenever declaredSize exceeds the relevant cap, Verify must return a
//     non-nil error (sound: assert only the reject-when-it-should direction).
package bundleverify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"runtime"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/pkg/trust"
)

// boundedBundleWorkLimit is a fixed allocation ceiling, independent of the
// fuzzed declared size -- see the package doc comment above for why this
// must NOT scale with declaredSize. Generous headroom over what parsing a
// bare tar header (~512 bytes) plus one gzip frame legitimately costs.
const boundedBundleWorkLimit = 1 << 22 // 4 MiB

func FuzzBundleDecompressionBounded(f *testing.F) {
	f.Add(uint64(0), true)
	f.Add(uint64(maxManifestBytes), true)
	f.Add(uint64(maxManifestBytes+1), true)
	f.Add(uint64(1)<<62, true)
	f.Add(uint64(1<<63-1), true)
	f.Add(uint64(0), false)
	f.Add(uint64(maxComponentBytes), false)
	f.Add(uint64(maxComponentBytes+1), false)
	f.Add(uint64(1)<<62, false)
	f.Add(uint64(1<<63-1), false)

	f.Fuzz(func(t *testing.T, declaredSizeRaw uint64, targetManifest bool) {
		// int64 tar.Header.Size cannot be negative; mask off the sign bit
		// rather than reject the input, so every fuzzed uint64 maps to a
		// well-defined, valid-to-construct declared size.
		declaredSize := int64(declaredSizeRaw &^ (1 << 63))

		var raw []byte
		var wantCap int64
		reg := trust.NewRegistry()
		if targetManifest {
			// No valid manifest/sig at all -- the oversized entry IS the
			// manifest itself, so no signing key is needed: an oversized
			// manifest must be rejected on size alone, before any signature
			// verification could even be attempted.
			raw = writeRawBundleOversizedEntry(t, nil, nil, manifestName, declaredSize)
			wantCap = maxManifestBytes
		} else {
			// The component-size cap is only reached AFTER signature
			// verification passes, so this branch needs a genuinely valid,
			// signed manifest -- the key must be registered, or every input
			// would fail at the signature-check stage and never actually
			// exercise the component-size cap this half of the fuzzer targets.
			pub, priv, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatalf("genkey: %v", err)
			}
			dir := srcDirWith(t, map[string]string{"images/a.tar": "x"})
			m, err := BuildManifest(dir, "v1.0.0", "k1", "", time.Unix(1_700_000_000, 0))
			if err != nil {
				t.Fatalf("BuildManifest: %v", err)
			}
			sig, err := Sign(m, priv)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			manifestBytes, merr := json.Marshal(m)
			if merr != nil {
				t.Fatalf("marshal manifest: %v", merr)
			}
			if err := reg.Add(trust.PurposeUpdate, "k1", pub); err != nil {
				t.Fatalf("reg.Add: %v", err)
			}
			raw = writeRawBundleOversizedEntry(t, manifestBytes, sig, "images/a.tar", declaredSize)
			wantCap = maxComponentBytes
		}

		start := time.Now()
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		var err error
		fuzzutil.Guard(t.Fatalf, "bundle decompression-bomb", func() {
			_, err = Verify(bytes.NewReader(raw), reg)
		})
		runtime.ReadMemStats(&m1)
		elapsed := time.Since(start)

		if declaredSize > wantCap && err == nil {
			t.Fatalf("BOUNDED-WORK: Verify accepted a tar entry declaring size %d, past the cap %d", declaredSize, wantCap)
		}

		if elapsed > 3*time.Second {
			t.Fatalf("BOUNDED-WORK: Verify took %s for a declared size of %d (input itself is a few hundred bytes) — work scaling with the declared value, not the actual input", elapsed, declaredSize)
		}
		alloc := m1.TotalAlloc - m0.TotalAlloc
		if alloc > boundedBundleWorkLimit {
			t.Fatalf("BOUNDED-WORK: Verify allocated %d bytes for a declared size of %d (limit %d, input itself is a few hundred bytes) — amplification regression",
				alloc, declaredSize, boundedBundleWorkLimit)
		}
	})
}
