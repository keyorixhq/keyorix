package keyfiles

// FuzzManifestRoundTrip feeds arbitrary bytes to LoadManifest — the parser of
// the key-set manifest (keyset.manifest.json, manifest.go) read at boot by
// VerifyKeySetConsistency — then re-encodes any manifest it accepts and checks
// the pair is stable. The manifest lives in the DEK directory; the package
// comment is explicit that it is NOT an authenticator (anyone who can write the
// key directory can rewrite it), so a corrupted or hand-edited manifest is
// squarely in scope, and LoadManifest must parse it safely or reject it, never
// crash.
//
// ORACLE (round-trip + determinism), for any input LoadManifest accepts:
//  1. STRUCTURAL: encodeManifest(m) written back out and re-loaded yields a
//     manifest deep-equal to m — every field the parser accepts survives a
//     serialize/parse cycle.
//  2. DETERMINISM: encoding the reloaded manifest produces byte-identical
//     output (encodeManifest uses json.Deterministic(true); boot compares and
//     rewrites manifests, so a non-deterministic encoding would churn the file
//     and defeat generation tracking).
// Plus: LoadManifest never panics on arbitrary bytes.
//
// WHAT THIS DOES NOT VERIFY:
//   - No integrity/authenticity: the manifest hashes are unkeyed; a forged
//     manifest with self-consistent hashes is a correct parse. This target does
//     not drive VerifyKeySetConsistency or compare against real key files.
//   - It does not assert the accept/reject BOUNDARY is correct (which exact
//     malformed inputs are rejected) — only that whatever is accepted round-
//     trips and whatever is rejected does so without crashing.
//   - readKeyFile's size cap and the DEK-directory path resolution are not
//     exercised; bytes are written to a throwaway temp file.
import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func FuzzManifestRoundTrip(f *testing.F) {
	f.Add([]byte(`{"format":1,"generation":1,"files":{}}`))
	f.Add([]byte(`{"format":1,"generation":2,"files":{"dek":{"sha256":"` +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		`","generation":2,"operation":"rotate-dek"}}}`))
	f.Add([]byte(`{"format":1,"generation":3,"files":{},"next":{"generation":4,"operation":"rotate-kek","files":{"dek":"` +
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" + `"}}}`))
	f.Add([]byte(`{"format":2,"files":{}}`)) // wrong format — rejected
	f.Add([]byte(`{"format":1}`))            // no files section — rejected
	f.Add([]byte(`{"format":1,"files":{"x":{"sha256":"short"}}}`))
	f.Add([]byte(`not json`))
	f.Add([]byte{})
	// A multi-file manifest, so the determinism check exercises map-key ordering.
	f.Add([]byte(`{"format":1,"generation":5,"files":{` +
		`"dek":{"sha256":"1111111111111111111111111111111111111111111111111111111111111111","generation":5,"operation":"rotate-dek"},` +
		`"provider":{"sha256":"2222222222222222222222222222222222222222222222222222222222222222","generation":4,"operation":"migrate-provider"},` +
		`"kek":{"sha256":"3333333333333333333333333333333333333333333333333333333333333333","generation":3,"operation":"rotate-kek"}}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "keyset.manifest.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skipf("could not write fixture: %v", err)
		}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("LoadManifest panicked on %q: %v", data, r)
			}
		}()

		m, err := LoadManifest(path)
		if err != nil {
			return // malformed manifest rejected — the safe outcome
		}

		enc, err := encodeManifest(m)
		if err != nil {
			t.Fatalf("encodeManifest failed for a manifest LoadManifest accepted (%q): %v", data, err)
		}

		path2 := filepath.Join(dir, "reencoded.manifest.json")
		if err := os.WriteFile(path2, enc, 0o600); err != nil {
			t.Skipf("could not write re-encoded fixture: %v", err)
		}
		m2, err := LoadManifest(path2)
		if err != nil {
			t.Fatalf("re-encoded manifest %q failed to reload: %v (original input %q)", enc, err, data)
		}

		if !reflect.DeepEqual(m, m2) {
			t.Fatalf("manifest round-trip mismatch:\n input   %q\n first   %+v\n reload  %+v\n encoded %q", data, m, m2, enc)
		}

		// Determinism: encodeManifest must be byte-stable across repeated
		// encodings of an equal manifest. json.Marshal WITHOUT json.Deterministic
		// emits map entries in (randomized) iteration order, so a single
		// comparison catches that only ~1-in-4 of the time for a multi-key
		// manifest; the loop makes the property's violation reliably observable.
		for i := range 64 {
			enc2, err := encodeManifest(m2)
			if err != nil {
				t.Fatalf("encodeManifest failed on reload: %v", err)
			}
			if !bytes.Equal(enc, enc2) {
				t.Fatalf("manifest encoding is not deterministic (iter %d):\n first  %q\n second %q\n input  %q", i, enc, enc2, data)
			}
		}
	})
}
