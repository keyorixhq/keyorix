package backupfmt

import (
	"encoding/json"
	"testing"
)

// FuzzManifestSignatureNeverAcceptsMismatch is SESSION-BV target 1: a
// mutated manifest or signature must never verify unless its bytes equal
// the signed original. Rather than hand-crafting byte flips (already
// exhaustively covered by TestVerifyManifestSignature_ExhaustiveSingleByteTamper),
// this differentially checks the fixed point design §5.4 implies: for ANY
// JSON that parses as a Manifest, re-signing a copy of it with the real key
// must produce a signature that verifies (correctness), and the ORIGINAL's
// own stored signature must verify if and only if it equals that freshly
// recomputed one (soundness) -- never "verified: true" for a signature that
// doesn't match the manifest's own canonical bytes under the key.
//
// This is independent of VerifyManifestSignature's own implementation (it
// doesn't just call the function under test twice and compare): SignManifest
// is the oracle, HMAC-SHA256 under a fixed key, so a bug in canonicalization
// (e.g. a map-ordering nondeterminism if a field were ever added that
// encodes as a Go map) or in the comparison (e.g. a prefix-only compare)
// shows up as this invariant breaking on some fuzzer-found input.
func FuzzManifestSignatureNeverAcceptsMismatch(f *testing.F) {
	key := testManifestKey()

	seedUnsigned := testFixtureManifest()
	seedUnsignedJSON, err := json.Marshal(seedUnsigned)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seedUnsignedJSON)

	seedSigned := testFixtureManifest()
	if err := SignManifest(&seedSigned, key); err != nil {
		f.Fatal(err)
	}
	seedSignedJSON, err := json.Marshal(seedSigned)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seedSignedJSON)

	// A signed manifest with its signature hand-corrupted -- the direct
	// "mutated signature" case the target names, expressed as a seed rather
	// than only reached by mutation.
	tampered := seedSigned
	tampered.Signature = tampered.Signature + "00"
	tamperedJSON, err := json.Marshal(tampered)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(tamperedJSON)

	f.Add([]byte("{}"))
	f.Add([]byte("not json at all"))
	f.Add([]byte(`{"format_version": 2, "signature": ""}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			t.Skip() // unparseable -- refused earlier in the real restore path (ExtractArchive's own json.Unmarshal)
		}

		resigned := m
		resigned.Signature = ""
		if err := SignManifest(&resigned, key); err != nil {
			t.Fatalf("SignManifest on a successfully-parsed manifest must not fail: %v", err)
		}
		if !VerifyManifestSignature(resigned, key) {
			t.Fatalf("a manifest freshly signed by SignManifest must verify against the same key it was signed with")
		}

		if m.Signature == "" {
			return // VerifyManifestSignature's own documented false for an absent signature; nothing more to check
		}
		if m.Signature == resigned.Signature {
			if !VerifyManifestSignature(m, key) {
				t.Fatalf("manifest's stored signature equals the canonical recomputation %q but did not verify", m.Signature)
			}
			return
		}
		if VerifyManifestSignature(m, key) {
			t.Fatalf("manifest verified with stored signature %q, but its canonical bytes under the key hash to %q -- "+
				"a mismatched signature must never verify", m.Signature, resigned.Signature)
		}
	})
}

// FuzzManifestJSONRoundTripIsStable feeds arbitrary bytes through
// Manifest's JSON decode/encode cycle and asserts it never panics,
// regardless of what auditverify.ExternalAnchorBundle or any nested struct
// field receives -- canonicalManifestBytes (the thing SignManifest/
// VerifyManifestSignature build their HMAC over) must be a total function
// of any successfully-parsed Manifest, including weird-but-valid JSON number
// forms, absent optional fields, and an attacker-supplied oversized
// Checkpoint.
func FuzzManifestJSONRoundTripIsStable(f *testing.F) {
	m := testFixtureManifest()
	data, err := json.Marshal(m)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(`{"checkpoint": {"chained_events": -1, "head_id": 0}}`))
	f.Add([]byte(`{"tables": [{}], "key_files": [{}]}`))
	f.Add([]byte(`{"created_at": "not-a-time"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			t.Skip()
		}
		b1, err := canonicalManifestBytes(m)
		if err != nil {
			t.Fatalf("canonicalManifestBytes failed on a successfully-parsed manifest: %v", err)
		}
		var reparsed Manifest
		if err := json.Unmarshal(b1, &reparsed); err != nil {
			t.Fatalf("canonicalManifestBytes produced JSON that doesn't itself parse back: %v", err)
		}
		b2, err := canonicalManifestBytes(reparsed)
		if err != nil {
			t.Fatalf("canonicalManifestBytes failed on its own re-parsed output: %v", err)
		}
		if string(b1) != string(b2) {
			t.Fatalf("canonicalManifestBytes is not a fixed point: parse->serialize->parse->serialize produced "+
				"different bytes\nfirst:  %s\nsecond: %s", b1, b2)
		}
	})
}
