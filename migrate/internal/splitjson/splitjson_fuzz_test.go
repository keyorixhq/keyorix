package splitjson

// splitjson_fuzz_test.go: FuzzSplitJSONObject drives splitjson.Object with hostile
// bytes. Object is reached from awssource/azuresource/gcpsource readSecret when
// --split-json is set, on the RAW secret VALUE read from a cloud provider — i.e. on
// attacker-controlled input at the tool's first contact with a customer. The value is
// exploded into one Keyorix secret per top-level JSON key; its field keys later feed
// cmd.sanitizeSecretName (name derivation), so a crash, a non-deterministic order, or a
// field the doc contract says cannot exist would corrupt the import plan.
//
// Oracles (what this does NOT verify is stated per oracle):
//   - O1 NO-PANIC: Object never panics on any bytes.
//   - DETERMINISM: two calls on identical input return byte-identical results, and the
//     Key order is sorted (plan idempotency, task oracle (d), depends on this). Does NOT
//     verify stability across semantically-equal-but-textually-different inputs.
//   - CONTRACT: the package doc promises every returned Field has a non-empty Key and a
//     non-empty Value, and ok==false implies a nil slice. A violation is a real DEFECT.
//     Does NOT verify the *meaning* of a value (that is the provider's).
//   - BOUNDED: output size is bounded by input size (no amplification). Does NOT verify a
//     fine-grained memory budget.

import (
	"reflect"
	"testing"
)

func FuzzSplitJSONObject(f *testing.F) {
	for _, s := range []string{
		``,
		`{}`,
		`{"a":"alice","b":"bob"}`,
		`{"":"x","k":""}`,
		`{"k":null,"j":"v"}`,
		`{"n":1,"b":true,"o":{"x":1},"arr":[1,2]}`,
		`"just a string"`,
		`[1,2,3]`,
		`{"k":"` + "\x00\r\n" + `"}`,
		`{"../../etc/passwd":"v"}`,
		`{"dup":"1","dup":"2"}`,
		`{"k":"` + string(rune(0x202e)) + `secret"}`,
		`not json at all`,
		`{"k":123456789012345678901234567890}`,
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		fields, ok := Object(string(data))

		// DETERMINISM: identical input, identical output.
		fields2, ok2 := Object(string(data))
		if ok != ok2 || !reflect.DeepEqual(fields, fields2) {
			t.Fatalf("Object not deterministic for %q: (%v,%v) vs (%v,%v)", data, fields, ok, fields2, ok2)
		}

		if !ok {
			if fields != nil {
				t.Fatalf("Object returned ok=false but non-nil fields %v for %q", fields, data)
			}
			return
		}

		var totalOut int
		prevKey := ""
		for i, fld := range fields {
			// CONTRACT: no empty key, no empty value (doc comment on Object/rawToString).
			if fld.Key == "" {
				t.Fatalf("Object returned an empty Key (index %d) for %q", i, data)
			}
			if fld.Value == "" {
				t.Fatalf("Object returned empty Value for key %q in %q", fld.Key, data)
			}
			// CONTRACT: sorted, strictly increasing keys (map keys are unique).
			if i > 0 && fld.Key <= prevKey {
				t.Fatalf("Object keys not strictly sorted: %q then %q in %q", prevKey, fld.Key, data)
			}
			prevKey = fld.Key
			totalOut += len(fld.Key) + len(fld.Value)
		}

		// BOUNDED: exploded output cannot exceed the input by more than a small constant
		// factor — no unbounded amplification. The factor is 3, not 1: encoding/json replaces
		// each invalid-UTF-8 byte in a decoded string (and map key) with U+FFFD (3 bytes), so a
		// key/value of raw 0xC2 bytes expands 1->3. That is a bounded constant expansion, not an
		// amplification bug; the 3x+64 ceiling is the correct bound (an earlier 2x+16 was a
		// miscalibrated oracle — see campaign report, ARTIFACT A1).
		if totalOut > 3*len(data)+64 {
			t.Fatalf("Object output %d bytes from %d input bytes (amplification) for %q", totalOut, len(data), data)
		}
	})
}
