// Reachability-first fuzz harness for github.com/oapi-codegen/runtime/types —
// the four custom JSON/text marshal types that are reachable from a hostile
// Keyorix server's HTTP responses when the CLI and migrate tool parse them.
//
// # Reachability trace
//
// cli/internal/apiclient/types.gen.go declares several struct fields typed
// openapi_types.Email (import alias for github.com/oapi-codegen/runtime/types):
//   - line ~1933: AccessRequest.RequestedByEmail
//   - line ~2296: AccessRequest.RequestedByEmail (duplicate shape)
//   - line ~2798, ~2827, ~2861: further Email fields on response structs
//
// When a generated Parse*Response function in client.gen.go calls
//
//	json.Unmarshal(bodyBytes, &dest)
//
// and &dest contains an openapi_types.Email field, encoding/json's reflection
// loop calls (*types.Email).UnmarshalJSON(fieldBytes) — which lives in this
// library. A hostile Keyorix server controls bodyBytes entirely.
//
// Note: every runtime.StyleParamWithLocation(...) call in client.gen.go goes
// OUTBOUND (CLI → server direction) and is not attacker-controlled. The actual
// attacker-controlled entry point is exclusively the types subpackage.
//
// # What is fuzzed
//
// Raw fuzzer bytes are passed directly as the data []byte parameter of each
// UnmarshalJSON / UnmarshalText method. This covers:
//   - malformed JSON (not a valid JSON token at all) → json.Unmarshal error
//   - valid JSON but wrong type (number, array, etc.) → json.Unmarshal error
//   - valid JSON string but invalid content → library-specific error
//   - valid JSON string with valid content → success, idempotence oracle triggered
//
// # Oracles
//
//   (a) no-panic / no-hang / bounded alloc
//       Each op runs in a goroutine with recover(); a panic becomes t.Fatal.
//       A 5s per-op watchdog catches hangs. Input is capped at 64KB; larger
//       inputs are skipped (bounded allocation via input cap, not resguard,
//       because every type delegates to stdlib or has O(n)-at-most allocation).
//
//   (b) idempotence (Email and Date only)
//       When UnmarshalJSON succeeds, MarshalJSON of the result must not panic,
//       and UnmarshalJSON of that re-marshaled output must succeed and produce
//       the same value. This is a correctness property these types claim:
//       if a parsed Email round-trips to a different Email, two "equal" values
//       would compare differently on re-normalization.
//
// # What these oracles do NOT verify
//
//   - NOT that the parsed value is semantically correct (net/mail / time.Parse
//     are the arbiters; we trust the stdlib).
//   - NOT constant-time comparison properties.
//   - NOT Duration's idempotence via UnmarshalJSON→String→ParseDuration
//     (would require exposing Duration's round-trip separately; the no-panic
//     oracle is the meaningful property for the custom ISO-8601 parser here).
//   - NOT File.MarshalJSON round-trip (MarshalJSON produces a base64 JSON array
//     from the stored bytes; the reverse is a different JSON structure than the
//     input, so round-trip is not a meaningful oracle for File).
package oapiruntime

import (
	"fmt"
	"strings"
	"testing"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
)

const maxInputBytes = 64 * 1024

// runOp runs fn in a goroutine with recover(), reporting any panic via
// panicMsg. The 5s watchdog sets timedOut.
func runOp(label string, fn func() error) (err error, panicMsg string, timedOut bool) {
	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicMsg = fmt.Sprintf("PANIC in %s: %v", label, r)
			}
			close(done)
		}()
		err = fn()
	}()
	select {
	case <-done:
		return err, panicMsg, false
	case <-time.After(5 * time.Second):
		return nil, "", true
	}
}

// opResult is the pure (t-free) verdict of one runOp call, so the oracle
// logic can be exercised directly in oracle_validation_test.go.
type opResult struct {
	err      error
	panicMsg string
	timedOut bool
}

func runOpResult(label string, fn func() error) opResult {
	err, panicMsg, timedOut := runOp(label, fn)
	return opResult{err: err, panicMsg: panicMsg, timedOut: timedOut}
}

// assertOp fails t if the op panicked or timed out (oracle (a)).
func assertOp(t *testing.T, r opResult) {
	t.Helper()
	if r.timedOut {
		t.Fatal("HANG: op did not return within watchdog bound")
	}
	if r.panicMsg != "" {
		t.Fatal(r.panicMsg)
	}
}

// --- FuzzOapiRuntimeEmail ---

// longLocalPart is a JSON-encoded email with a 1024-'a' local part,
// exercising DoS-shaped inputs without encoding/json in the seed generator.
var longLocalPart = func() []byte {
	local := strings.Repeat("a", 1024)
	// Build a JSON string literal manually: '"' + content + '"'
	b := make([]byte, 0, 1+len(local)+len(`@example.com"`))
	b = append(b, '"')
	b = append(b, local...)
	b = append(b, `@example.com"`...)
	return b
}()

func FuzzOapiRuntimeEmail(f *testing.F) {
	// Seeds: valid JSON-encoded email strings, raw non-JSON bytes, edge cases.
	f.Add([]byte(`"user@example.com"`))
	f.Add([]byte(`"Display Name <user@example.com>"`))
	f.Add([]byte(`""`))
	f.Add([]byte(`"not-an-email"`))
	f.Add([]byte("not json at all"))
	f.Add([]byte(`null`))
	f.Add([]byte(`42`))
	f.Add(longLocalPart)                    // long local-part (DoS-shaped)
	f.Add([]byte{0x00, 0x01, 0x02})         // NUL bytes as raw binary input
	f.Add([]byte(`"user+test@example.com"`)) // plus-quoted local part

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxInputBytes {
			t.Skip()
		}

		// Oracle (a): UnmarshalJSON must not panic or hang.
		var e1 openapi_types.Email
		r := runOpResult("Email.UnmarshalJSON", func() error {
			return e1.UnmarshalJSON(data)
		})
		assertOp(t, r)
		if r.err != nil {
			return // parse error is fine; no idempotence check needed
		}

		// Oracle (b): MarshalJSON must not panic.
		var marshaled []byte
		rm := runOpResult("Email.MarshalJSON", func() error {
			var merr error
			marshaled, merr = e1.MarshalJSON()
			return merr
		})
		assertOp(t, rm)
		if rm.err != nil {
			// MarshalJSON can fail (e.g., if the stored email is somehow
			// unparseable by mail.ParseAddress a second time). Record but
			// don't fail — this is not a correctness violation per the type's
			// documented contract, since MarshalJSON may reject invalid values.
			t.Logf("MarshalJSON error after successful UnmarshalJSON: %v (input %q)", rm.err, data)
			return
		}

		// Oracle (b): re-UnmarshalJSON of the marshaled bytes must succeed
		// and yield the same value (idempotence).
		var e2 openapi_types.Email
		r2 := runOpResult("Email.UnmarshalJSON(remarshaled)", func() error {
			return e2.UnmarshalJSON(marshaled)
		})
		assertOp(t, r2)
		if r2.err != nil {
			t.Fatalf("IDEMPOTENCE BROKEN: Email.UnmarshalJSON succeeded on %q → marshaled %q, but re-UnmarshalJSON failed: %v",
				data, marshaled, r2.err)
		}
		if e1 != e2 {
			t.Fatalf("IDEMPOTENCE BROKEN: Email.UnmarshalJSON(%q) → %q, re-unmarshal → %q (differ)",
				data, string(e1), string(e2))
		}
	})
}

// --- FuzzOapiRuntimeDate ---

func FuzzOapiRuntimeDate(f *testing.F) {
	// Seeds: valid JSON-encoded date strings, text-format dates, edge cases.
	f.Add([]byte(`"2024-01-15"`))
	f.Add([]byte(`"2000-02-29"`))  // leap day
	f.Add([]byte(`"1970-01-01"`))  // epoch
	f.Add([]byte(`"9999-12-31"`))  // max sane year
	f.Add([]byte(`"0000-01-01"`))  // zero year
	f.Add([]byte(`"2024-00-01"`))  // month=0 out of range
	f.Add([]byte(`"2024-13-01"`))  // month=13 out of range
	f.Add([]byte(`"2024-01-00"`))  // day=0 out of range
	f.Add([]byte(`"2024-01-32"`))  // day=32 out of range
	f.Add([]byte(`"not-a-date"`))
	f.Add([]byte(`""`))
	f.Add([]byte(`null`))
	f.Add([]byte("2024-01-15"))  // raw text (for UnmarshalText path)
	f.Add([]byte("2000-02-29"))  // leap day, text
	f.Add([]byte(""))            // empty text
	f.Add([]byte("not-a-date")) // invalid text

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxInputBytes {
			t.Skip()
		}

		// Oracle (a) + (b) for UnmarshalJSON path.
		var d1 openapi_types.Date
		rj := runOpResult("Date.UnmarshalJSON", func() error {
			return d1.UnmarshalJSON(data)
		})
		assertOp(t, rj)
		if rj.err == nil {
			// Oracle (b): MarshalJSON → re-UnmarshalJSON idempotence.
			var marshaled []byte
			rm := runOpResult("Date.MarshalJSON", func() error {
				var merr error
				marshaled, merr = d1.MarshalJSON()
				return merr
			})
			assertOp(t, rm)
			if rm.err == nil {
				var d2 openapi_types.Date
				r2 := runOpResult("Date.UnmarshalJSON(remarshaled)", func() error {
					return d2.UnmarshalJSON(marshaled)
				})
				assertOp(t, r2)
				if r2.err != nil {
					t.Fatalf("IDEMPOTENCE BROKEN: Date.UnmarshalJSON succeeded on %q → marshaled %q, but re-UnmarshalJSON failed: %v",
						data, marshaled, r2.err)
				}
				if !d1.Time.Equal(d2.Time) {
					t.Fatalf("IDEMPOTENCE BROKEN: Date.UnmarshalJSON(%q) → %s, re-unmarshal → %s (differ)",
						data, d1.String(), d2.String())
				}
			}
		}

		// Oracle (a) for UnmarshalText path (independent of UnmarshalJSON).
		var d3 openapi_types.Date
		rt := runOpResult("Date.UnmarshalText", func() error {
			return d3.UnmarshalText(data)
		})
		assertOp(t, rt)
	})
}

// --- FuzzOapiRuntimeDuration ---

func FuzzOapiRuntimeDuration(f *testing.F) {
	// Seeds: valid RFC-3339 duration strings (JSON and text), malformed variants.
	// ParseDuration expects strings starting with "P".
	f.Add([]byte(`"P1Y2M3DT4H5M6S"`)) // full duration, JSON
	f.Add([]byte(`"P2W"`))             // weeks-only, JSON
	f.Add([]byte(`"PT0S"`))            // zero duration, JSON
	f.Add([]byte(`"P1Y"`))             // year only, JSON
	f.Add([]byte(`"PT1.5S"`))          // fractional seconds, JSON
	f.Add([]byte(`"PT0.5S"`))          // fractional seconds at boundary
	f.Add([]byte(`"P2W3D"`))           // weeks + days (invalid per grammar), JSON
	f.Add([]byte(`"P"`))               // P with no component, JSON
	f.Add([]byte(`"not-a-duration"`))
	f.Add([]byte(`""`))
	f.Add([]byte(`null`))
	f.Add([]byte("P1Y2M3DT4H5M6S")) // text format
	f.Add([]byte("PT1H30M"))         // text: 1h30m
	f.Add([]byte("P2W"))             // text: weeks-only
	f.Add([]byte("PT0S"))            // text: zero
	f.Add([]byte(""))                // empty text
	f.Add([]byte("PTTTTT"))          // multiple T, invalid

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxInputBytes {
			t.Skip()
		}

		// Oracle (a): UnmarshalJSON must not panic or hang.
		var dur1 openapi_types.Duration
		rj := runOpResult("Duration.UnmarshalJSON", func() error {
			return dur1.UnmarshalJSON(data)
		})
		assertOp(t, rj)

		// Oracle (a): UnmarshalText must not panic or hang (independent).
		var dur2 openapi_types.Duration
		rt := runOpResult("Duration.UnmarshalText", func() error {
			return dur2.UnmarshalText(data)
		})
		assertOp(t, rt)
	})
}

// --- FuzzOapiRuntimeFile ---

func FuzzOapiRuntimeFile(f *testing.F) {
	// Seeds: various binary blobs, JSON arrays (which is what MarshalJSON produces),
	// JSON nulls, objects, strings.
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`[72,101,108,108,111]`)) // "Hello" as byte array
	f.Add([]byte(`"not an array"`))
	f.Add([]byte(`{}`))
	f.Add([]byte{0x00, 0x01, 0x02, 0x03}) // raw binary
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxInputBytes {
			t.Skip()
		}

		// Oracle (a): UnmarshalJSON must not panic or hang.
		var file openapi_types.File
		r := runOpResult("File.UnmarshalJSON", func() error {
			return file.UnmarshalJSON(data)
		})
		assertOp(t, r)
	})
}
