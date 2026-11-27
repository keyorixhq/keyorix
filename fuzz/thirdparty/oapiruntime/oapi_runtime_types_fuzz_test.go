// Reachability-first fuzz harness for github.com/oapi-codegen/runtime/types:
// the four custom JSON/text marshal types of the module version the root,
// cli and migrate go.mod files require (v1.9.0).
//
// # Reachability trace
//
// Only Email is reachable from shipped code. cli/internal/apiclient/types.gen.go
// declares five openapi_types.Email fields (json:"email", at lines ~1933, 2296,
// 2804, 2833 and 2867); migrate/internal/apiclient uses none. Date, Duration and
// File have no Keyorix call site: they are library-hardening targets.
//
// When a generated Parse*Response function in client.gen.go calls
//
//	json.Unmarshal(bodyBytes, &dest)
//
// and &dest contains an openapi_types.Email field, encoding/json's reflection
// loop calls (*types.Email).UnmarshalJSON(fieldBytes), which lives in this
// library. A hostile Keyorix server controls bodyBytes entirely.
//
// Note: every runtime.StyleParamWithLocation(...) call in client.gen.go goes
// OUTBOUND (CLI to server) and is not attacker-controlled.
//
// # What is fuzzed
//
// Raw fuzzer bytes are passed directly as the data []byte parameter of each
// UnmarshalJSON / UnmarshalText method (Duration and Date implement both; Email
// and File implement only the JSON methods).
//
// # Oracles
//
//	(a) no-panic / no-hang
//	    Each op runs in a goroutine with recover(); a panic becomes t.Fatal.
//	    A per-op watchdog (opWatchdog, 5s) catches hangs. Input is capped at
//	    64KB; larger inputs are skipped. This is an input cap, not a
//	    measurement of allocation.
//
//	(b) idempotence (Email and Date only)
//	    When UnmarshalJSON succeeds, MarshalJSON of the result must succeed,
//	    and UnmarshalJSON of that re-marshaled output must succeed and produce
//	    the same value. The checks live in emailRoundTripViolation and
//	    dateRoundTripViolation, which the oracle validation tests drive RED
//	    with planted marshalers.
//
// # Known upstream deviation (tolerated, pinned)
//
// Upstream (*Email).UnmarshalJSON stores the UNQUOTED local part of the parsed
// address, which its own MarshalJSON then rejects for any quoted local part
// ("a b"@example.com, "a@b"@x.com). Issue #4797. The Email oracle tolerates
// exactly that class (emailNeedsQuotedLocalPart) and
// repro_email_quoted_localpart_test.go pins the upstream behaviour, so it
// fails when upstream is fixed and the tolerance can be removed. Any other
// marshal failure after a successful unmarshal is a violation.
//
// # What these oracles do NOT verify
//
//   - NOT that the parsed value is semantically correct (net/mail / time.Parse
//     are the arbiters; we trust the stdlib).
//   - NOT constant-time comparison properties.
//   - NOT round-trip of quoted Email local parts (known upstream deviation above).
//   - NOT Duration's idempotence via UnmarshalJSON, String, ParseDuration
//     (the no-panic oracle is the meaningful property for the custom ISO-8601
//     parser here).
//   - NOT File.MarshalJSON round-trip (MarshalJSON produces a base64 JSON array
//     from the stored bytes; the reverse is a different JSON structure than the
//     input, so round-trip is not a meaningful oracle for File).
package oapiruntime

import (
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"testing"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
)

const maxInputBytes = 64 * 1024

// opWatchdog is the per-op hang bound; a var so the hang oracle can be
// validated with a short bound.
var opWatchdog = 5 * time.Second

// runOp runs fn in a goroutine with recover(), reporting any panic via
// panicMsg. The opWatchdog bound sets timedOut. The goroutine reports through
// a buffered channel and touches no variable the caller returns, so a hung op
// that finishes late cannot race with the timeout return.
func runOp(label string, fn func() error) (panicMsg string, timedOut bool, err error) {
	type result struct {
		err      error
		panicMsg string
	}
	ch := make(chan result, 1)
	go func() {
		var res result
		defer func() {
			if r := recover(); r != nil {
				res.panicMsg = fmt.Sprintf("PANIC in %s: %v", label, r)
			}
			ch <- res
		}()
		res.err = fn()
	}()
	select {
	case res := <-ch:
		return res.panicMsg, false, res.err
	case <-time.After(opWatchdog):
		return "", true, nil
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
	panicMsg, timedOut, err := runOp(label, fn)
	return opResult{err: err, panicMsg: panicMsg, timedOut: timedOut}
}

// opViolation returns the oracle (a) verdict of r: "" when the op neither hung
// nor panicked.
func opViolation(r opResult) string {
	if r.timedOut {
		return "HANG: op did not return within watchdog bound"
	}
	return r.panicMsg
}

// assertOp fails t if the op panicked or timed out (oracle (a)).
func assertOp(t *testing.T, r opResult) {
	t.Helper()
	if v := opViolation(r); v != "" {
		t.Fatal(v)
	}
}

// emailNeedsQuotedLocalPart reports whether e is the known upstream deviation
// (issue #4797): the stored value is the unquoted local part of a quoted
// address, so it either does not re-parse as written (ErrValidationEmail on
// marshal) or re-parses to a different address (" 0@0" becomes "0@0"), but
// quoting its local part yields an address that parses back to exactly e.
// Nothing else is tolerated.
func emailNeedsQuotedLocalPart(e openapi_types.Email) bool {
	s := string(e)
	if a, err := mail.ParseAddress(s); err == nil && a.Address == s {
		return false
	}
	at := strings.LastIndex(s, "@")
	if at <= 0 {
		return false
	}
	a, err := mail.ParseAddress(strconv.Quote(s[:at]) + s[at:])
	return err == nil && a.Address == s
}

// emailRoundTripViolation runs the Email oracles (a) and (b) on data and
// returns "" or a description of the violation. marshal is injected so the
// validation tests can plant a non-idempotent marshaler.
func emailRoundTripViolation(data []byte, marshal func(openapi_types.Email) ([]byte, error)) string {
	var e1 openapi_types.Email
	r := runOpResult("Email.UnmarshalJSON", func() error { return e1.UnmarshalJSON(data) })
	if v := opViolation(r); v != "" {
		return v
	}
	if r.err != nil {
		return "" // parse error is fine; no idempotence check needed
	}

	var marshaled []byte
	rm := runOpResult("Email.MarshalJSON", func() error {
		var merr error
		marshaled, merr = marshal(e1)
		return merr
	})
	if v := opViolation(rm); v != "" {
		return v
	}
	if rm.err != nil {
		if emailNeedsQuotedLocalPart(e1) {
			return "" // known upstream deviation, #4797
		}
		return fmt.Sprintf("IDEMPOTENCE BROKEN: Email.UnmarshalJSON succeeded on %q → %q, but MarshalJSON failed: %v",
			data, string(e1), rm.err)
	}

	var e2 openapi_types.Email
	r2 := runOpResult("Email.UnmarshalJSON(remarshaled)", func() error { return e2.UnmarshalJSON(marshaled) })
	if v := opViolation(r2); v != "" {
		return v
	}
	if r2.err != nil {
		return fmt.Sprintf("IDEMPOTENCE BROKEN: Email.UnmarshalJSON succeeded on %q → marshaled %q, but re-UnmarshalJSON failed: %v",
			data, marshaled, r2.err)
	}
	if e1 != e2 {
		if emailNeedsQuotedLocalPart(e1) {
			return "" // known upstream deviation, #4797
		}
		return fmt.Sprintf("IDEMPOTENCE BROKEN: Email.UnmarshalJSON(%q) → %q, re-unmarshal → %q (differ)",
			data, string(e1), string(e2))
	}
	return ""
}

// dateRoundTripViolation is the Date counterpart of emailRoundTripViolation.
func dateRoundTripViolation(data []byte, marshal func(openapi_types.Date) ([]byte, error)) string {
	var d1 openapi_types.Date
	rj := runOpResult("Date.UnmarshalJSON", func() error { return d1.UnmarshalJSON(data) })
	if v := opViolation(rj); v != "" {
		return v
	}
	if rj.err != nil {
		return ""
	}
	var marshaled []byte
	rm := runOpResult("Date.MarshalJSON", func() error {
		var merr error
		marshaled, merr = marshal(d1)
		return merr
	})
	if v := opViolation(rm); v != "" {
		return v
	}
	if rm.err != nil {
		return ""
	}
	var d2 openapi_types.Date
	r2 := runOpResult("Date.UnmarshalJSON(remarshaled)", func() error { return d2.UnmarshalJSON(marshaled) })
	if v := opViolation(r2); v != "" {
		return v
	}
	if r2.err != nil {
		return fmt.Sprintf("IDEMPOTENCE BROKEN: Date.UnmarshalJSON succeeded on %q → marshaled %q, but re-UnmarshalJSON failed: %v",
			data, marshaled, r2.err)
	}
	if !d1.Time.Equal(d2.Time) {
		return fmt.Sprintf("IDEMPOTENCE BROKEN: Date.UnmarshalJSON(%q) → %s, re-unmarshal → %s (differ)",
			data, d1.String(), d2.String())
	}
	return ""
}

func realEmailMarshal(e openapi_types.Email) ([]byte, error) { return e.MarshalJSON() }
func realDateMarshal(d openapi_types.Date) ([]byte, error)   { return d.MarshalJSON() }

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
	f.Add(longLocalPart)                     // long local-part (DoS-shaped)
	f.Add([]byte{0x00, 0x01, 0x02})          // NUL bytes as raw binary input
	f.Add([]byte(`"user+test@example.com"`)) // plus-quoted local part
	f.Add([]byte(`"\"a b\"@example.com"`))   // quoted local part: known upstream deviation (#4797)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxInputBytes {
			t.Skip()
		}

		if v := emailRoundTripViolation(data, realEmailMarshal); v != "" {
			t.Fatal(v)
		}
	})
}

// --- FuzzOapiRuntimeDate ---

func FuzzOapiRuntimeDate(f *testing.F) {
	// Seeds: valid JSON-encoded date strings, text-format dates, edge cases.
	f.Add([]byte(`"2024-01-15"`))
	f.Add([]byte(`"2000-02-29"`)) // leap day
	f.Add([]byte(`"1970-01-01"`)) // epoch
	f.Add([]byte(`"9999-12-31"`)) // max sane year
	f.Add([]byte(`"0000-01-01"`)) // zero year
	f.Add([]byte(`"2024-00-01"`)) // month=0 out of range
	f.Add([]byte(`"2024-13-01"`)) // month=13 out of range
	f.Add([]byte(`"2024-01-00"`)) // day=0 out of range
	f.Add([]byte(`"2024-01-32"`)) // day=32 out of range
	f.Add([]byte(`"not-a-date"`))
	f.Add([]byte(`""`))
	f.Add([]byte(`null`))
	f.Add([]byte("2024-01-15")) // raw text (for UnmarshalText path)
	f.Add([]byte("2000-02-29")) // leap day, text
	f.Add([]byte(""))           // empty text
	f.Add([]byte("not-a-date")) // invalid text

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxInputBytes {
			t.Skip()
		}

		// Oracle (a) + (b) for UnmarshalJSON path.
		if v := dateRoundTripViolation(data, realDateMarshal); v != "" {
			t.Fatal(v)
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
	f.Add([]byte(`"P2W"`))            // weeks-only, JSON
	f.Add([]byte(`"PT0S"`))           // zero duration, JSON
	f.Add([]byte(`"P1Y"`))            // year only, JSON
	f.Add([]byte(`"PT1.5S"`))         // fractional seconds, JSON
	f.Add([]byte(`"PT0.5S"`))         // fractional seconds at boundary
	f.Add([]byte(`"P2W3D"`))          // weeks + days (invalid per grammar), JSON
	f.Add([]byte(`"P"`))              // P with no component, JSON
	f.Add([]byte(`"not-a-duration"`))
	f.Add([]byte(`""`))
	f.Add([]byte(`null`))
	f.Add([]byte("P1Y2M3DT4H5M6S")) // text format
	f.Add([]byte("PT1H30M"))        // text: 1h30m
	f.Add([]byte("P2W"))            // text: weeks-only
	f.Add([]byte("PT0S"))           // text: zero
	f.Add([]byte(""))               // empty text
	f.Add([]byte("PTTTTT"))         // multiple T, invalid

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
