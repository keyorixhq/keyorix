package libconformance

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

// jsonReqBody mirrors the SHAPE of a typical Keyorix HTTP request body struct
// (e.g. server/http/handlers/pat_handler.go's create-PAT body): a required-ish
// string, an optional string pointer, a numeric field and a nested object. The
// exact field set is not important — the target is over the DECODE PATHS, not
// this struct. Field tags match the json idiom used across the handlers.
type jsonReqBody struct {
	Name      string          `json:"name"`
	ExpiresAt *string         `json:"expiresAt"`
	TTL       int64           `json:"ttl"`
	Scopes    []string        `json:"scopes"`
	Meta      map[string]any  `json:"meta"`
	Nested    *jsonReqNested  `json:"nested"`
	Raw       json.RawMessage `json:"raw"`
}

type jsonReqNested struct {
	Enabled bool `json:"enabled"`
}

// FuzzJSONStrictDecodeDifferential is a differential fuzz target over the JSON
// request-decode paths Keyorix actually uses versus the stricter alternatives it
// could have used.
//
// LIVE CALLER: every Keyorix HTTP handler decodes its body with
//
//	json.NewDecoder(r.Body).Decode(&body)
//
// (confirmed: server/http/handlers/pat_handler.go:164, and ~40 other handlers;
// NONE of them call DisallowUnknownFields, and none read past the first JSON
// value). The two sibling decode strategies compared here are:
//
//	A  json.NewDecoder(data).Decode(&v)          — THE Keyorix handler path
//	B  json.Unmarshal(data, &v)                  — the whole-body-is-one-value path
//	C  decoder + DisallowUnknownFields           — the strict path Keyorix omits
//	M  json.Unmarshal(data, &map[string]any)     — schemaless decode
//
// Oracles (classified disagreement, never panic-only):
//
//   - A-vs-B ACCEPT/REJECT PARITY: the single security-relevant question. A and B
//     decode the SAME struct from the SAME bytes. They are documented to differ in
//     exactly one way — json.Decoder.Decode reads ONE value and ignores whatever
//     trailing bytes follow, whereas json.Unmarshal rejects trailing non-whitespace
//     ("invalid character after top-level value"). Any A-accepts/B-rejects split is
//     therefore gated: if A left unconsumed trailing bytes it is the KNOWN
//     "trailing-data" class (EXPECTED, and the talk material — Keyorix handlers
//     silently accept trailing garbage / a second smuggled JSON value after the
//     body). Any split WITHOUT trailing data, or any A-rejects/B-accepts split, is
//     NEW and fails.
//   - A-vs-C UNKNOWN-FIELD divergence: when C rejects but A accepts, the input
//     carried an unknown field. This is the mass-assignment-adjacent behaviour
//     Keyorix chose (unknown fields silently dropped). It is recorded as the
//     "unknown-field" class — expected, but surfaced so the choice is visible.
//   - A-vs-M PARITY ON WELL-FORMEDNESS: a struct decode (A) and a schemaless map
//     decode (M) must agree on whether the bytes are a well-formed JSON object.
//     They legitimately differ on TYPE mismatches (e.g. {"ttl":"x"} — A rejects on
//     the int field, M accepts the string), so only the "both see valid JSON
//     syntax" direction is asserted; type-driven splits are the "type-mismatch"
//     class.
func FuzzJSONStrictDecodeDifferential(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"name":"x"}`),
		[]byte(`{"name":"x","ttl":5}`),
		[]byte(`{"name":"x"}{"name":"y"}`), // trailing second value (smuggling)
		[]byte(`{"name":"x"}  `),           // trailing whitespace only
		[]byte(`{"name":"x"}garbage`),      // trailing garbage
		[]byte(`{"name":"x","unknown":1}`), // unknown field
		[]byte(`{"ttl":"not-an-int"}`),     // type mismatch on int
		[]byte(`{"nested":{"enabled":true}}`),
		[]byte(`{"scopes":["a","b"]}`),
		[]byte(`   {"name":"x"}`), // leading whitespace
		[]byte(`[1,2,3]`),         // wrong top-level type
		[]byte(`null`),
		[]byte(`{"name":"x","meta":{"k":"v"}}`),
		[]byte(`{"raw":{"anything":[1,2]}}`),
		[]byte(``),
		[]byte(`{"ttl":1e309}`),                      // number overflow
		[]byte("{\"name\":\"x\"}\n{\"name\":\"y\"}"), // newline-separated (NDJSON smuggle)
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}

		// Path A — the Keyorix handler path.
		var va jsonReqBody
		decA := json.NewDecoder(bytes.NewReader(data))
		errA := decA.Decode(&va)
		// After a successful single-value Decode, are there non-whitespace bytes
		// left? That is the ONLY documented A/B divergence source.
		trailing := false
		if errA == nil {
			if _, perr := decA.Token(); perr != io.EOF {
				// Token() returning anything other than io.EOF means Decode left
				// a further token (a second value / garbage) in the stream.
				trailing = true
			}
		}

		// Path B — whole-body-is-one-value.
		var vb jsonReqBody
		errB := json.Unmarshal(data, &vb)

		acceptA := errA == nil
		acceptB := errB == nil

		if acceptA != acceptB {
			switch {
			case acceptA && !acceptB && trailing:
				// KNOWN, security-relevant: Decoder.Decode accepted a body with
				// trailing bytes that Unmarshal rejects.
				if !jsonDecodeExpectedDiff["A-vs-B:trailing-data"] {
					t.Fatalf("NEW A/B split classified trailing-data but not in table\n  input=%q", data)
				}
			case acceptA && !acceptB && !trailing:
				t.Fatalf("NEW A-accepts/B-rejects split with NO trailing data (unexpected)\n  input=%q\n  errB=%v", data, errB)
			default: // acceptB && !acceptA
				class := "A-vs-B:B-accepts-A-rejects"
				if !jsonDecodeExpectedDiff[class] {
					t.Fatalf("NEW B-accepts/A-rejects split\n  input=%q\n  errA=%v", data, errA)
				}
			}
		}

		// Path C — DisallowUnknownFields. Only meaningful when A accepted.
		if acceptA {
			var vc jsonReqBody
			decC := json.NewDecoder(bytes.NewReader(data))
			decC.DisallowUnknownFields()
			errC := decC.Decode(&vc)
			if errC != nil {
				msg := errC.Error()
				if containsAny(msg, "unknown field") {
					if !jsonDecodeExpectedDiff["A-vs-C:unknown-field"] {
						t.Fatalf("NEW A/C split: C rejected an unknown field but class not listed\n  input=%q\n  errC=%v", data, errC)
					}
				}
				// Other C errors (e.g. C also saw trailing? no — Decode is same
				// single-value semantics) are not asserted here.
			}
		}

		// Path M — schemaless map decode, compared to A on object well-formedness.
		var vm any
		errM := json.Unmarshal(data, &vm)
		acceptM := errM == nil
		if acceptA && !acceptM && !trailing {
			// A (struct) accepted but M (schemaless) rejected, no trailing data.
			// This is NOT impossible: the two decoders share one tokenizer but
			// differ in what they MATERIALIZE. A struct decode (A) SKIPS the value
			// of an unknown field without parsing it, and stores a json.RawMessage
			// field as raw bytes — in neither case does it convert the number to a
			// Go float64/int, so it never hits the float64-range check. A schemaless
			// decode (M) materializes every number into float64 and rejects one that
			// overflows (e.g. {"":1e700} under the unknown key "", or {"raw":1e700}).
			// That is a genuine, benign value-materialization differential, gated as
			// a named class; only a NON-materialization M-rejection (a true syntax
			// reject A somehow passed) is impossible.
			if isSchemalessMaterializationReject(errM) {
				if !jsonDecodeExpectedDiff["A-vs-M:schemaless-number-range"] {
					t.Fatalf("NEW A/M materialization split not listed in table\n  input=%q\n  errM=%v", data, errM)
				}
			} else {
				t.Fatalf("struct decode accepted but schemaless decode rejected for a NON-materialization reason (impossible-direction)\n  input=%q\n  errM=%v", data, errM)
			}
		}
		if acceptM && !acceptA {
			// Expected when types mismatch (M has no schema). Only flag if NOT a
			// type-ish rejection.
			if errA != nil && !isTypeOrTrailingReject(errA, trailing) {
				class := "A-vs-M:non-type-reject"
				if !jsonDecodeExpectedDiff[class] {
					t.Fatalf("NEW A/M split: struct decode rejected for a non-type reason while schemaless accepted\n  input=%q\n  errA=%v", data, errA)
				}
			}
		}
	})
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && bytes.Contains([]byte(s), []byte(sub)) {
			return true
		}
	}
	return false
}

// isTypeOrTrailingReject reports whether a struct-decode error is a plain
// type-mismatch (or trailing-data) rejection, i.e. the benign, expected reason a
// struct decode rejects something schemaless decode accepts.
func isTypeOrTrailingReject(err error, trailing bool) bool {
	if trailing {
		return true
	}
	if _, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
		return true
	}
	// Overflow of a numeric field surfaces as a *strconv.NumError wrapped in a
	// generic error; treat number-range/format rejects as type-ish.
	msg := err.Error()
	return containsAny(msg, "cannot unmarshal", "overflow", "out of range", "invalid number")
}

// isSchemalessMaterializationReject reports whether a json.Unmarshal-into-any
// error is a value-materialization rejection (chiefly a number too large for
// float64), the only reason schemaless decode legitimately rejects bytes a
// struct decode accepted by skipping/raw-storing them.
func isSchemalessMaterializationReject(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
		return true
	}
	return containsAny(err.Error(), "cannot unmarshal number", "overflow", "out of range")
}
