// Package kinhostile is a test-only hostile-input harness for the kin-openapi
// (github.com/getkin/kin-openapi) openapi3 Schema validator — the engine Keyorix
// reaches through server/http/handlers/contracttest, the server/http OpenAPI
// stateful fuzzer, and internal/egressguard.
//
// SCOPE / REACHABILITY HONESTY. In every LIVE Keyorix caller the SCHEMA is the
// trusted, committed server/http/handlers/openapi.yaml and the INSTANCE is either a
// handler's own response (response-conformance) or a test-generated body — never a
// raw attacker-controlled schema+instance pair. So a finding here is a LIBRARY
// property (ReDoS / composition-explosion / deep-recursion panic / round-trip
// instability), classified HARDENING/CANDIDATE and labelled "not reachable with
// attacker-controlled schema" unless a concrete live call path is traced. The
// library is still fuzzed so a dependency bump that regresses it is caught.
//
// It does NOT duplicate internal/libconformance FuzzJSONSchemaValidatorDifferential
// (a kin-vs-santhosh VERDICT differential on three tiny fixed schemas, no pattern/
// format/composition, no resource metering). This target fuzzes the SCHEMA itself —
// deep nesting, allOf/anyOf/oneOf, pattern, additionalProperties, recursion — and
// meters WORK, which no existing target does.
//
// ORACLES (what each does / does NOT verify is in its comment):
//
//	O-KIN-1  no panic: UnmarshalJSON + VisitJSON + MarshalJSON on any input must not
//	         panic (recorded natively by the fuzzer).
//	O-KIN-2  bounded work: VisitJSON is wrapped by fuzzutil.Guard (3s hang/amplif
//	         watchdog, FATAL) and metered by resguard (alloc_bytes/mallocs FATAL vs a
//	         calibrated ceiling; wall/cpu advisory). Catches superlinear composition
//	         blow-up and any make-from-length-field amplification.
//	O-KIN-3  schema round-trip idempotence: for a schema kin ACCEPTS, MarshalJSON →
//	         UnmarshalJSON → MarshalJSON is byte-stable. A drift is a serialization
//	         defect. FATAL.
package kinhostile

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const (
	maxSchemaBytes   = 1 << 13 // 8 KiB: ample for pathological nesting/composition
	maxInstanceBytes = 1 << 13 // 8 KiB: ample for deep/large instances; larger inputs
	// mostly stall the fuzz engine's corpus I/O without reaching new library behaviour.
	budgetPath = "testdata/resguard-kinopenapi.json"
)

// superlinearWall is the O-KIN-2b fatal ceiling for one decode+visit+roundtrip on a
// <=16 KiB input (see the oracle comment in FuzzOpenAPISchemaBoundedWork).
const superlinearWall = 2500 * time.Millisecond

// parseSchema attempts kin's standalone schema decode. Returns nil if kin rejects it.
func parseSchema(data []byte) *openapi3.Schema {
	s := openapi3.NewSchema()
	if err := s.UnmarshalJSON(data); err != nil {
		return nil
	}
	return s
}

// roundTripResult holds the outcome of a Marshal→Unmarshal→Marshal cycle computed
// inside the watchdog goroutine; the assertions run on the test goroutine.
type roundTripResult struct {
	ran          bool // a schema was accepted and the cycle attempted
	reparseErr   error
	remarshalErr error
	first        []byte
	second       []byte
}

// computeRoundTrip is the heavy, assertion-free half of O-KIN-3, safe to run on the
// watchdog goroutine. assertRoundTrip does the t.Fatalf checks on the test goroutine.
//
// O-KIN-3 does NOT verify semantic equality (two differently-ordered-but-equivalent
// schemas), only that kin's own Marshal→Unmarshal→Marshal reaches a fixed point — a
// weaker but defect-revealing property (a field dropped or mutated is caught).
func computeRoundTrip(s *openapi3.Schema) roundTripResult {
	var r roundTripResult
	first, err := s.MarshalJSON()
	if err != nil {
		return r // un-marshalable accepted schema: not this oracle's concern.
	}
	r.ran = true
	r.first = first
	s2 := openapi3.NewSchema()
	if err := s2.UnmarshalJSON(first); err != nil {
		r.reparseErr = err
		return r
	}
	second, err := s2.MarshalJSON()
	if err != nil {
		r.remarshalErr = err
		return r
	}
	r.second = second
	return r
}

func assertRoundTrip(t *testing.T, r roundTripResult) {
	if !r.ran {
		return
	}
	if r.reparseErr != nil {
		t.Fatalf("O-KIN-3: schema kin produced via MarshalJSON failed to re-parse: %v\n  json=%s", r.reparseErr, truncate(r.first))
	}
	if r.remarshalErr != nil {
		t.Fatalf("O-KIN-3: re-parsed schema failed to MarshalJSON: %v", r.remarshalErr)
	}
	if string(r.first) != string(r.second) {
		t.Fatalf("O-KIN-3: schema MarshalJSON not idempotent\n  first =%s\n  second=%s", truncate(r.first), truncate(r.second))
	}
}

// checkRoundTrip is the combined form used by the deterministic seed guard (runs on
// the test goroutine, no watchdog needed there).
func checkRoundTrip(t *testing.T, s *openapi3.Schema) { assertRoundTrip(t, computeRoundTrip(s)) }

func truncate(b []byte) string {
	if len(b) > 400 {
		return string(b[:400]) + "...(truncated)"
	}
	return string(b)
}

func FuzzOpenAPISchemaBoundedWork(f *testing.F) {
	budget, err := resguard.LoadBudget(budgetPath)
	haveBudget := err == nil
	if !haveBudget {
		f.Logf("no committed budget at %s (run TestKinCalibrate with RESGUARD_CALIBRATE=1); metering without a ceiling", budgetPath)
	}
	p := resguard.New(f, resguard.Options{SampleEvery: 8})

	for _, sd := range kinSeeds() {
		f.Add(sd.schema, sd.instance)
	}

	f.Fuzz(func(t *testing.T, schemaJSON, instanceJSON []byte) {
		if len(schemaJSON) > maxSchemaBytes || len(instanceJSON) > maxInstanceBytes {
			return
		}
		// O-KIN-1 + O-KIN-2: EVERY heavy kin call — schema decode, instance decode,
		// VisitJSON, and the round trip — runs inside ONE hang/amplification watchdog,
		// so a superlinear parse or a blow-up in ANY stage is attributed (not silently
		// absorbed into a stalled worker). VisitJSON is additionally metered by resguard
		// for the alloc/mallocs ceiling.
		var cost resguard.Cost
		var measured bool
		var rt roundTripResult
		started := time.Now()
		fuzzutil.Guard(t.Fatalf, "kin schema decode+visit+roundtrip", func() {
			s := parseSchema(schemaJSON)
			if s == nil {
				return // kin rejected the schema shape — nothing to validate.
			}
			var inst any
			if err := json.Unmarshal(instanceJSON, &inst); err != nil {
				return
			}
			cost = p.Measure(len(schemaJSON)+len(instanceJSON), func() {
				_ = s.VisitJSON(inst)
			})
			measured = true
			rt = computeRoundTrip(s) // heavy half; assertions run below on the test goroutine
		})
		elapsed := time.Since(started)
		// Assertions + budget check on the TEST goroutine (t.Fatalf is unsafe off it).
		if measured {
			resguard.FeedCoverage(cost)
			if haveBudget {
				budget.Check(t.Fatalf, cost)
			}
			assertRoundTrip(t, rt)
			// O-KIN-2b (superlinear wall): the whole decode+visit+roundtrip on a
			// <=16 KiB input must finish well under the Guard deadline. A multi-second
			// wall on so small an input is strongly superlinear — a bounded-work
			// candidate worth saving. Set below Guard's 3s so near-threshold slow
			// inputs are attributed here (with size) rather than as a bare "hang".
			// Generous (2.5s) so co-scheduled -parallel load does not false-trip it.
			if elapsed > superlinearWall {
				t.Fatalf("O-KIN-2b: superlinear work: %s on a %d-byte schema + %d-byte instance (>%s)",
					elapsed, len(schemaJSON), len(instanceJSON), superlinearWall)
			}
		}
	})
}
