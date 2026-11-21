package kinhostile

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

type kinSeed struct {
	schema   []byte
	instance []byte
}

// nestedAllOf builds a schema nested n levels deep in allOf, to probe deep-recursion
// behaviour of UnmarshalJSON / VisitJSON (a stack-overflow panic would be O-KIN-1).
func nestedAllOf(n int) []byte {
	var b strings.Builder
	for range n {
		b.WriteString(`{"allOf":[`)
	}
	b.WriteString(`{"type":"object"}`)
	for range n {
		b.WriteString(`]}`)
	}
	return []byte(b.String())
}

// nestedObject builds a schema that is n object levels deep via properties, each
// requiring the next — a recursion/explosion probe when paired with a matching
// deeply-nested instance.
func nestedObject(n int) []byte {
	var b strings.Builder
	for range n {
		b.WriteString(`{"type":"object","properties":{"a":`)
	}
	b.WriteString(`{"type":"integer"}`)
	for range n {
		b.WriteString(`}}`)
	}
	return []byte(b.String())
}

func nestedInstance(n int) []byte {
	var b strings.Builder
	for range n {
		b.WriteString(`{"a":`)
	}
	b.WriteString(`1`)
	for range n {
		b.WriteString(`}`)
	}
	return []byte(b.String())
}

// anyOfExplosion builds a schema with an array whose items anyOf has width branches,
// nested depth deep — the shape where a validator that tries every branch at every
// level does exponential work.
func anyOfExplosion(width, depth int) []byte {
	branch := func() string {
		parts := make([]string, width)
		for i := range parts {
			parts[i] = `{"type":"integer","minimum":` + string(rune('0'+i%10)) + `}`
		}
		return `{"anyOf":[` + strings.Join(parts, ",") + `]}`
	}
	schema := branch()
	for range depth {
		schema = `{"type":"array","items":` + schema + `}`
	}
	return []byte(schema)
}

func anyOfInstance(depth int) []byte {
	v := "1"
	for range depth {
		v = "[" + v + "]"
	}
	return []byte(v)
}

func kinSeeds() []kinSeed {
	seeds := []kinSeed{
		// Keyorix-shaped benign schemas (the calibration/benign corpus).
		{[]byte(`{"type":"object","required":["name"],"additionalProperties":false,"properties":{"name":{"type":"string","minLength":1,"maxLength":64},"ttl":{"type":"integer","minimum":1}}}`), []byte(`{"name":"ok","ttl":5}`)},
		{[]byte(`{"type":"string","enum":["admin","reader","writer"]}`), []byte(`"admin"`)},
		{[]byte(`{"type":"array","items":{"type":"string"},"maxItems":10,"minItems":1}`), []byte(`["a","b"]`)},
		// pattern (RE2 — no catastrophic ReDoS, but exercises compile + match).
		{[]byte(`{"type":"string","pattern":"^(a+)+$"}`), []byte(`"aaaaaaaaaaaaaaaaaaaaaaaa!"`)},
		{[]byte(`{"type":"string","pattern":"^([a-z]+-)*[a-z]+$"}`), []byte(`"a-b-c-d-e-f-g-h"`)},
		// format keywords.
		{[]byte(`{"type":"string","format":"email"}`), []byte(`"x@y.z"`)},
		{[]byte(`{"type":"string","format":"uuid"}`), []byte(`"not-a-uuid"`)},
		// composition.
		{[]byte(`{"oneOf":[{"type":"integer"},{"type":"string"}]}`), []byte(`42`)},
		{[]byte(`{"allOf":[{"type":"object"},{"required":["x"]}]}`), []byte(`{"x":1}`)},
		{[]byte(`{"anyOf":[{"type":"integer"},{"type":"boolean"}]}`), []byte(`true`)},
		// discriminator.
		{[]byte(`{"oneOf":[{"type":"object","properties":{"kind":{"type":"string"}}}],"discriminator":{"propertyName":"kind"}}`), []byte(`{"kind":"a"}`)},
		// additionalProperties variants.
		{[]byte(`{"type":"object","additionalProperties":{"type":"integer"}}`), []byte(`{"a":1,"b":2}`)},
		{[]byte(`{"type":"object","additionalProperties":false}`), []byte(`{"a":1}`)},
		// deep nesting / explosion probes.
		{nestedAllOf(64), []byte(`{}`)},
		{nestedObject(64), nestedInstance(64)},
		{anyOfExplosion(6, 4), anyOfInstance(4)},
		{anyOfExplosion(8, 6), anyOfInstance(6)},
		// large array instance against a trivial item schema (within the 8 KiB bound).
		{[]byte(`{"type":"array","items":{"type":"integer"}}`), hugeIntArray(3000)},
		// degenerate / empty.
		{[]byte(`{}`), []byte(`{"anything":true}`)},
		{[]byte(`true`), []byte(`123`)},
	}
	return seeds
}

func hugeIntArray(n int) []byte {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "1"
	}
	return []byte("[" + strings.Join(parts, ",") + "]")
}

// TestKinSeeds_NoPanicRoundTrip is the committed deterministic guard (default
// `go test`): every seed parses (or is cleanly rejected), VisitJSON does not panic,
// and any accepted schema round-trips. It is the non-fuzz replay of O-KIN-1/O-KIN-3.
func TestKinSeeds_NoPanicRoundTrip(t *testing.T) {
	for i, sd := range kinSeeds() {
		s := parseSchema(sd.schema)
		if s == nil {
			continue
		}
		var inst any
		if err := json.Unmarshal(sd.instance, &inst); err != nil {
			continue
		}
		_ = s.VisitJSON(inst) // must not panic
		checkRoundTrip(t, s)
		_ = i
	}
}

// TestKinHarness_NotVacuous proves VisitJSON actually discriminates valid vs invalid
// instances (so a green fuzz run is meaningful, not a no-op validator).
func TestKinHarness_NotVacuous(t *testing.T) {
	s := parseSchema([]byte(`{"type":"object","required":["name"],"additionalProperties":false,"properties":{"name":{"type":"string","minLength":1,"maxLength":4}}}`))
	if s == nil {
		t.Fatal("precondition: schema must parse")
	}
	var good, bad any
	_ = json.Unmarshal([]byte(`{"name":"ok"}`), &good)
	_ = json.Unmarshal([]byte(`{"name":"toolong","extra":1}`), &bad)
	if err := s.VisitJSON(good); err != nil {
		t.Fatalf("valid instance rejected: %v", err)
	}
	if err := s.VisitJSON(bad); err == nil {
		t.Fatal("invalid instance accepted — validator is vacuous")
	}
}

// roundTripStable is the pure comparison backing O-KIN-3, extracted so it can be
// red/green-proven without needing the library to misbehave.
func roundTripStable(first, second []byte) bool { return string(first) == string(second) }

// TestKinOracles_RedGreen red/green-proves the two assertable oracles on crafted
// values (library misbehaviour is not needed; the defect is expressible as a crafted
// Cost / crafted marshal pair — mirroring backupfmt's input-expressible plant).
func TestKinOracles_RedGreen(t *testing.T) {
	// O-KIN-3: idempotence comparison.
	if !roundTripStable([]byte(`{"type":"object"}`), []byte(`{"type":"object"}`)) {
		t.Fatal("O-KIN-3 GREEN failed: identical marshals judged unstable")
	}
	if roundTripStable([]byte(`{"type":"object"}`), []byte(`{"type":"array"}`)) {
		t.Fatal("O-KIN-3 RED failed: differing marshals judged stable")
	}

	// O-KIN-2: resguard budget fires on an over-ceiling cost and passes a benign one.
	b := resguard.Calibrate("kin_test", benignKinCosts(t), resguard.DefaultFactor)
	delete(b.Meters, "live_heap")
	benign := benignKinCosts(t)[0]
	var benignFired bool
	b.Check(func(string, ...any) { benignFired = true }, benign)
	if benignFired {
		t.Fatalf("O-KIN-2 GREEN failed: benign cost tripped the budget")
	}
	red := benign
	red.AllocBytes = benign.AllocBytes*1000 + (1 << 30) // a gross amplification
	red.Mallocs = benign.Mallocs*1000 + (1 << 20)
	red.Sampled = true
	var redFired bool
	b.Check(func(string, ...any) { redFired = true }, red)
	if !redFired {
		t.Fatalf("O-KIN-2 RED failed: a 1 GiB alloc spike did not trip the budget")
	}
}

// benignKinCosts measures VisitJSON over the Keyorix-shaped benign schemas for
// calibration. Excludes the explosion/deep-nesting probes (those are the shapes the
// budget must flag, not learn as normal).
func benignKinCosts(tb testing.TB) []resguard.Cost {
	tb.Helper()
	benign := kinSeeds()[:13] // the Keyorix-shaped + composition seeds, before the probes
	var costs []resguard.Cost
	for range 4 {
		for _, sd := range benign {
			s := parseSchema(sd.schema)
			if s == nil {
				continue
			}
			var inst any
			if json.Unmarshal(sd.instance, &inst) != nil {
				continue
			}
			p := resguard.New(tb, resguard.Options{SampleEvery: 1})
			c := p.Measure(len(sd.schema)+len(sd.instance), func() { _ = s.VisitJSON(inst) })
			costs = append(costs, c)
		}
	}
	return costs
}

// TestKinCalibrate regenerates the committed budget under RESGUARD_CALIBRATE=1.
func TestKinCalibrate(t *testing.T) {
	b := resguard.Calibrate("kin_visitjson", benignKinCosts(t), resguard.DefaultFactor)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes should be calibrated; meters=%v", b.Summary())
	}
	// live_heap is a whole-process post-GC reading; for a sub-millisecond VisitJSON it
	// is dominated by the fuzz engine's own heap, not input-attributable work. The
	// input-attributable amplification meters alloc_bytes/mallocs stay fatal; a true
	// hang/amplification is independently caught by fuzzutil.Guard.
	// (INV-FUZZKIN-liveheap-not-metered)
	delete(b.Meters, "live_heap")
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(budgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", budgetPath, b.Summary())
	}
}

// keep openapi3 import used even if seeds change.
var _ = openapi3.NewSchema
