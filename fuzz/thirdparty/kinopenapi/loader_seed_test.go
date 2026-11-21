package kinhostile

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Sentinel errors shared by the loader harnesses.
var (
	errCanaryRefused = errors.New("ko3-canary: external read refused (no IO performed)")
	errReloadNil     = errors.New("re-load returned nil doc with nil error")
)

// docEnvelope wraps component schemas into a minimal valid OpenAPI 3.0 document.
func docEnvelope(componentsSchemas string, extra string) []byte {
	return []byte(fmt.Sprintf(
		`{"openapi":"3.0.0","info":{"title":"ko3","version":"1"},"paths":{}%s,"components":{"schemas":%s}}`,
		extra, componentsSchemas))
}

// recursiveSelfRef: a component that refers to itself — the classic circular
// $ref the loader must resolve without infinite recursion / stack overflow.
func recursiveSelfRef() []byte {
	return docEnvelope(`{"Node":{"type":"object","properties":{"next":{"$ref":"#/components/schemas/Node"},"v":{"type":"integer"}}}}`, "")
}

// mutualRecursion: A -> B -> A, a cycle through two components.
func mutualRecursion() []byte {
	return docEnvelope(`{"A":{"type":"object","properties":{"b":{"$ref":"#/components/schemas/B"}}},"B":{"type":"object","properties":{"a":{"$ref":"#/components/schemas/A"}}}}`, "")
}

// deepRefChain: C0 -> C1 -> ... -> Cn, a linear ref chain n deep (stack depth probe).
func deepRefChain(n int) []byte {
	var b strings.Builder
	b.WriteString("{")
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		next := fmt.Sprintf("#/components/schemas/C%d", i+1)
		fmt.Fprintf(&b, `"C%d":{"type":"object","properties":{"n":{"$ref":%q}}}`, i, next)
	}
	// terminal
	fmt.Fprintf(&b, `,"C%d":{"type":"integer"}`, n)
	b.WriteString("}")
	return docEnvelope(b.String(), "")
}

// deepAllOfInComponent: one component nested allOf d deep (resolution + validate recursion).
func deepAllOfInComponent(d int) []byte {
	var s strings.Builder
	for range d {
		s.WriteString(`{"allOf":[`)
	}
	s.WriteString(`{"type":"object"}`)
	for range d {
		s.WriteString(`]}`)
	}
	return docEnvelope(fmt.Sprintf(`{"Deep":%s}`, s.String()), "")
}

// manyRefsFanout: one hub component with w properties each $ref-ing the same
// terminal — large ref fan-out the resolver must handle without amplification.
func manyRefsFanout(w int) []byte {
	var b strings.Builder
	b.WriteString(`{"Hub":{"type":"object","properties":{`)
	for i := range w {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"p%d":{"$ref":"#/components/schemas/Leaf"}`, i)
	}
	b.WriteString(`}},"Leaf":{"type":"string"}}`)
	return docEnvelope(b.String(), "")
}

// extensionFields: x-* extension keys at document, schema and path level —
// kin must preserve or ignore them without choking (and round-trip them).
func extensionFields() []byte {
	return []byte(`{"openapi":"3.0.0","x-top":{"a":[1,2,3]},"info":{"title":"ko3","version":"1","x-info":"hi"},"paths":{},"components":{"schemas":{"S":{"type":"object","x-schema":{"nested":{"deep":true}},"properties":{"f":{"type":"string","x-prop":42}}}}}}`)
}

// duplicateNames: two JSON keys with the SAME name in one object (last-wins
// per encoding/json) plus colliding component names across case.
func duplicateNames() []byte {
	return []byte(`{"openapi":"3.0.0","info":{"title":"ko3","version":"1"},"paths":{},"components":{"schemas":{"Dup":{"type":"string"},"Dup":{"type":"integer"},"dup":{"type":"boolean"}}}}`)
}

// pathItemRefs: a $ref in paths/responses/parameters, not just schemas.
func pathItemRefs() []byte {
	return []byte(`{"openapi":"3.0.0","info":{"title":"ko3","version":"1"},"paths":{"/x":{"get":{"responses":{"200":{"$ref":"#/components/responses/R"}}}}},"components":{"responses":{"R":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/S"}}}}},"schemas":{"S":{"type":"object","properties":{"self":{"$ref":"#/components/schemas/S"}}}}}}`)
}

// externalFileRef / externalHTTPRef / externalSSRFRef: external $refs the
// Config-A air-gap target injects. Harmless under Config B (refused by the
// canary func); under Config A they must be refused BEFORE any read.
func externalFileRef(path string) []byte {
	return docEnvelope(fmt.Sprintf(`{"X":{"$ref":%q}}`, "file://"+path), "")
}

func loaderSeeds() [][]byte {
	seeds := [][]byte{
		// minimal valid documents
		docEnvelope(`{"S":{"type":"object","properties":{"name":{"type":"string"}}}}`, ""),
		[]byte(`{"openapi":"3.0.0","info":{"title":"ko3","version":"1"},"paths":{}}`),
		// recursion / cycles
		recursiveSelfRef(),
		mutualRecursion(),
		deepRefChain(16),
		deepRefChain(64),
		deepAllOfInComponent(32),
		deepAllOfInComponent(64),
		// fan-out
		manyRefsFanout(32),
		manyRefsFanout(128),
		// extensions / duplicates / path refs
		extensionFields(),
		duplicateNames(),
		pathItemRefs(),
		// external refs (safe under Config B; refused under Config A)
		externalFileRef("/etc/passwd"),
		[]byte(`{"openapi":"3.0.0","info":{"title":"ko3","version":"1"},"paths":{},"components":{"schemas":{"X":{"$ref":"http://169.254.169.254/latest/meta-data/"}}}}`),
		// degenerate
		[]byte(`{}`),
		[]byte(`{"openapi":"3.0.0"}`),
		[]byte(`{"openapi":"3.1.0","info":{"title":"ko3","version":"1"},"paths":{},"components":{"schemas":{"S":{"type":"string"}}}}`),
	}
	return seeds
}

// TestLoaderSeeds_NoPanic is the committed deterministic guard (default
// `go test`): every seed loads (or is cleanly rejected) under Config B without a
// panic, and any accepted document satisfies O-LOAD-3/O-LOAD-5. It is the
// non-fuzz replay of O-LOAD-1/3/5.
func TestLoaderSeeds_NoPanic(t *testing.T) {
	for i, data := range loaderSeeds() {
		var reads int
		o := runLoaderPipeline(data, &reads)
		assertLoaderOutcome(t, data, o)
		_ = i
	}
}

// TestLoaderHarness_NotVacuous proves the loader actually resolves internal
// refs (so a green run is meaningful): a self-referential component must load
// with its $ref preserved in the marshalled output, and a document with a
// dangling internal ref must be rejected.
func TestLoaderHarness_NotVacuous(t *testing.T) {
	var reads int
	o := runLoaderPipeline(recursiveSelfRef(), &reads)
	if !o.loaded {
		t.Fatal("precondition: a self-referential document must load (cycle resolution)")
	}
	if !strings.Contains(string(o.marshal1), `"$ref"`) {
		t.Fatalf("expected the resolved cycle to still marshal a $ref; got %s", truncate(o.marshal1))
	}
	// A dangling ref must be rejected (validator not vacuous).
	dangling := docEnvelope(`{"S":{"$ref":"#/components/schemas/DoesNotExist"}}`, "")
	l := newCanaryLoader(new(int))
	if _, err := l.LoadFromData(dangling); err == nil {
		t.Fatal("dangling internal $ref accepted — loader/validator is vacuous")
	}
}
