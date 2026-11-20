package libconformance

// DF1 Oracle D — $ref/$defs territory verdict differential:
// getkin/kin-openapi (built-in OpenAPI 3.0 validator, refs resolved by its Loader) vs
// santhosh-tekuri/jsonschema/v6 (JSON Schema 2020-12).
//
// FuzzOpenAPIVsJSONSchema (Oracle C) hands kin a bare openapi3.Schema, which cannot
// resolve any $ref: kin rejects every $ref/$defs schema there, so Oracle C compares no
// verdict in this territory. Oracle D wraps the schema in an OpenAPI 3.0.3 document
// (kinRefDocument: the schema becomes components.schemas.S, root $defs are hoisted into
// components.schemas) so kin's Loader resolves "#" and "#/$defs/<name>" refs, including
// recursive ones, and then compares the two verdicts.
//
// Why the built-in validator and not openapi3.EnableJSONSchema2020(): in kin-openapi
// v0.153.0 that option evaluates with santhosh-tekuri/jsonschema/v6 itself
// (schema_jsonschema_validator.go), which would compare santhosh with santhosh.
//
// Splits found in this territory so far: openapi-ref-sibling-ignored (OpenAPI 3.0 ignores
// keywords next to $ref; 2020-12 applies them). Every Oracle-C split is reachable through
// a $ref too (e.g. a $defs target with nullable:true), so those entries are inherited.
//
// google/jsonschema-go (KFZ-2026-021, a non-consuming $ref cycle that recursed without
// bound) is NOT a dependency of this module, so neither KFZ-2026-021 nor that library is
// covered here. TestJSONSchemaRefDiff_CycleSafety only smoke-tests santhosh on the same
// cycle shapes. A stack overflow cannot be recovered; it would show up as a crash of the
// test or fuzz process, not as a classified differential.
//
// WHAT THIS ORACLE DOES NOT VERIFY (TestRefDiff_SeedsReachVerdictComparison pins the
// per-group reach):
//   - Pure ref-only cycles ({"$ref":"#"}, A->A via $defs): kin's document validation
//     reports "found unresolved ref", so the pair is skipped; only a santhosh crash/hang
//     is detectable there.
//   - $dynamicRef/$dynamicAnchor/$anchor/$id and other 2020-12-only keywords: kin's 3.0
//     document validation rejects them, and kin has no independent 2020-12 evaluator, so
//     those pairs are skipped (crash/hang detection only).
//   - $ref targets other than "#" and "#/$defs/<name>" (JSON pointers into the schema,
//     nested $defs, external URIs): kinRefDocument refuses to map them.
//   - Schemas only one library compiles (kinOK=false or jsOK=false) are skipped, not
//     classified. Only the accept/reject verdict is compared, not error paths.
//   - KFZ-2026-021 / KFZ-2026-086 are ids in the private KFZ fuzz-findings ledger
//     (keyorix-private), not in this repository.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// kinRefComponents is where kinRefDocument puts the schema under test ("S") and its
// hoisted $defs ("d_<name>").
const kinRefComponents = "#/components/schemas/"

// componentNameRE is the OpenAPI component-name charset. A $defs name outside it cannot
// become a component key, and it also rules out "/" and "~" (JSON-pointer escapes), so a
// "#/$defs/<name>" ref maps to exactly one component.
var componentNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// forEachSubschema calls fn on every direct subschema of m under the subschema keywords
// OpenAPI 3.0 defines (properties, items, additionalProperties, not, allOf, anyOf, oneOf),
// stopping at the first false.
func forEachSubschema(m map[string]any, fn func(any) bool) bool {
	if props, isMap := m["properties"].(map[string]any); isMap {
		for _, p := range props {
			if !fn(p) {
				return false
			}
		}
	}
	for _, kw := range []string{"items", "additionalProperties", "not"} {
		if sub, has := m[kw]; has && !fn(sub) {
			return false
		}
	}
	for _, kw := range []string{"allOf", "anyOf", "oneOf"} {
		subs, _ := m[kw].([]any)
		for _, s := range subs {
			if !fn(s) {
				return false
			}
		}
	}
	return true
}

// kinRefDocument wraps a standalone JSON Schema in an OpenAPI 3.0.3 document so that
// kin-openapi's Loader resolves its internal $refs, which a bare openapi3.Schema cannot:
//   - the schema becomes components.schemas.S and every "#" ref points at it;
//   - each root-level $defs/<name> becomes components.schemas.d_<name> and every
//     "#/$defs/<name>" ref points at it.
//
// The rewrite walks forEachSubschema only. ok=false when the mapping cannot be faithful:
// a non-object root, a $defs that is not an object or has a name outside the component
// charset, any other $ref target (JSON pointers into the schema, $anchor names, external
// URIs), or a $ref left anywhere the walk did not rewrite. The pair is then skipped,
// never compared under a wrong translation.
func kinRefDocument(schemaBytes []byte) ([]byte, bool) {
	doc, ok := decodeJSONNumbers(schemaBytes)
	root, isMap := doc.(map[string]any)
	if !ok || !isMap {
		return nil, false
	}
	// 2020-12-only keywords that kin's 3.0 document validation does not understand.
	// $dynamicRef with an empty URI is treated as an ignored extension keyword by kin
	// rather than triggering a document-level error, so the pair would reach comparison
	// and produce a spurious divergence. Detect these anywhere in the schema tree and
	// return ok=false (skip-only), consistent with the "dynamic" seed group documentation.
	if anyNode(doc, func(n any) bool {
		m, isMap := n.(map[string]any)
		if !isMap {
			return false
		}
		_, hasDR := m["$dynamicRef"]
		_, hasDA := m["$dynamicAnchor"]
		return hasDR || hasDA
	}) {
		return nil, false
	}
	components := map[string]any{}
	if raw, has := root["$defs"]; has {
		defs, isMap := raw.(map[string]any)
		if !isMap {
			return nil, false
		}
		for name, d := range defs {
			if !componentNameRE.MatchString(name) {
				return nil, false
			}
			components["d_"+name] = d
		}
		delete(root, "$defs")
	}
	components["S"] = root
	for _, sch := range components {
		if !rewriteSchemaRefs(sch, components) {
			return nil, false
		}
	}
	if anyNode(components, func(n any) bool {
		m, isMap := n.(map[string]any)
		if !isMap {
			return false
		}
		ref, has := m["$ref"]
		s, isStr := ref.(string)
		return has && (!isStr || !strings.HasPrefix(s, kinRefComponents))
	}) {
		return nil, false
	}
	out, err := json.Marshal(map[string]any{
		"openapi":    "3.0.3",
		"info":       map[string]any{"title": "df1-oracle-d", "version": "1"},
		"paths":      map[string]any{},
		"components": map[string]any{"schemas": components},
	})
	return out, err == nil
}

// rewriteSchemaRefs rewrites the $ref of one schema node and of its subschemas in place
// (see kinRefDocument). It returns false on a $ref it cannot map.
func rewriteSchemaRefs(node any, components map[string]any) bool {
	m, isMap := node.(map[string]any)
	if !isMap {
		return true // a boolean or malformed schema is left for kin's own validation
	}
	if raw, has := m["$ref"]; has {
		ref, isStr := raw.(string)
		if !isStr {
			return false
		}
		name, isDef := strings.CutPrefix(ref, "#/$defs/")
		_, defined := components["d_"+name]
		switch {
		case ref == "#":
			m["$ref"] = kinRefComponents + "S"
		case isDef && defined && componentNameRE.MatchString(name):
			m["$ref"] = kinRefComponents + "d_" + name
		default:
			return false
		}
	}
	return forEachSubschema(m, func(sub any) bool { return rewriteSchemaRefs(sub, components) })
}

// kinRefVerdict is the kin-openapi side of Oracle D. It loads kinRefDocument(schemaBytes)
// with openapi3.NewLoader (external refs stay disallowed, the Loader default), validates
// the document, and evaluates the instance against components.schemas.S with kin's
// BUILT-IN validator (no EnableJSONSchema2020, see the file header). ok=false means the
// pair is not comparable; panicked=true means kin panicked.
func kinRefVerdict(schemaBytes, instanceBytes []byte) (valid, ok, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			valid, ok, panicked = false, false, true
		}
	}()
	docBytes, mapped := kinRefDocument(schemaBytes)
	if !mapped {
		return false, false, false
	}
	doc, err := openapi3.NewLoader().LoadFromData(docBytes)
	if err != nil {
		return false, false, false
	}
	if err := doc.Validate(context.Background()); err != nil {
		return false, false, false
	}
	ref := doc.Components.Schemas["S"]
	if ref == nil || ref.Value == nil {
		return false, false, false
	}
	var inst any
	if err := json.NewDecoder(bytes.NewReader(instanceBytes)).Decode(&inst); err != nil {
		return false, false, false
	}
	return ref.Value.VisitJSON(inst) == nil, true, false
}

// stripRefSiblings removes every keyword next to a $ref (root $defs excepted, because
// kinRefDocument hoists it), which is what kin's Loader does under the OpenAPI 3.0
// Reference Object rule. It walks the root, root $defs and forEachSubschema. stripped is
// false when no $ref had a sibling.
func stripRefSiblings(schemaBytes []byte) (out []byte, stripped bool) {
	doc, ok := decodeJSONNumbers(schemaBytes)
	root, isMap := doc.(map[string]any)
	if !ok || !isMap {
		return nil, false
	}
	var walk func(node any, isRoot bool) bool
	walk = func(node any, isRoot bool) bool {
		m, isMap := node.(map[string]any)
		if !isMap {
			return true
		}
		if _, has := m["$ref"]; has {
			for k := range m {
				if k != "$ref" && (!isRoot || k != "$defs") {
					delete(m, k)
					stripped = true
				}
			}
		}
		if isRoot {
			defs, _ := m["$defs"].(map[string]any)
			for _, d := range defs {
				walk(d, false)
			}
		}
		return forEachSubschema(m, func(sub any) bool { return walk(sub, false) })
	}
	walk(root, true)
	if !stripped {
		return nil, false
	}
	out, err := json.Marshal(root)
	return out, err == nil
}

// refCompare is Oracle D's core: compareVerdicts with kin resolving $refs through
// kinRefVerdict, plus the one $ref-specific classification. A kin-accepts/santhosh-rejects
// split is keyed openapi-ref-sibling-ignored only when the mechanism is confirmed:
// santhosh, given the schema with the $ref siblings stripped, returns kin's verdict. A
// split the stripping does not explain keeps its Oracle-C key (usually the
// non-allowlisted verdict-differs).
func refCompare(schemaBytes, instanceBytes []byte) *schemaVerdictMismatch {
	return refCompareWith(kinRefVerdict, schemaBytes, instanceBytes)
}

// refCompareWith is refCompare with the kin side injectable, so the red tests can plant a
// divergence the real libraries do not produce.
func refCompareWith(kinFn func(schemaBytes, instanceBytes []byte) (valid, ok, panicked bool), schemaBytes, instanceBytes []byte) *schemaVerdictMismatch {
	m := compareVerdicts(kinFn, schemaBytes, instanceBytes)
	if m == nil || strings.HasSuffix(m.key, "-panic") || !m.kinV || m.jsV {
		return m
	}
	stripped, had := stripRefSiblings(schemaBytes)
	if !had {
		return m
	}
	if v, ok, panicked, _ := jsVerdict(stripped, instanceBytes); ok && !panicked && v == m.kinV {
		m.key = "openapi-ref-sibling-ignored"
	}
	return m
}

// refDiffCheck is the body of FuzzJSONSchemaRefDifferential: nil when the pair agrees, is
// not comparable, or splits only in a way allow documents.
func refDiffCheck(allow *allowlist, schemaBytes, instanceBytes []byte) error {
	if len(schemaBytes) > 1<<14 || len(instanceBytes) > 1<<14 {
		return nil
	}
	m := refCompare(schemaBytes, instanceBytes)
	if m == nil || allow.allows(m.key) {
		return nil
	}
	return fmt.Errorf("DIFFERENTIAL [kin-openapi vs jsonschema/v6, $ref-territory] "+
		"verdict disagreement (key=%s)\n  schema=%s\n  instance=%s\n  "+
		"kin-openapi.valid=%v  jsonschema.valid=%v",
		m.key, m.schema, m.inst, m.kinV, m.jsV)
}

// refSeedGroup is a named group of seed schemas. compared says whether the group must
// reach at least one verdict comparison over refInstanceSeeds (true) or is documented as
// skip-only (false); TestRefDiff_SeedsReachVerdictComparison enforces both directions.
type refSeedGroup struct {
	name     string
	compared bool
	schemas  []string
}

var refSeedGroups = []refSeedGroup{
	{name: "cycle", compared: true, schemas: []string{
		// Pure ref-only cycles: kin reports an unresolved ref (skipped); santhosh
		// compiles them and rejects every instance. Crash/hang detection only.
		`{"$ref":"#"}`,
		`{"$defs":{"A":{"$ref":"#/$defs/A"}},"$ref":"#/$defs/A"}`,
		// Legal recursive schemas: both sides resolve and evaluate them.
		`{"type":"object","properties":{"child":{"$ref":"#"}}}`,
		`{"type":"array","items":{"$ref":"#"}}`,
	}},
	{name: "defs", compared: true, schemas: []string{
		`{"$defs":{"x":{"type":"string"}},"$ref":"#/$defs/x"}`,
		`{"type":"object","properties":{"name":{"$ref":"#/$defs/name"}},"$defs":{"name":{"type":"string","minLength":1}}}`,
		// $ref with a sibling keyword: openapi-ref-sibling-ignored ("a" is too short).
		`{"$defs":{"x":{"type":"string"}},"$ref":"#/$defs/x","minLength":3}`,
		// Oracle-C splits reached through a $ref target.
		`{"$defs":{"x":{"type":"string","nullable":true}},"$ref":"#/$defs/x"}`,
		`{"$defs":{"x":{"minimum":0}},"$ref":"#/$defs/x"}`,
	}},
	{name: "dynamic", compared: false, schemas: []string{
		// 2020-12-only: kin's 3.0 document validation rejects these (skip-only).
		`{"$dynamicAnchor":"item","type":"string"}`,
		`{"$defs":{"base":{"$dynamicAnchor":"item","type":"string"}},"$dynamicRef":"#item"}`,
		// $dynamicRef with an empty URI: kin ignores it (unknown extension keyword) but
		// jsonschema/v6 treats it as a self-ref cycle. kinRefDocument now detects
		// $dynamicRef anywhere and returns ok=false before reaching comparison.
		`{"$dynamicRef":""}`,
	}},
	{name: "oracle-c", compared: true, schemas: []string{
		// Plain Oracle-C seeds, so mutations also start from the inherited splits.
		`{"type":"string","nullable":true}`, // openapi-nullable-extension
		`{"enum":[]}`,                       // enum-semantics
		`{"type":"integer"}`,                // number-coercion (1e-1000 instance)
		`{"minimum":0}`,                     // openapi-null-semantics + bignum-panic
		`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`,
	}},
}

var refInstanceSeeds = [][]byte{
	[]byte(`{}`),
	[]byte(`{"name":"alice"}`),
	[]byte(`{"child":{}}`),
	[]byte(`[[],[[]]]`),
	[]byte(`"hello"`),
	[]byte(`"a"`),
	[]byte(`42`),
	[]byte(`null`),
	[]byte(`1e1000001`), // KFZ-2026-086 shape: huge exponent
	[]byte(`1e-1000`),   // number-coercion: underflows to float64 0.0
}

// refDiffAllow holds tolerated verdict-divergence classes for Oracle D: the Oracle-C
// entries (each is reachable through a $ref target, see the "defs" seeds) plus the one
// $ref-specific split classified so far.
var refDiffAllow = func() *allowlist {
	return newAllowlist(
		expectedDiff{
			key: "openapi-ref-sibling-ignored",
			reason: "OpenAPI 3.0.3 Reference Object: properties next to `$ref` SHALL be ignored, " +
				"and kin-openapi's Loader does so (it evaluates only the ref target). JSON Schema " +
				"2020-12 applies `$ref` together with its sibling keywords, so santhosh enforces " +
				"them. kin therefore ACCEPTS what santhosh REJECTS. Keyed only when santhosh, given " +
				"the schema with the siblings stripped, returns kin's verdict. RED-PROVEN by " +
				"`{\"$defs\":{\"x\":{\"type\":\"string\"}},\"$ref\":\"#/$defs/x\",\"minLength\":3}` + `\"a\"`.",
		},
		expectedDiff{
			key: "openapi-nullable-extension",
			reason: "Inherited from Oracle C: OpenAPI 3.0 `nullable:true` is accepted by " +
				"kin-openapi; jsonschema/v6 ignores it and enforces the base `type`. See " +
				"openapiDiffAllow for the full reasoning. RED-PROVEN by " +
				"`{\"type\":\"string\",\"nullable\":true}` + `null`, and through a $ref target by " +
				"`{\"$defs\":{\"x\":{\"type\":\"string\",\"nullable\":true}},\"$ref\":\"#/$defs/x\"}` + `null`.",
		},
		expectedDiff{
			key: "enum-semantics",
			reason: "Inherited from Oracle C: empty `enum:[]`. JSON Schema 2020-12 denies " +
				"everything (no value is a member of an empty enum); kin-openapi treats it as " +
				"no constraint (allow-all). RED-PROVEN by `{\"enum\":[]}` + `{}`.",
		},
		expectedDiff{
			key: "number-coercion",
			reason: "Inherited from Oracle C: kin-openapi decodes numbers as float64; " +
				"santhosh keeps exact decimal. `1e-1000` underflows to 0.0 for float64 " +
				"and kin accepts it as a valid integer. RED-PROVEN by `{\"type\":\"integer\"}` " +
				"+ `1e-1000`.",
		},
		expectedDiff{
			key: "openapi-null-semantics",
			reason: "Inherited from Oracle C: kin-openapi rejects null for any schema without " +
				"`nullable:true`; jsonschema/v6 accepts null where `type` does not constrain it. " +
				"RED-PROVEN by `{\"minimum\":0}` + `null`.",
		},
		expectedDiff{
			key: "jsonschema-numeric-bignum-panic",
			reason: "Inherited from Oracle C: santhosh-tekuri/jsonschema/v6 v6.0.3 panics (nil " +
				"*big.Rat deref, validator.go:532) when validating a huge-exponent number against " +
				"a numeric bound keyword.  Deterministic at exponent > 1e6 with an actual bound. " +
				"kin-openapi handles the same input without panicking.  RED-PROVEN by " +
				"`{\"minimum\":0}` + `1e1000001`, and through a $ref target by " +
				"`{\"$defs\":{\"x\":{\"minimum\":0}},\"$ref\":\"#/$defs/x\"}` + `1e1000001`.",
		},
	)
}

// FuzzJSONSchemaRefDifferential is Oracle D: a verdict differential over the $ref/$defs
// territory that FuzzOpenAPIVsJSONSchema cannot compare (see the file header for what it
// does and does not cover).
func FuzzJSONSchemaRefDifferential(f *testing.F) {
	for _, g := range refSeedGroups {
		for _, s := range g.schemas {
			for _, inst := range refInstanceSeeds {
				f.Add([]byte(s), inst)
			}
		}
	}

	allow := refDiffAllow()
	f.Fuzz(func(t *testing.T, schemaBytes, instanceBytes []byte) {
		if err := refDiffCheck(allow, schemaBytes, instanceBytes); err != nil {
			t.Fatal(err)
		}
	})
}

// TestRefDiffAllowlistNoDead verifies no allowlist entry is dead over the seed
// corpus.  A dead entry is a "this divergence is documented" claim that no seed
// actually exercises — exactly the stale-skip shape.
func TestRefDiffAllowlistNoDead(t *testing.T) {
	allow := refDiffAllow()
	for _, g := range refSeedGroups {
		for _, s := range g.schemas {
			for _, inst := range refInstanceSeeds {
				if m := refCompare([]byte(s), inst); m != nil {
					allow.allows(m.key)
				}
			}
		}
	}
	allow.assertNoDeadEntries(t)
}

// TestRefDiff_SeedsReachVerdictComparison guards the condition Oracle D's claim rests on:
// that seed pairs in $ref territory actually reach a verdict comparison (both
// kinRefVerdict and jsVerdict usable). A group marked compared=true must have at least one
// compared pair, otherwise the differential is vacuous for it; a group marked
// compared=false must have none, so the file header's "skip-only" claim cannot silently
// become wrong (if kin starts evaluating $dynamicRef, re-document and flip the flag).
//
// The calibration half pins the failure that actually happened: with Oracle C's bare-schema
// kinVerdict as the kin side (Oracle D's kin side up to 9aef7b1e), the cycle and defs
// groups compare zero pairs. That is also the premise of the file header's "Oracle C
// compares no verdict in this territory".
func TestRefDiff_SeedsReachVerdictComparison(t *testing.T) {
	for _, g := range refSeedGroups {
		compared := refSeedReach(kinRefVerdict, g)
		t.Logf("group %s: compared=%d of %d pairs", g.name, compared, len(g.schemas)*len(refInstanceSeeds))
		switch {
		case g.compared && compared == 0:
			t.Errorf("group %s: no seed pair reaches a verdict comparison; Oracle D is vacuous for it", g.name)
		case !g.compared && compared != 0:
			t.Errorf("group %s: documented skip-only but %d pairs are now compared; update the file header and the flag", g.name, compared)
		}
	}
	t.Run("calibration/bare-schema-kin-side-is-vacuous", func(t *testing.T) {
		for _, g := range refSeedGroups {
			if g.name != "cycle" && g.name != "defs" {
				continue
			}
			if n := refSeedReach(kinVerdict, g); n != 0 {
				t.Errorf("group %s: bare-schema kinVerdict now compares %d pairs; the file header's Oracle C claim is stale", g.name, n)
			}
		}
	})
}

// refSeedReach counts the seed pairs of g that both kinFn and jsVerdict can use.
func refSeedReach(kinFn func(schemaBytes, instanceBytes []byte) (valid, ok, panicked bool), g refSeedGroup) int {
	compared := 0
	for _, s := range g.schemas {
		for _, inst := range refInstanceSeeds {
			_, kinOK, _ := kinFn([]byte(s), inst)
			_, jsOK, _, _ := jsVerdict([]byte(s), inst)
			if kinOK && jsOK {
				compared++
			}
		}
	}
	return compared
}
