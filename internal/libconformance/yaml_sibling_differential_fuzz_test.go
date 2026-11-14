package libconformance

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	newyaml "go.yaml.in/yaml/v3"
	oldyaml "gopkg.in/yaml.v3"
)

// FuzzYAMLSiblingDifferential is a differential fuzz target over the two
// sibling YAML v3 implementations this module links:
//
//   - gopkg.in/yaml.v3 v3.0.1  — the historical import path, used directly by
//     Keyorix tooling (scripts/e2e, scripts/metrics/{surfacewalk,cfgkeys},
//     scripts/fuzzing/configspace, scripts/ci/guardinputs — traced live callers).
//   - go.yaml.in/yaml/v3 v3.0.5 — the project's new canonical home for the same
//     library, pulled transitively (via oasdiff) at a LATER tag. It is the drop-in
//     successor the ecosystem is migrating to.
//
// They share a lineage but are DIFFERENT releases (v3.0.1 vs v3.0.5), so "do
// they still agree, byte-for-byte, on accept/reject and decoded value?" is a
// real question — the answer is the slide "where equivalent libraries disagree".
//
// Oracles (each a classified disagreement, never panic-only — a panic in either
// library also surfaces natively and is itself a finding):
//
//   - ACCEPT/REJECT PARITY: for the same bytes, both libraries must either both
//     accept (nil error) or both reject. A split verdict is a disagreement; it is
//     only tolerated if its normalized class is listed in the EXPECTED-DIFFERENCE
//     table (yamlExpectedDiff). Any UNLISTED split fails the target.
//   - DECODED-VALUE EQUALITY: when BOTH accept, the two decoded values must be
//     equal. Equality is checked by re-marshalling each decoded value with ONE
//     fixed encoder (gopkg) and comparing the bytes — this is order-independent
//     (Marshal sorts map keys), NaN-stable (both re-encode to `.nan`) and immune
//     to int/float formatting nuances, at the cost noted in "what it does NOT
//     verify". A mismatch is a disagreement, gated by the same table.
//   - DUPLICATE-KEY PRE-SCAN CONSISTENCY (the internal/yamlsafe surrogate):
//     internal/yamlsafe is absent from this tree, so the duplicate-key pre-scan
//     the task calls for is implemented here (yamlHasDuplicateKey, test-only). The
//     property: if the pre-scan finds a duplicate mapping key, then a library that
//     nonetheless ACCEPTS the document (silently keeping one of the colliding
//     values) is a finding — that is exactly the key-shadowing bug a yamlsafe
//     pre-scan exists to stop. Both libraries are expected to reject duplicate
//     keys natively since yaml.v3; a library accepting one is the disagreement.
func FuzzYAMLSiblingDifferential(f *testing.F) {
	seeds := []string{
		"",
		"null",
		"x: 1",
		"x: 1\ny: 2\n",
		"x: 1\nx: 2\n",            // duplicate key (both expected to reject)
		"- 1\n- 2\n- 3\n",         // sequence
		"a:\n  b:\n    c: 1\n",     // nested maps
		"foo: !!str 123\n",        // explicit tag
		"n: .nan\ni: .inf\n",      // float specials
		"big: 0x7fffffffffffffff\n", // hex int
		"t: true\nf: no\n",        // bools / yaml 1.1 vs 1.2
		"s: 2020-01-02\n",         // timestamp
		"anchor: &a 1\nref: *a\n",  // anchor/alias
		"key: |\n  multi\n  line\n", // block scalar
		"? [a, b]\n: val\n",        // complex mapping key
		"'': empty-key\n",          // empty key
		"a: 1\nb: {c: 2, c: 3}\n",   // nested duplicate key
		"---\na: 1\n---\nb: 2\n",    // multi-document (single-value decode)
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Bound the input: YAML's alias expansion and deep nesting are a known
		// DoS surface (yaml.v3 caps alias expansion internally); we are testing
		// parity, not re-testing their DoS caps, so keep inputs modest so a slow
		// pathological expansion in ONE library does not masquerade as a
		// disagreement with the other.
		if len(data) > 4096 {
			return
		}

		var vNew, vOld any
		errNew := newyaml.Unmarshal(data, &vNew)
		errOld := oldyaml.Unmarshal(data, &vOld)

		acceptNew := errNew == nil
		acceptOld := errOld == nil

		// Oracle 1: accept/reject parity.
		if acceptNew != acceptOld {
			class := classifyYAMLSplit(errNew, errOld)
			if !yamlExpectedDiff[class] {
				t.Fatalf("NEW accept/reject disagreement [class=%q]\n  input=%q\n  go.yaml.in accept=%v err=%v\n  gopkg      accept=%v err=%v",
					class, data, acceptNew, errNew, acceptOld, errOld)
			}
			return // a listed split: the two libraries legitimately diverge here.
		}

		if !acceptNew {
			// Both rejected — nothing more to compare.
			return
		}

		// Oracle 2: decoded-value equality via one fixed canonical encoder.
		canonNew, mErrNew := oldyaml.Marshal(vNew)
		canonOld, mErrOld := oldyaml.Marshal(vOld)
		if mErrNew != nil || mErrOld != nil {
			// Re-encoding a decoded value should not fail; if it does, the value
			// shape itself differs in a way the encoder rejects — surface it.
			if (mErrNew == nil) != (mErrOld == nil) {
				t.Fatalf("re-encode disagreement\n  input=%q\n  newErr=%v oldErr=%v", data, mErrNew, mErrOld)
			}
			return
		}
		if !reflect.DeepEqual(canonNew, canonOld) {
			class := "value-mismatch"
			if !yamlExpectedDiff[class] {
				t.Fatalf("NEW decoded-value disagreement\n  input=%q\n  go.yaml.in canonical=%q\n  gopkg      canonical=%q",
					data, canonNew, canonOld)
			}
		}

		// Oracle 3: duplicate-key pre-scan consistency.
		// Both libraries accepted. If a duplicate mapping key is present, at least
		// one colliding value was silently dropped — a yamlsafe pre-scan would
		// reject it. Since yaml.v3 rejects duplicates natively, reaching here with
		// a duplicate means the library FAILED to, which is the finding.
		if dup, where := yamlHasDuplicateKey(data); dup {
			t.Fatalf("duplicate-key SHADOWING accepted by a sibling that should reject it\n  input=%q\n  duplicate at: %s\n  (yamlsafe pre-scan would reject; native yaml.v3 is expected to as well)", data, where)
		}
	})
}

// classifyYAMLSplit maps a split accept/reject verdict to a stable, coarse class
// string so the EXPECTED-DIFFERENCE table can enumerate the known divergences by
// name rather than by exact error text (which carries line/column noise).
func classifyYAMLSplit(errNew, errOld error) string {
	// Exactly one is non-nil here (callers guarantee a split).
	msg := ""
	side := ""
	if errNew != nil {
		msg, side = errNew.Error(), "go.yaml.in-rejects"
	} else {
		msg, side = errOld.Error(), "gopkg-rejects"
	}
	msg = strings.ToLower(msg)
	switch {
	case strings.Contains(msg, "already defined"):
		return side + ":duplicate-key"
	case strings.Contains(msg, "alias") || strings.Contains(msg, "anchor"):
		return side + ":alias"
	case strings.Contains(msg, "unmarshal errors"):
		return side + ":type"
	case strings.Contains(msg, "did not find expected") || strings.Contains(msg, "could not find expected"):
		return side + ":syntax"
	case strings.Contains(msg, "control characters are not allowed"):
		return side + ":control-char"
	case strings.Contains(msg, "mapping values are not allowed"):
		return side + ":mapping-context"
	default:
		return side + ":other"
	}
}

// yamlHasDuplicateKey is the test-only duplicate-key pre-scan standing in for the
// absent internal/yamlsafe package. It walks the document's node tree and reports
// the first mapping that contains two entries whose keys render to the same
// canonical string. It uses gopkg's node API (the direct-dependency library).
func yamlHasDuplicateKey(data []byte) (bool, string) {
	var root oldyaml.Node
	if err := oldyaml.Unmarshal(data, &root); err != nil {
		return false, ""
	}
	return walkDupKey(&root, "$")
}

func walkDupKey(n *oldyaml.Node, path string) (bool, string) {
	switch n.Kind {
	case oldyaml.DocumentNode, oldyaml.SequenceNode:
		for i, c := range n.Content {
			if dup, w := walkDupKey(c, fmt.Sprintf("%s[%d]", path, i)); dup {
				return true, w
			}
		}
	case oldyaml.MappingNode:
		seen := make(map[string]bool, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := canonKey(n.Content[i])
			if seen[k] {
				return true, fmt.Sprintf("%s key %q", path, k)
			}
			seen[k] = true
			if dup, w := walkDupKey(n.Content[i+1], path+"."+k); dup {
				return true, w
			}
		}
	}
	return false, ""
}

// canonKey renders a key node to a stable string. For scalars it is the value;
// for composite keys (YAML complex keys) it is a sorted structural rendering so
// that two equal composite keys collide.
func canonKey(n *oldyaml.Node) string {
	switch n.Kind {
	case oldyaml.ScalarNode:
		return "s:" + n.Tag + ":" + n.Value
	case oldyaml.SequenceNode:
		parts := make([]string, 0, len(n.Content))
		for _, c := range n.Content {
			parts = append(parts, canonKey(c))
		}
		return "seq:[" + strings.Join(parts, ",") + "]"
	case oldyaml.MappingNode:
		parts := make([]string, 0, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			parts = append(parts, canonKey(n.Content[i])+"="+canonKey(n.Content[i+1]))
		}
		sort.Strings(parts)
		return "map:{" + strings.Join(parts, ",") + "}"
	case oldyaml.AliasNode:
		if n.Alias != nil {
			return "alias:" + canonKey(n.Alias)
		}
		return "alias:?"
	default:
		return "?:" + n.Value
	}
}
