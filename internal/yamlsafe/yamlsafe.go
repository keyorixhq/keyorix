// Package yamlsafe decodes YAML that an operator hands to Keyorix (an import
// file, an agent config) without paying the quadratic cost go.yaml.in/yaml/v4
// charges for a mapping that repeats a key.
//
// The library returns its "mapping key already defined" error only after
// comparing each key against every earlier key, so a document of n identical
// keys costs O(n^2) time and memory: about 1.4 GB for a 20 KB file
// (https://github.com/yaml/go-yaml/issues/510). A size cap sized for a linear
// parser does not bound that. Unmarshal parses to a node tree first (linear),
// rejects the first duplicate key with a hash set, and only then decodes into
// the target, so the same input fails fast and in linear time.
//
// The library's own pairwise check is switched off for the decode (it is O(n^2)
// in time even when no key repeats: 100000 distinct keys, about 1 MB, cost two
// minutes). The pre-check is a superset of it: it also rejects every pair of keys
// the library would count as equal (same kind and raw value), including merge
// keys, non-scalar keys and keys that fail to decode. Documents that pass decode
// like yaml.Unmarshal, with these deliberate differences, all fail-closed: a
// repeated merge key (<<), a repeated sequence or mapping key, and keys that
// resolve to the same value through different spellings (1 and 01, which the
// library accepts because it compares raw text) are rejected.
//
// This package imports only the YAML library and the standard library, so the
// CLI module may use it without widening its dependency closure.
package yamlsafe

import (
	"fmt"

	"go.yaml.in/yaml/v4"
)

// Unmarshal is yaml.Unmarshal with an up-front, linear-time duplicate-key check.
// It decodes only the first document, like yaml.Unmarshal, and an empty
// document leaves v untouched.
func Unmarshal(data []byte, v any) error {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	if root.Kind == 0 {
		return nil // empty input: nothing to decode, v stays as it was
	}
	if err := CheckDuplicateKeys(&root); err != nil {
		return err
	}
	return root.Load(v, yaml.WithV3Defaults(), yaml.WithUniqueKeys(false))
}

// CheckDuplicateKeys returns an error naming the first mapping key that appears
// twice in the same mapping anywhere under n. Scalar keys are compared by their
// decoded value, so 1, 01 and 0x1 count as the same key (stricter than the
// library, which compares the raw text). Every key, whatever its kind, is also
// compared by kind and raw value, the identity the library uses, so merge keys
// and sequence or mapping keys cannot repeat either.
func CheckDuplicateKeys(n *yaml.Node) error {
	return walk(n, 0)
}

// maxDepth bounds the walk. The parser already refuses documents nested deeper
// than its own limit; this is a second guard so a future parser change cannot
// turn the walk into unbounded recursion.
const maxDepth = 10000

// rawKey is the identity the library's own duplicate check uses.
type rawKey struct {
	kind  yaml.Kind
	value string
}

func walk(n *yaml.Node, depth int) error {
	if n == nil {
		return nil
	}
	if depth > maxDepth {
		return fmt.Errorf("line %d: document is nested too deeply", n.Line)
	}
	if n.Kind == yaml.MappingNode {
		seen := make(map[any]int, len(n.Content)/2)
		raw := make(map[rawKey]int, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			orig := n.Content[i]
			rk := rawKey{orig.Kind, orig.Value}
			if first, dup := raw[rk]; dup {
				return fmt.Errorf("line %d: mapping key %q already defined at line %d", orig.Line, orig.Value, first)
			}
			raw[rk] = orig.Line
			k := orig
			if k.Kind == yaml.AliasNode && k.Alias != nil {
				k = k.Alias
			}
			if k.Kind == yaml.ScalarNode && k.Tag != "!!merge" {
				var key any
				if err := k.Decode(&key); err == nil {
					if first, dup := seen[key]; dup {
						return fmt.Errorf("line %d: mapping key %q already defined at line %d", n.Content[i].Line, k.Value, first)
					}
					seen[key] = n.Content[i].Line
				}
			}
			if err := walk(n.Content[i], depth+1); err != nil {
				return err
			}
			if err := walk(n.Content[i+1], depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, c := range n.Content {
		if err := walk(c, depth+1); err != nil {
			return err
		}
	}
	return nil
}
