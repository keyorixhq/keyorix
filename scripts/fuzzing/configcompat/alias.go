package configcompat

import (
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/config"
)

// AliasPair is one deprecated-key rename: the old dotted YAML path and its
// current insecure_ replacement, taken verbatim from the config package's own
// alias table so this harness can never drift from the code it checks.
type AliasPair struct {
	Old string
	New string
}

// aliasPairs returns the renamed-key table the loader actually honours. It is
// config.DeprecatedSettingAliasPaths(), not a copy — if a row is added or
// removed in the production table, the fuzzer sees it on the next run.
func aliasPairs() []AliasPair {
	raw := config.DeprecatedSettingAliasPaths()
	out := make([]AliasPair, 0, len(raw))
	for _, p := range raw {
		out = append(out, AliasPair{Old: p[0], New: p[1]})
	}
	return out
}

// buildDoc renders a minimal YAML document that sets the single dotted path to
// value. A segment ending in "[]" names a one-element sequence, matching the
// alias table's own "[]" convention (sso.providers[], fallbacks[]). It builds a
// nested map/slice and marshals it, so indentation and quoting are always
// well-formed.
func buildDoc(path string, value any) []byte {
	segs := strings.Split(path, ".")
	tree := nest(segs, value)
	b, err := yaml.Marshal(tree)
	if err != nil {
		return nil
	}
	return b
}

// nest builds the nested structure for segs with value at the leaf. A "[]"
// segment produces a map key whose value is a one-element slice holding the
// rest of the structure.
func nest(segs []string, value any) any {
	if len(segs) == 0 {
		return value
	}
	seg := segs[0]
	if name, ok := strings.CutSuffix(seg, "[]"); ok {
		return map[string]any{name: []any{nest(segs[1:], value)}}
	}
	return map[string]any{seg: nest(segs[1:], value)}
}

// rawHasPath reports whether the dotted path's leaf key is present anywhere the
// path describes in the raw YAML tree. Sequence ("[]") segments match every
// element. Used by I2 to tell an explicit operator opt-in apart from an
// inherited default. A parse error yields false (the strict decode elsewhere is
// where a malformed file is reported).
func rawHasPath(data []byte, path string) bool {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil || len(root.Content) == 0 {
		return false
	}
	return nodeHasPath(root.Content[0], strings.Split(path, "."))
}

func nodeHasPath(n *yaml.Node, segs []string) bool {
	if n == nil || len(segs) == 0 {
		return false
	}
	seg := segs[0]
	if name, ok := strings.CutSuffix(seg, "[]"); ok {
		_, seq := mapChild(n, name)
		if seq == nil || seq.Kind != yaml.SequenceNode {
			return false
		}
		for _, item := range seq.Content {
			if nodeHasPath(item, segs[1:]) {
				return true
			}
		}
		return false
	}
	k, v := mapChild(n, seg)
	if k == nil {
		return false
	}
	if len(segs) == 1 {
		return true
	}
	return nodeHasPath(v, segs[1:])
}

// mapChild returns the key and value nodes for key in mapping node m, or
// (nil, nil).
func mapChild(m *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}
