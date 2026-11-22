package config

// FuzzYAMLV4TypedDecode (#4574): properties go.yaml.in/yaml/v4 keeps for a typed decode into
// Config. It deliberately does NOT assert "typed decode rejects what `any` decode rejects":
// a struct decode never constructs the value of a key that has no field, so it accepts a
// self-referencing anchor or a duplicate key under an ignored key that an `any` decode
// refuses. That is go-yaml design (yaml.v3 behaves the same), Keyorix is unaffected, and it
// is recorded in docs/findings/2026-11-22-TRIAGE-go-yaml-typed-decode-skips-ignored-values.md.
// The two inputs that showed it are seeds under testdata/fuzz/FuzzYAMLV4TypedDecode/ and
// must pass this target.

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v4"
)

// typedDecodeBudget is generous on purpose: the inputs are capped at baselineFuzzMaxInput
// bytes, so a decode that needs seconds is a work-bound failure, not a slow runner.
const typedDecodeBudget = 10 * time.Second

func FuzzYAMLV4TypedDecode(f *testing.F) {
	baselineSeeds(f)
	f.Add([]byte("&e \n0: *e"))    // anchor cycle under an ignored key (triage entry, input 1)
	f.Add([]byte(": {s,s}"))       // duplicate key inside an ignored value (triage entry, input 2)
	f.Add([]byte("zz: &e [*e]\n")) // same mechanism, parses in yaml.v3 too
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > baselineFuzzMaxInput {
			return
		}

		// Bounded work, no panic (a panic fails the fuzz run by itself), deterministic result.
		start := time.Now()
		var a, b Config
		errA := yaml.Unmarshal(data, &a)
		errB := yaml.Unmarshal(data, &b)
		if d := time.Since(start); d > typedDecodeBudget {
			t.Fatalf("two typed decodes of %d bytes took %v\n  input=%q", len(data), d, data)
		}
		if (errA == nil) != (errB == nil) || (errA != nil && errA.Error() != errB.Error()) {
			t.Fatalf("typed decode is not deterministic: errors differ\n  first=%v\n  second=%v\n  input=%q", errA, errB, data)
		}
		if errA == nil && !sameConfig(t, &a, &b) {
			t.Fatalf("typed decode is not deterministic: values differ\n  input=%q", data)
		}
		if errA != nil {
			return
		}

		// Under KnownFields an unknown top-level key is rejected, naming the key and not
		// echoing its value, while the plain decode of the same bytes still accepts it.
		var root yaml.Node
		if yaml.Unmarshal(data, &root) != nil || root.Kind != yaml.DocumentNode || len(root.Content) != 1 {
			return
		}
		m := root.Content[0]
		if m.Kind != yaml.MappingNode {
			return
		}
		const unknown, marker = "zz_unknown_typed_decode", "MARKER-NOT-A-SECRET"
		m.Content = append(m.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: unknown},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: marker})
		injected, err := yaml.Marshal(&root)
		if err != nil {
			return
		}
		var plain Config
		if yaml.Unmarshal(injected, &plain) != nil {
			return // re-encoding changed what the plain decode accepts; not this property
		}
		var strict Config
		err = yaml.Load(injected, &strict, yaml.WithKnownFields(), yaml.WithSingleDocument())
		if err == nil {
			t.Fatalf("KnownFields accepted an unknown top-level key\n  original=%q\n  injected=%q", data, injected)
		}
		if !strings.Contains(err.Error(), unknown) || strings.Contains(err.Error(), marker) {
			t.Fatalf("KnownFields error must name the key and not echo its value: %q\n  injected=%q", err, injected)
		}
	})
}

// sameConfig reports whether two decodes of the same bytes produced the same value. NaN
// floats never compare equal under DeepEqual, so fall back to the encoded form.
func sameConfig(t *testing.T, a, b *Config) bool {
	t.Helper()
	if reflect.DeepEqual(a, b) {
		return true
	}
	ea, errA := yaml.Marshal(a)
	eb, errB := yaml.Marshal(b)
	if errA != nil || errB != nil {
		return errA != nil && errB != nil && errA.Error() == errB.Error()
	}
	return bytes.Equal(ea, eb)
}
