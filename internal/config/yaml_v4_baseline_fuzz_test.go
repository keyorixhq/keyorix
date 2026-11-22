package config

// One fuzz target per go.yaml.in/yaml/v4 path left unguarded after #4573 (#4574). Each
// checks only properties v4 must keep on its own; there is no second parser. Seeds are
// committed under testdata/fuzz/<FuzzName>/ and replay in the normal `go test` tier.

import (
	"bytes"
	"errors"
	"io"
	"testing"

	yaml "go.yaml.in/yaml/v4"
)

const baselineFuzzMaxInput = 8192

func baselineSeeds(f *testing.F) {
	for _, s := range []string{
		"", "environment: a\n", "storage:\n  type: postgres\n  database:\n    native_read_pool_max: 12\n",
		"security:\n  require_mfa: true\n", "environment: 7\n", "storage:\n  - type\n",
		"environment: a\n---\nenvironment: b\n", "environment: a\n---\nbogus: 1\n",
		"environment: &e a\nminimum_cli_version: *e\n", "environment: a\nenvironment: b\n",
		"bogus: ~\n", "storage: {type: postgres, bogus: 1}\n", "- 1\n- 2\n", "[unterminated",
	} {
		f.Add([]byte(s))
	}
}

// The typed-decode target (typed decode rejects what `any` decode rejects) is NOT in this
// file: go-yaml v4 violates that property (a struct decode never constructs the value of a
// key that has no field, so a self-referencing anchor or a duplicate key inside such a value
// is accepted). It is reported as NEEDS DECISION: third-party finding go-yaml.

// FuzzYAMLV4MultiDocument: walking a stream with the v4 Loader never panics or loops, and
// reads every document: when both the untyped and the typed walk reach EOF cleanly they
// must have seen the same number of documents.
func FuzzYAMLV4MultiDocument(f *testing.F) {
	baselineSeeds(f)
	f.Add([]byte("a: 1\n---\nb: 2\n---\nc: 3\n"))
	f.Add([]byte("---\n---\n---\n"))
	f.Add([]byte("a: 1\n...\n---\nb: 2\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > baselineFuzzMaxInput {
			return
		}
		untypedDocs, untypedErr := walkStream(data, func() any { return new(any) })
		typedDocs, typedErr := walkStream(data, func() any { return new(Config) })
		// No typed-rejects-what-`any`-rejects check here: a struct decode does not construct
		// the value of a key with no field, so it accepts some streams the `any` walk
		// refuses (NEEDS DECISION: third-party finding go-yaml, see the PR report).
		if untypedErr == nil && typedErr == nil && untypedDocs != typedDocs {
			t.Fatalf("document count differs between walks: any=%d typed=%d\n  input=%q", untypedDocs, typedDocs, data)
		}
	})
}

// walkStream loads every document of data with the v4 Loader into a fresh value from
// mk, returning how many it read. It stops on the first error other than io.EOF.
func walkStream(data []byte, mk func() any) (int, error) {
	l, err := yaml.NewLoader(bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	n := 0
	for range baselineFuzzMaxInput + 1 { // a document needs at least one byte; more means the Loader is stuck
		err := l.Load(mk())
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		n++
	}
	return n, errors.New("loader produced more documents than input bytes")
}

// FuzzYAMLV4KnownFields: strict decoding never panics and is never more permissive than a
// plain decode, and appending a key no Config field has to a mapping that a plain decode
// accepts is rejected in strict mode while the plain decode still accepts it.
func FuzzYAMLV4KnownFields(f *testing.F) {
	baselineSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > baselineFuzzMaxInput {
			return
		}
		var plain Config
		plainErr := yaml.Unmarshal(data, &plain)

		var strict Config
		strictErr := yaml.Load(data, &strict, yaml.WithKnownFields(), yaml.WithSingleDocument())
		if plainErr != nil && strictErr == nil {
			t.Fatalf("KnownFields accepted what a plain decode rejects\n  input=%q\n  plain error=%v", data, plainErr)
		}
		if plainErr != nil {
			return
		}

		var root yaml.Node
		if yaml.Unmarshal(data, &root) != nil || root.Kind != yaml.DocumentNode || len(root.Content) != 1 {
			return
		}
		m := root.Content[0]
		if m.Kind != yaml.MappingNode {
			return
		}
		const unknown = "zz_unknown_key_v4_baseline"
		m.Content = append(m.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: unknown},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "1"})
		injected, err := yaml.Marshal(&root)
		if err != nil {
			return
		}
		var again Config
		if err := yaml.Unmarshal(injected, &again); err != nil {
			return // re-encoding changed what the plain decode accepts; not this property
		}
		var s Config
		if err := yaml.Load(injected, &s, yaml.WithKnownFields(), yaml.WithSingleDocument()); err == nil {
			t.Fatalf("KnownFields accepted an unknown key a plain decode accepts\n  original=%q\n  injected=%q", data, injected)
		}
	})
}
