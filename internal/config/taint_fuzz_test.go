//go:build taintoverlay

package config

// Input-to-sink taint harness for config loading (see internal/fuzzutil/taint).
// One string leaf of a valid config is replaced by a marker-bearing value per
// iteration (the fuzzer picks the leaf and the marker position), then the file
// is loaded and validated. Contract allow-list, fixed before the first run:
// config fields legitimately name files (cert/key/db/log/secret paths) and
// endpoints (hosts), so path and host flows are allowed and recorded; a flow
// into a command, query or template is unexpected.
//
// Run: go test -tags taintoverlay -overlay <taintoverlay dir>/overlay.json \
//        -vet=off -run '^$' -fuzz FuzzTaintConfigLoad ./internal/config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/taint"
)

func stringLeaves(n *yaml.Node, out *[]*yaml.Node) {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 1; i < len(n.Content); i += 2 { // values only
			stringLeaves(n.Content[i], out)
		}
	case yaml.SequenceNode, yaml.DocumentNode:
		for _, c := range n.Content {
			stringLeaves(c, out)
		}
	case yaml.ScalarNode:
		if n.Tag == "!!str" {
			*out = append(*out, n)
		}
	}
}

func FuzzTaintConfigLoad(f *testing.F) {
	// Base document: the zero Config marshalled, so every YAML key of the config
	// surface is present with an (empty) string leaf the harness can taint.
	base, err := yaml.Marshal(&Config{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint16(0), uint8(0), "a")
	taint.Allow(
		taint.Rule{Class: taint.Path, Why: "config fields name files (operator-trusted)"},
		taint.Rule{Class: taint.Host, Why: "config fields name endpoints (operator-trusted)"},
	)
	f.Fuzz(func(t *testing.T, leaf uint16, mode uint8, extra string) {
		taint.RequireOverlay(t.Fatalf)
		taint.Reset()
		defer taint.Check(t.Fatalf)
		var doc yaml.Node
		if err := yaml.Unmarshal(base, &doc); err != nil {
			t.Skip(err)
		}
		var leaves []*yaml.Node
		stringLeaves(&doc, &leaves)
		if len(leaves) == 0 {
			t.Skip("no string leaves")
		}
		n := leaves[int(leaf)%len(leaves)]
		if mode%2 == 0 {
			n.Value = taint.Str(extra)
		} else {
			n.Value = taint.PathStr(extra)
		}
		out, err := yaml.Marshal(&doc)
		if err != nil {
			t.Skip(err)
		}
		p := filepath.Join(t.TempDir(), "keyorix.yaml")
		if err := os.WriteFile(p, out, 0o600); err != nil {
			t.Skip(err)
		}
		cfg, err := Load(p)
		if err != nil || cfg == nil {
			return
		}
		_ = cfg.Validate()
		_ = cfg.ValidateSecretSources()
	})
}
