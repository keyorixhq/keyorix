package config

import (
	"fmt"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/securefiles"
	"gopkg.in/yaml.v3"
)

// ExplicitlySetPaths reads the config file at path (resolved exactly as Load
// resolves it) and returns every dotted YAML key path the file literally
// writes, intermediate mappings included. Sequences are flattened the same
// way InsecureSetting.SourcePaths spells them: a key under any element of
// sso.providers is reported as sso.providers.<key>, with no index.
//
// This is how the posture report tells an EXPLICIT weakening (the file asks
// for it) from a SHIPPED DEFAULT (the file says nothing, and the weak state is
// what Load resolves an absent key to). It reports presence, not value: a file
// that writes `require_transport_tls: false` has explicitly asked for
// cleartext, even though false is also the default.
//
// What it does not see: a YAML merge key (`<<: *anchor`) is reported as the
// literal key "<<", not expanded, so a setting arriving only through a merge
// reads as not explicitly set.
func ExplicitlySetPaths(path string) (map[string]bool, error) {
	path = ResolvedPath(path)
	baseDir, readPath := appRootDir, path
	if filepath.IsAbs(path) {
		baseDir, readPath = filepath.Dir(path), filepath.Base(path)
	}
	data, err := securefiles.SafeReadFile(baseDir, readPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}
	return explicitlySetPathsIn(data)
}

func explicitlySetPathsIn(data []byte) (map[string]bool, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	paths := map[string]bool{}
	var walk func(n *yaml.Node, prefix string)
	walk = func(n *yaml.Node, prefix string) {
		switch n.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, c := range n.Content {
				walk(c, prefix)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				p := n.Content[i].Value
				if prefix != "" {
					p = prefix + "." + p
				}
				paths[p] = true
				walk(n.Content[i+1], p)
			}
		}
	}
	walk(&root, "")
	return paths, nil
}
