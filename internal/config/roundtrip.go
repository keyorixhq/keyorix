package config

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/keyorixhq/keyorix/internal/securefiles"
	"gopkg.in/yaml.v3"
)

// IsNotExist reports whether err (as returned by Load) means the config file does not
// exist at all, as opposed to existing but failing to read or parse. Load wraps the
// underlying read/decode error, so the standard library's os.IsNotExist -- which predates
// errors.Is and only recognizes a narrow set of unwrapped error shapes -- does NOT
// reliably detect this through Load's wrapping; use this instead.
//
// Any caller that falls back to default values on a Load error MUST check IsNotExist
// first. Without it, a config file that exists but fails to parse (a single typo, say) is
// indistinguishable from one that was never created, and a caller that then re-Saves
// silently destroys the existing file's content -- including any security-relevant
// setting it held (#1644: a config with a stray typo plus security.require_transport_tls:
// true, run through `keyorix auth login`, came back with that control silently reverted
// to its false default and every other prior setting gone, with a plain success message).
func IsNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

// SaveFields updates only the given dot-separated YAML key paths (e.g.
// "storage.remote.base_url" -- YAML key names, not Go struct field names) in the config
// file at path, leaving every other key, value, comment, and the existing ordering
// untouched. This is the fix for the second half of #1644: Save re-marshals the entire
// *Config struct, which silently reconstitutes the whole file from whatever that
// in-memory value does or doesn't have set -- any field the caller didn't explicitly
// carry over from a prior Load is written back at its Go zero value, and comments/
// ordering are lost outright. SaveFields never touches a key the caller didn't name.
//
// If path does not exist yet, a new file containing only these fields is created
// (mirroring Save's existing fresh-install behavior). If path exists but its content is
// not valid YAML, SaveFields returns an error and writes nothing -- it applies the same
// "a parse failure is not licence to replace the file" rule Load already follows, for the
// write side. Values are marshaled via yaml.Node.Encode, so any YAML-marshalable Go value
// (string, bool, int, ...) is accepted.
func SaveFields(path string, fields map[string]any) error {
	if path == "" {
		path = filepath.Join(appRootDir, "keyorix.yaml")
	}

	baseDir, rwPath := appRootDir, path
	if filepath.IsAbs(path) {
		baseDir, rwPath = filepath.Dir(path), filepath.Base(path)
	}

	var doc yaml.Node
	data, err := securefiles.SafeReadFile(baseDir, rwPath)
	switch {
	case err == nil:
		if uerr := yaml.Unmarshal(data, &doc); uerr != nil {
			return fmt.Errorf("failed to parse existing config file %q: %w", path, uerr)
		}
	case IsNotExist(err):
		// No existing content — doc stays its zero value; filled in below.
	default:
		return fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode}
	}
	if len(doc.Content) == 0 {
		doc.Content = append(doc.Content, &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"})
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("config file %q does not contain a YAML mapping at its root", path)
	}

	for keyPath, value := range fields {
		if err := yamlSetField(root, strings.Split(keyPath, "."), value); err != nil {
			return fmt.Errorf("failed to set %q: %w", keyPath, err)
		}
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := securefiles.SecureWriteFileSync(baseDir, rwPath, out, 0o600); err != nil {
		return fmt.Errorf("failed to write config file %q: %w", path, err)
	}
	return nil
}

// yamlSetField sets value at the given dot-path within a YAML mapping node, creating
// intermediate mapping nodes as needed and overwriting (rather than merging into) any
// existing non-mapping node found along an intermediate segment.
func yamlSetField(mapping *yaml.Node, path []string, value any) error {
	key := path[0]
	idx := -1
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			idx = i
			break
		}
	}

	if len(path) == 1 {
		valNode := &yaml.Node{}
		if err := valNode.Encode(value); err != nil {
			return err
		}
		if idx == -1 {
			mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, valNode)
		} else {
			mapping.Content[idx+1] = valNode
		}
		return nil
	}

	var child *yaml.Node
	if idx == -1 {
		child = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, child)
	} else {
		child = mapping.Content[idx+1]
		if child.Kind != yaml.MappingNode {
			child.Kind, child.Tag, child.Content, child.Value = yaml.MappingNode, "!!map", nil, ""
		}
	}
	return yamlSetField(child, path[1:], value)
}
