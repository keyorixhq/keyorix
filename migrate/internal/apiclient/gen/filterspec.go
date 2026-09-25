// Command filterspec produces a narrowed copy of server/http/handlers/openapi.yaml
// containing only the paths keyorix-migrate's generated client actually needs. Ported from
// cli/internal/apiclient/gen/filterspec.go (same shape, own keptPaths list) rather than
// imported: migrate cannot depend on cli/ (docs/design-keyorix-migrate.md's "Module
// boundaries" section) and the two tools' path sets diverge from the start (migrate never
// needs auth/rbac/audit/compliance routes at all).
//
// `components:` is kept in full, same reasoning as cli/'s filterspec: openapi.yaml is
// $ref-heavy, and a wrong reference-pruning pass silently breaking a kept path's schema is a
// worse failure than a few dozen extra unused generated types.
//
// Run via `make -C migrate client` (see migrate/Makefile), not directly.
package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// keptPaths is the worklist: as migrate wires new command groups (AWS/Azure/GCP sources,
// Step 3), add the REST paths they need here and re-run `make -C migrate client`.
var keptPaths = []string{
	"/api/v1/version",
	"/api/v1/projects",
	"/api/v1/projects/{id}/environments",
	"/api/v1/secrets",
	"/api/v1/secrets/{id}",
	"/api/v1/secrets/by-name",
	// Preflight (docs/design-keyorix-migrate.md's "Pre-flight check"): confirm the PAT is
	// valid, not near expiry, and scoped to write in the target project/environment, before
	// any Vault traffic or Keyorix write happens.
	"/api/v1/auth/tokens",
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: filterspec <input-openapi.yaml> <output-openapi.yaml>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "filterspec:", err)
		os.Exit(1)
	}
}

func run(inPath, outPath string) error {
	data, err := os.ReadFile(inPath) // #nosec G304 G703 -- inPath/outPath are argv from `make client`, a local dev/CI codegen tool, not user/network input
	if err != nil {
		return fmt.Errorf("read %s: %w", inPath, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", inPath, err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: unexpected document shape", inPath)
	}
	root := doc.Content[0]

	pathsNode, ok := mappingValue(root, "paths")
	if !ok {
		return fmt.Errorf("%s: no top-level 'paths' key", inPath)
	}

	kept := map[string]bool{}
	for _, p := range keptPaths {
		kept[p] = true
	}

	var filteredContent []*yaml.Node
	found := map[string]bool{}
	for i := 0; i+1 < len(pathsNode.Content); i += 2 {
		keyNode, valNode := pathsNode.Content[i], pathsNode.Content[i+1]
		if kept[keyNode.Value] {
			filteredContent = append(filteredContent, keyNode, valNode)
			found[keyNode.Value] = true
		}
	}
	for _, p := range keptPaths {
		if !found[p] {
			return fmt.Errorf("%s: keptPaths entry %q does not exist in the source spec", inPath, p)
		}
	}
	pathsNode.Content = filteredContent

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("marshal filtered spec: %w", err)
	}
	if err := os.WriteFile(outPath, out, 0o600); err != nil { // #nosec G304 G703 -- see the ReadFile call above
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	return nil
}

func mappingValue(m *yaml.Node, key string) (*yaml.Node, bool) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1], true
		}
	}
	return nil, false
}
