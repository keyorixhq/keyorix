// Command filterspec produces a narrowed copy of server/http/handlers/openapi.yaml
// containing only the paths the thin CLI's generated client actually needs, per Phase 3 PR
// (docs/cli-split-inventory.md §7). Generating a client for the full ~167-operation spec
// when a given PR wires only a handful of them (PR 0: 4) produces a client dominated by
// dead generated code -- narrowing the INPUT spec keeps the generated OUTPUT proportionate
// to what's actually used, while still being real generation from the canonical API
// definition (ADR-106), not a hand-maintained subset.
//
// `components:` is kept in full rather than reference-chased down to only what the kept
// paths use: openapi.yaml is 400+ $ref-heavy, and a wrong reference-pruning pass silently
// breaking a kept path's schema would be a worse failure mode than a few dozen extra unused
// generated types (server/http/handlers/openapi.yaml's own components section is not large
// enough for that trade to matter).
//
// Run via `make -C cli client` (see cli/Makefile), not directly -- see this repo's root
// Makefile for the analogous `make proto` pattern.
package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// keptPaths is the worklist: as each Phase 3 PR (docs/cli-split-inventory.md §7) wires a
// new command group, add the REST paths it needs here and re-run `make -C cli client`.
var keptPaths = []string{
	"/health",
	"/api/v1/version",
	"/auth/login",
	"/auth/logout",
	"/api/v1/auth/profile",
	// PR 2 (docs/cli-split-inventory.md §7) -- pat, auth (mfa/logout), machine.
	"/api/v1/auth/mfa/stepup",
	"/api/v1/auth/tokens",
	"/api/v1/auth/tokens/{id}",
	"/api/v1/auth/tokens/expired",
	"/api/v1/pat-hygiene",
	"/api/v1/projects/{id}/machine-identities",
	"/api/v1/projects/{id}/machine-identities/{machineId}",
	"/api/v1/projects/{id}/machine-identities/{machineId}/tokens",
	"/api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}",
	"/api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings",
	"/api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings/{bindingId}",
	"/api/v1/machine-token-hygiene",
	"/api/v1/machine-identities/audit",
	"/api/v1/projects",
	// PR 6 (docs/cli-split-inventory.md §7) -- project, user.
	"/api/v1/projects/{id}/stats",
	"/api/v1/projects/{id}/hygiene",
	"/api/v1/projects/{id}/health",
	"/api/v1/projects/{id}/environments",
	"/api/v1/projects/{id}/environments/{envId}/clone",
	"/api/v1/environments/{id}",
	"/api/v1/users",
	"/api/v1/users/{id}",
	"/api/v1/users/by-email",
	"/api/v1/users/{id}/suspend",
	"/api/v1/users/{id}/reactivate",
	"/api/v1/users/{id}/require-password-reset",
	"/api/v1/users/{id}/revoke-sessions",
	"/api/v1/users/{id}/resend-setup-link",
	"/api/v1/admin/jobs/suspend-inactive-users",
	// PR 3 (docs/cli-split-inventory.md §7) -- rbac, group, invite.
	"/api/v1/users/{id}/roles",
	"/api/v1/roles",
	"/api/v1/roles/{id}/permissions",
	"/api/v1/user-roles",
	"/api/v1/groups",
	"/api/v1/groups/{id}",
	"/api/v1/groups/{id}/members",
	"/api/v1/groups/{id}/members/{userId}",
	"/api/v1/groups/{id}/roles",
	"/api/v1/groups/{id}/roles/{roleId}",
	"/api/v1/audit/rbac-logs",
	"/api/v1/rbac/permission-matrix",
	"/api/v1/projects/{id}/invitations",
	"/api/v1/projects/{id}/invitations/{invitationId}",
	"/api/v1/projects/{id}/invitations/{invitationId}/resend",
	// PR 1 (docs/cli-split-inventory.md §7) -- dynamic-secret, rotation, breakglass.
	"/api/v1/dynamic-secrets/configs",
	"/api/v1/dynamic-secrets/configs/{id}",
	"/api/v1/dynamic-secrets/configs/{id}/classification",
	"/api/v1/dynamic-secrets/configs/{id}/issue",
	"/api/v1/dynamic-secrets/configs/{id}/leases",
	"/api/v1/dynamic-secrets/configs/{id}/revoke-all",
	"/api/v1/dynamic-secrets/leases/{leaseID}/renew",
	"/api/v1/dynamic-secrets/leases/{leaseID}/revoke",
	"/api/v1/rotation-policies",
	"/api/v1/rotation-policies/evaluate",
	"/api/v1/rotation-policies/{id}",
	"/api/v1/projects/{id}/rotation-plan",
	"/api/v1/rotation-plan",
	"/api/v1/projects/{id}/rotation-order",
	"/api/v1/projects/{id}/break-glass",
	"/api/v1/projects/{id}/break-glass/{activationId}/revoke",
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
