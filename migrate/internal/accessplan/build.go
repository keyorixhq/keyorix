package accessplan

import "github.com/keyorixhq/keyorix/migrate/internal/healthscan"

// BuildInput bundles every Vault-read input one full Build needs. Policies is every ACL policy
// this Vault has (role/user builders filter down to their own token_policies); a policy that is
// not attached to any auth-method role or user is never surfaced on its own — it grants nothing
// to anyone in Vault today, so there is no live access to preserve or report (vault scan's own
// policy-sprawl check already flags an orphaned-policy count for a different purpose).
type BuildInput struct {
	Policies        []healthscan.Policy
	AppRoles        []healthscan.AppRoleRoleConfig
	KubernetesRoles []healthscan.KubernetesAuthRoleConfig
	UserpassUsers   []healthscan.UserpassUserConfig
}

// Build runs every source's builder against the same PathMapper/issuer and compacts duplicate
// Unmappable items: the same policy stanza can be attached to several auth-method roles, which
// would otherwise produce an identical Unmappable item once per role — a human reviewer needs to
// see it once, not N times. Create/Skip/Conflict items are never deduplicated (each is a
// distinct real object or edge).
func Build(in BuildInput, mapper *PathMapper, k8sIssuer string) Plan {
	var items []Item
	items = append(items, BuildAppRoleItems(in.AppRoles, in.Policies, mapper)...)
	items = append(items, BuildKubernetesItems(in.KubernetesRoles, in.Policies, mapper, k8sIssuer)...)
	items = append(items, BuildUserpassItems(in.UserpassUsers)...)
	return Plan{Items: compactUnmappable(items)}
}

func compactUnmappable(items []Item) []Item {
	seen := map[string]bool{}
	out := make([]Item, 0, len(items))
	for _, it := range items {
		if it.Outcome != Unmappable {
			out = append(out, it)
			continue
		}
		key := string(it.Kind) + "|" + it.SourceRef + "|" + string(it.Category) + "|" + it.Reason
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, it)
	}
	return out
}
