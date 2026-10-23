package accessplan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

// WidenedGrant is one role grant that keyorix-migrate v0.96.0–v0.96.3's apply-access would
// have created for a migrated machine identity but the current mapping rules refuse: the
// grant is wider than the Vault policy stanza it came from (RD-SMT-SPIKE-1). audit-access
// checks each against live Keyorix and reports the ones that exist.
type WidenedGrant struct {
	MachineName   string
	ProjectID     int
	EnvironmentID int // 0 = project-wide.
	RoleName      string
	Permissions   []string
	// SourceRef names the Vault policy stanza ("policy:<name> path:<path>") and Category/Reason
	// say why the current rules refuse it.
	SourceRef string
	Category  UnmappableCategory
	Reason    string
	// AlsoGrantedByCurrentRules is true when the current rules still grant RoleName to the
	// machine in ProjectID at another environment. The Keyorix API lists a machine's roles
	// without their environment, so audit-access can then not tell the widened grant from the
	// legitimate one: it reports the widened one as unconfirmed.
	AlsoGrantedByCurrentRules bool
}

// AuditWidenedGrants returns, for every machine identity Build would name (AppRole roles and
// Kubernetes service-account pairs), the grants v0.96.x would have created that the current
// rules do not, sorted for a stable report. It never reads Keyorix: the caller confirms which
// of these actually exist.
func AuditWidenedGrants(in BuildInput, mapper *PathMapper, k8sIssuer string) []WidenedGrant {
	byName := policiesByName(in.Policies)
	var out []WidenedGrant
	for _, role := range in.AppRoles {
		out = append(out, widenedFor(sanitizeIdentityName("vault-approle", role.Name), resolveAttachedPolicies(role.TokenPolicies, byName), mapper)...)
	}
	if k8sIssuer != "" {
		for _, role := range in.KubernetesRoles {
			if containsLiteral(role.BoundServiceAccountNames, "*") || containsLiteral(role.BoundServiceAccountNamespaces, "*") {
				continue
			}
			for _, ns := range role.BoundServiceAccountNamespaces {
				for _, name := range role.BoundServiceAccountNames {
					machine := sanitizeIdentityName("vault-k8s", role.Name+"-"+ns+"-"+name)
					out = append(out, widenedFor(machine, resolveAttachedPolicies(role.TokenPolicies, byName), mapper)...)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.MachineName != b.MachineName {
			return a.MachineName < b.MachineName
		}
		if a.ProjectID != b.ProjectID {
			return a.ProjectID < b.ProjectID
		}
		if a.EnvironmentID != b.EnvironmentID {
			return a.EnvironmentID < b.EnvironmentID
		}
		if a.RoleName != b.RoleName {
			return a.RoleName < b.RoleName
		}
		return a.SourceRef < b.SourceRef
	})
	return out
}

type grantKey struct {
	role    string
	project int
	env     int
}

func widenedFor(machine string, policies []healthscan.Policy, mapper *PathMapper) []WidenedGrant {
	current := BuildPolicyItems(policies, mapper)
	granted := map[grantKey]bool{}
	grantedRoleInProject := map[grantKey]bool{}
	refused := map[string]Item{}
	for _, it := range current {
		switch it.Outcome {
		case Create:
			granted[grantKey{role: it.ProposedName, project: it.ProposedProjectID, env: it.ProposedEnvironmentID}] = true
			grantedRoleInProject[grantKey{role: it.ProposedName, project: it.ProposedProjectID}] = true
		case Unmappable:
			if it.Category == CategoryNarrowerThanScope || it.Category == CategoryMetadataOnly || it.Category == CategoryCrossMountScope {
				refused[it.SourceRef] = it
			}
		}
	}
	var out []WidenedGrant
	seen := map[grantKey]bool{}
	for _, g := range legacyV096Grants(policies, mapper) {
		k := grantKey{role: g.role, project: g.project, env: g.env}
		if granted[k] || seen[k] {
			continue
		}
		why, ok := refused[g.sourceRef]
		if !ok {
			continue // refused today for an unrelated reason the old rules shared.
		}
		seen[k] = true
		out = append(out, WidenedGrant{
			MachineName: machine, ProjectID: g.project, EnvironmentID: g.env,
			RoleName: g.role, Permissions: g.perms, SourceRef: g.sourceRef,
			Category: why.Category, Reason: why.Reason,
			AlsoGrantedByCurrentRules: grantedRoleInProject[grantKey{role: g.role, project: g.project}],
		})
	}
	return out
}

type legacyGrant struct {
	role      string
	perms     []string
	project   int
	env       int
	sourceRef string
}

// legacyV096Grants reproduces the Create outcomes of keyorix-migrate v0.96.0–v0.96.3's
// BuildPolicyItems (git tag v0.96.3, migrate/internal/accessplan/policies.go and
// pathmapper.go) for one machine's policies: the same sudo/templated/deny-overlap filtering,
// "read" and "list" both mapping to secrets.read, and legacyV096Resolve's scope. It exists
// only so audit-access can name the grants those releases created; nothing builds a plan from
// it. TestLegacyV096_MatchesShippedBehaviour pins it to the v0.96.3 test expectations.
func legacyV096Grants(policies []healthscan.Policy, mapper *PathMapper) []legacyGrant {
	type allow struct {
		ref, path string
		perms     []string
	}
	var allows []allow
	var denyPaths []string
	for _, pol := range policies {
		for _, b := range pol.Blocks {
			switch {
			case containsCapability(b.Capabilities, "sudo"), isTemplatedPath(b.Path):
			case containsCapability(b.Capabilities, "deny"):
				denyPaths = append(denyPaths, b.Path)
			default:
				set := map[string]bool{}
				for _, c := range b.Capabilities {
					if c == "list" {
						set["secrets.read"] = true
					} else if p := capabilityToPermission(c); p != "" {
						set[p] = true
					}
				}
				if len(set) == 0 {
					continue
				}
				perms := make([]string, 0, len(set))
				for p := range set {
					perms = append(perms, p)
				}
				sort.Strings(perms)
				allows = append(allows, allow{ref: stanzaRef(pol.Name, b.Path), path: b.Path, perms: perms})
			}
		}
	}
	var out []legacyGrant
	for _, a := range allows {
		if overlapsAnyDeny(a.path, denyPaths) {
			continue
		}
		res, ok := mapper.legacyV096Resolve(a.path)
		if !ok {
			continue
		}
		out = append(out, legacyGrant{role: roleName(a.perms), perms: a.perms, project: res.ProjectID, env: res.EnvironmentID, sourceRef: a.ref})
	}
	return out
}

// legacyV096Resolve is v0.96.3's PathMapper.Resolve: the first override whose prefix the path
// starts with wins outright, otherwise the first two literal segments after the KV mount (and
// KV v2's data/ or metadata/) name the project and environment. See legacyV096Grants.
func (m *PathMapper) legacyV096Resolve(rawPolicyPath string) (ScopeResolution, bool) {
	for _, ov := range m.overrides {
		if strings.HasPrefix(rawPolicyPath, ov.prefix) {
			return ScopeResolution{ProjectID: ov.projectID, EnvironmentID: ov.environmentID}, true
		}
	}
	_, rest, ok := m.stripMountAndKVInfix(rawPolicyPath)
	if !ok {
		return ScopeResolution{}, false
	}
	segments := literalSegments(rest)
	if len(segments) == 0 {
		return ScopeResolution{}, false
	}
	project, found := m.projectsByName[segments[0]]
	if !found {
		return ScopeResolution{}, false
	}
	if len(segments) == 1 {
		return ScopeResolution{ProjectID: project.ID}, true
	}
	env, found := m.envsByProjectID[project.ID][segments[1]]
	if !found {
		return ScopeResolution{}, false
	}
	return ScopeResolution{ProjectID: project.ID, EnvironmentID: env.ID}, true
}

// String renders a finding as one human-readable line (scope ids as Keyorix reports them).
func (g WidenedGrant) String() string {
	env := "all environments"
	if g.EnvironmentID != 0 {
		env = fmt.Sprintf("environment %d", g.EnvironmentID)
	}
	return fmt.Sprintf("%s holds %s (%s) on project %d / %s, from %s [%s]", g.MachineName, g.RoleName, strings.Join(g.Permissions, ","), g.ProjectID, env, g.SourceRef, g.Category)
}
