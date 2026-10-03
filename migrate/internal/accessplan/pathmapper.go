package accessplan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ProjectRef/EnvironmentRef are the Keyorix project/environment identities PathMapper resolves
// Vault path segments against — read once, read-only, via accesstarget before building a Plan.
type ProjectRef struct {
	ID   int
	Name string
}

type EnvironmentRef struct {
	ID   int
	Name string
}

// KVMountInfo is the KV mount PathMapper needs to strip Vault's KV v2 "data/"/"metadata/"
// routing segment before applying the project/environment convention — mirrors
// healthscan.KVMount (this package cannot import healthscan's Client-bearing types without
// pulling in a live-Vault dependency it doesn't need, so the caller converts).
type KVMountInfo struct {
	Path      string // e.g. "secret/", trailing slash, as Vault's sys/mounts reports it.
	KVVersion int
}

// pathOverride is one parsed "--path-map" entry.
type pathOverride struct {
	prefix        string
	projectID     int
	environmentID int
}

// PathMapper resolves a raw Vault ACL policy path to a Keyorix (project, environment) scope,
// per ADR-114's "Path tree → project/environment" section. ONLY Vault's actual glob syntax is
// handled: a single trailing "*" at the end of the path (Vault does not support a mid-path
// wildcard segment) — this is the one fact that keeps scope resolution simple: the wildcard, if
// present, can only ever land on the LAST segment, never in the middle, so there is no "glob
// spans multiple non-adjacent scopes" case to enumerate.
type PathMapper struct {
	overrides       []pathOverride // sorted longest-prefix-first
	projectsByName  map[string]ProjectRef
	envsByProjectID map[int]map[string]EnvironmentRef
	kvMounts        []KVMountInfo
}

// NewPathMapper builds a PathMapper. rawOverrides is the raw --path-map flag values, each
// "<vault-prefix>=<projectID>:<environmentID>" (environmentID 0 = global-within-project).
func NewPathMapper(projects []ProjectRef, environmentsByProject map[int][]EnvironmentRef, kvMounts []KVMountInfo, rawOverrides []string) (*PathMapper, error) {
	m := &PathMapper{
		projectsByName:  make(map[string]ProjectRef, len(projects)),
		envsByProjectID: make(map[int]map[string]EnvironmentRef, len(environmentsByProject)),
		kvMounts:        kvMounts,
	}
	for _, p := range projects {
		m.projectsByName[p.Name] = p
	}
	for projectID, envs := range environmentsByProject {
		byName := make(map[string]EnvironmentRef, len(envs))
		for _, e := range envs {
			byName[e.Name] = e
		}
		m.envsByProjectID[projectID] = byName
	}
	for _, raw := range rawOverrides {
		ov, err := parsePathOverride(raw)
		if err != nil {
			return nil, err
		}
		m.overrides = append(m.overrides, ov)
	}
	sort.Slice(m.overrides, func(i, j int) bool { return len(m.overrides[i].prefix) > len(m.overrides[j].prefix) })
	return m, nil
}

func parsePathOverride(raw string) (pathOverride, error) {
	prefix, scope, ok := strings.Cut(raw, "=")
	if !ok || prefix == "" {
		return pathOverride{}, fmt.Errorf("--path-map %q: want \"<vault-prefix>=<projectID>:<environmentID>\"", raw)
	}
	projectStr, envStr, ok := strings.Cut(scope, ":")
	if !ok {
		return pathOverride{}, fmt.Errorf("--path-map %q: want \"<vault-prefix>=<projectID>:<environmentID>\"", raw)
	}
	projectID, err := strconv.Atoi(projectStr)
	if err != nil || projectID <= 0 {
		return pathOverride{}, fmt.Errorf("--path-map %q: projectID %q must be a positive integer", raw, projectStr)
	}
	environmentID, err := strconv.Atoi(envStr)
	if err != nil || environmentID < 0 {
		return pathOverride{}, fmt.Errorf("--path-map %q: environmentID %q must be a non-negative integer (0 = global)", raw, envStr)
	}
	return pathOverride{prefix: prefix, projectID: projectID, environmentID: environmentID}, nil
}

// ScopeResolution is the Keyorix scope Resolve found.
type ScopeResolution struct {
	ProjectID     int
	EnvironmentID int // 0 = global-within-project.
}

// Resolve maps a raw Vault ACL policy path (e.g. "secret/data/team-a/prod/db-password", or
// "secret/data/team-a/*") to a Keyorix scope. ok=false means the path is Unmappable —
// category/reason explain why, for the caller to attach to the resulting Item.
func (m *PathMapper) Resolve(rawPolicyPath string) (res ScopeResolution, category UnmappableCategory, reason string, ok bool) {
	for _, ov := range m.overrides {
		if strings.HasPrefix(rawPolicyPath, ov.prefix) {
			return ScopeResolution{ProjectID: ov.projectID, EnvironmentID: ov.environmentID}, "", "", true
		}
	}

	mount, rest, ok := m.stripMountAndKVInfix(rawPolicyPath)
	if !ok {
		return ScopeResolution{}, CategoryMountManagement, fmt.Sprintf("%q is not under any enabled KV mount (sys/*, auth/*, identity/*, a dynamic-secrets engine, or an unlisted mount) — no project/environment scoping applies", rawPolicyPath), false
	}

	segments := literalSegments(rest)
	if len(segments) == 0 {
		return ScopeResolution{}, CategoryUnresolvedPathScope, fmt.Sprintf("%q covers the entire %q KV mount — map this to a project manually (--path-map), or review per-project", rawPolicyPath, mount), false
	}

	project, found := m.projectsByName[segments[0]]
	if !found {
		return ScopeResolution{}, CategoryUnresolvedPathScope, fmt.Sprintf("%q: no Keyorix project named %q", rawPolicyPath, segments[0]), false
	}
	if len(segments) == 1 {
		// A literal project segment followed only by a trailing wildcard (e.g. "team-a/*")
		// provably covers every environment under the project, present and future — the one
		// case ADR-114 names explicitly as a legitimate use of the env=0 sentinel, not a
		// fallback for "couldn't resolve the environment."
		return ScopeResolution{ProjectID: project.ID, EnvironmentID: 0}, "", "", true
	}
	env, found := m.envsByProjectID[project.ID][segments[1]]
	if !found {
		return ScopeResolution{}, CategoryUnresolvedPathScope, fmt.Sprintf("%q: no Keyorix environment named %q in project %q", rawPolicyPath, segments[1], project.Name), false
	}
	return ScopeResolution{ProjectID: project.ID, EnvironmentID: env.ID}, "", "", true
}

// stripMountAndKVInfix finds the KV mount rawPolicyPath falls under (longest-path match, so a
// mount path that is itself a prefix of another mount's path never wins incorrectly) and
// returns the mount-relative remainder with KV v2's fixed "data/"/"metadata/" routing segment
// removed. ok=false means rawPolicyPath is not under any known KV mount at all.
func (m *PathMapper) stripMountAndKVInfix(rawPolicyPath string) (mount, rest string, ok bool) {
	var best KVMountInfo
	bestLen := -1
	for _, km := range m.kvMounts {
		if strings.HasPrefix(rawPolicyPath, km.Path) && len(km.Path) > bestLen {
			best, bestLen = km, len(km.Path)
		}
	}
	if bestLen < 0 {
		return "", "", false
	}
	rest = strings.TrimPrefix(rawPolicyPath, best.Path)
	if best.KVVersion == 2 {
		switch {
		case strings.HasPrefix(rest, "data/"):
			rest = strings.TrimPrefix(rest, "data/")
		case strings.HasPrefix(rest, "metadata/"):
			rest = strings.TrimPrefix(rest, "metadata/")
		case rest == "data" || rest == "metadata":
			rest = ""
		default:
			// A KV v2 mount's policy path that skips the data/metadata routing segment
			// entirely never matches a real secret read/write — Vault itself would never
			// authorize anything through it. Treated as unresolvable rather than guessed at.
			return "", "", false
		}
	}
	return strings.TrimSuffix(best.Path, "/"), rest, true
}

// literalSegments splits a mount-relative, KV-infix-stripped path into its literal (non-glob)
// leading segments. Vault's ACL glob syntax permits "*" only as the entire final segment — this
// function's only job is to drop that one trailing wildcard segment when present; every segment
// it returns is a literal, exact name.
func literalSegments(rest string) []string {
	rest = strings.Trim(rest, "/")
	if rest == "" || rest == "*" {
		return nil
	}
	segments := strings.Split(rest, "/")
	if segments[len(segments)-1] == "*" {
		segments = segments[:len(segments)-1]
	}
	return segments
}
