package accessplan

import (
	"fmt"
	"slices"
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
	kvTree          map[string]KVMountListing // nil = the Vault tree was never listed.
}

// KVMountListing is what plan-access listed in one KV mount at the two levels the default
// convention maps: the mount root and, for each root key naming a Keyorix project, that
// directory.
type KVMountListing struct {
	// RootListed is false when LIST of the mount root was denied or failed.
	RootListed bool
	// Projects holds every root key (trailing "/" stripped) that names a Keyorix project.
	Projects map[string]KVProjectListing
}

// KVProjectListing is one <project> key at a KV mount's root.
type KVProjectListing struct {
	// Listed is false when <project>/ is a directory whose LIST was denied or failed.
	Listed bool
	// Envs holds the keys directly under <project>/ (trailing "/" stripped): environment
	// directories, or secrets stored at that level.
	Envs []string
}

// SetKVTree gives the mapper the KV tree plan-access listed, keyed by mount path as
// KVMountInfo.Path spells it ("kv1/"). Without it, a default-convention path on a Vault with
// more than one KV mount is Unmappable: nothing proves the other mounts are empty there.
func (m *PathMapper) SetKVTree(tree map[string]KVMountListing) {
	m.kvTree = tree
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
	// CrossMountEvidence is set for a default-convention or --path-map resolution (also when it
	// is refused as CategoryCrossMountScope); see Item.CrossMountEvidence.
	CrossMountEvidence []string
}

// Resolve maps a raw Vault ACL policy path (e.g. "secret/data/team-a/prod/*", or
// "secret/data/team-a/*") to a Keyorix scope. ok=false means the path is Unmappable —
// category/reason explain why, for the caller to attach to the resulting Item.
//
// A Keyorix grant covers its whole (project, environment), so a path resolves only when it
// covers the whole Vault subtree mapped to that scope: a trailing-glob path whose literal part
// is the override prefix (or a prefix of it), or "<project>/*" / "<project>/<env>/*" under the
// default convention. Anything narrower (an exact secret path, a deeper subtree, part of an
// override, one of two overrides into the same scope) is CategoryNarrowerThanScope, and a KV v2
// metadata/ path is CategoryMetadataOnly: granting the scope there would let the migrated
// principal read secret values Vault never let it read. A default-convention scope that another
// KV mount's paths also route to (or that SetKVTree's listing cannot rule out) is
// CategoryCrossMountScope, for the same reason.
func (m *PathMapper) Resolve(rawPolicyPath string) (res ScopeResolution, category UnmappableCategory, reason string, ok bool) {
	if m.isKVMetadataPath(rawPolicyPath) {
		return ScopeResolution{}, CategoryMetadataOnly, fmt.Sprintf("%q is a KV v2 metadata/ path: it grants key listing and version metadata, never secret values, and Keyorix has no permission that narrow — secrets.read would expose every value in the scope", rawPolicyPath), false
	}

	for _, ov := range m.overrides {
		if strings.HasPrefix(rawPolicyPath, ov.prefix) {
			res := ScopeResolution{ProjectID: ov.projectID, EnvironmentID: ov.environmentID}
			if !globCovers(rawPolicyPath, dirPrefix(ov.prefix)) {
				return ScopeResolution{}, CategoryNarrowerThanScope, fmt.Sprintf("%q covers only part of --path-map %q (project %d / environment %d): a grant on that scope would also reach every other secret in it, which this policy never allowed — import that Vault subtree into its own environment and map it with --path-map %q=<projectID>:<environmentID>, or grant manually", rawPolicyPath, ov.prefix, ov.projectID, ov.environmentID, strings.TrimSuffix(rawPolicyPath, "*")), false
			}
			if reason := m.sharedScopeReason(rawPolicyPath, res); reason != "" {
				return ScopeResolution{}, CategoryNarrowerThanScope, reason, false
			}
			return m.overrideScope(rawPolicyPath, ov, res)
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
	// Only "<project>/*" and "<project>/<env>/*" cover a whole scope. An exact path ("team-a/prod",
	// "team-a/prod/db") or a deeper glob ("team-a/prod/db/*") names part of it.
	scopeGlob := strings.HasSuffix(rest, "/*") && len(segments) <= 2 && !strings.ContainsAny(strings.TrimSuffix(rest, "/*"), "*+")
	if len(segments) == 1 {
		if !scopeGlob {
			return ScopeResolution{}, CategoryNarrowerThanScope, fmt.Sprintf("%q is narrower than project %q: only %q/%s/* covers the whole project", rawPolicyPath, project.Name, mount, project.Name), false
		}
		// A literal project segment followed only by a trailing wildcard (e.g. "team-a/*")
		// provably covers every environment under the project, present and future — the one
		// case ADR-114 names explicitly as a legitimate use of the env=0 sentinel, not a
		// fallback for "couldn't resolve the environment."
		return m.defaultScope(rawPolicyPath, ScopeResolution{ProjectID: project.ID, EnvironmentID: 0}, project.Name, "")
	}
	env, found := m.envsByProjectID[project.ID][segments[1]]
	if !found {
		return ScopeResolution{}, CategoryUnresolvedPathScope, fmt.Sprintf("%q: no Keyorix environment named %q in project %q", rawPolicyPath, segments[1], project.Name), false
	}
	if !scopeGlob {
		return ScopeResolution{}, CategoryNarrowerThanScope, fmt.Sprintf("%q is narrower than environment %q of project %q: a Keyorix grant covers every secret in the environment, and only a policy on the whole environment path (\"<mount>/%s/%s/*\") can be migrated to one — grant the individual secrets manually", rawPolicyPath, env.Name, project.Name, project.Name, env.Name), false
	}
	return m.defaultScope(rawPolicyPath, ScopeResolution{ProjectID: project.ID, EnvironmentID: env.ID}, project.Name, env.Name)
}

// defaultScope returns a default-convention resolution unless an override also routes other
// Vault paths into the same scope (see sharedScopeReason) or another KV mount holds paths the
// same convention routes there (see crossMountEvidence).
func (m *PathMapper) defaultScope(rawPolicyPath string, res ScopeResolution, projectName, envName string) (ScopeResolution, UnmappableCategory, string, bool) {
	if reason := m.sharedScopeReason(rawPolicyPath, res); reason != "" {
		return ScopeResolution{}, CategoryNarrowerThanScope, reason, false
	}
	own, _ := m.kvMountFor(rawPolicyPath)
	evidence, shared := m.crossMountEvidence(own.Path, projectName, envName, false)
	res.CrossMountEvidence = evidence
	if len(shared) > 0 {
		return res, CategoryCrossMountScope, fmt.Sprintf("%q resolves to project %q%s by the default convention, but the same convention also routes another KV mount's paths there (%s): a grant there would reach that mount's imported secrets too, which this policy never allowed — import each mount into its own environment and map it with --path-map, or grant manually", rawPolicyPath, projectName, envLabel(envName), strings.Join(shared, "; ")), false
	}
	return res, "", "", true
}

// overrideScope returns the scope a --path-map entry maps rawPolicyPath into, unless another KV
// mount holds paths the default convention names into the same project/environment. The override
// declares which Vault subtree it takes into the scope, but plan-access never sees what the
// operator imported where, and the default convention routes kv1/team-a/dev/x to team-a/dev
// whatever the mount: so the scope is only equivalent to the Vault policy when the listing of
// every other mount proves nothing lands there by name (a path another --path-map entry routes
// elsewhere does not). A project or environment this mapper does not know has nothing the
// convention could name into it.
func (m *PathMapper) overrideScope(rawPolicyPath string, ov pathOverride, res ScopeResolution) (ScopeResolution, UnmappableCategory, string, bool) {
	projectName, envName, known := m.scopeNames(res)
	if !known {
		return res, "", "", true
	}
	own, _ := m.kvMountFor(rawPolicyPath)
	evidence, shared := m.crossMountEvidence(own.Path, projectName, envName, true)
	res.CrossMountEvidence = evidence
	if len(shared) > 0 {
		return res, CategoryCrossMountScope, fmt.Sprintf("%q resolves to project %q%s through --path-map %q, but the default convention also routes another KV mount's paths there (%s): a grant there would reach that mount's imported secrets too, which this policy never allowed — send that mount's paths to their own scope with --path-map, import it into its own environment, or grant manually", rawPolicyPath, projectName, envLabel(envName), ov.prefix, strings.Join(shared, "; ")), false
	}
	return res, "", "", true
}

// scopeNames returns the names of the project and environment a resolution points at (envName ""
// for the whole project), the names the default convention matches. ok=false: not a known scope.
func (m *PathMapper) scopeNames(res ScopeResolution) (projectName, envName string, ok bool) {
	for name, p := range m.projectsByName {
		if p.ID != res.ProjectID {
			continue
		}
		if res.EnvironmentID == 0 {
			return name, "", true
		}
		for name2, e := range m.envsByProjectID[p.ID] {
			if e.ID == res.EnvironmentID {
				return name, name2, true
			}
		}
		return "", "", false
	}
	return "", "", false
}

func envLabel(envName string) string {
	if envName == "" {
		return " (every environment)"
	}
	return fmt.Sprintf(" / environment %q", envName)
}

// Cross-mount evidence states, one per KV mount.
const (
	crossMountPolicyMount = "policy mount"
	crossMountAbsent      = "absent"
	crossMountPresent     = "present"
	crossMountNotListed   = "not listed"
	// crossMountMapped is followed by the --path-map prefix that routes the mount's paths at
	// the scope to another scope, so they do not land here by name.
	crossMountMapped = "mapped by --path-map "
)

// crossMountEvidence reports, for the default-convention scope <project>/[<env>/] of a policy
// on ownMount, what every KV mount holds there per the listing SetKVTree gave: one sorted
// "<mount><project>/[<env>/]: <state>" line per mount. shared lists the lines of other mounts
// that hold paths there or could not be listed (fail closed: an unlisted mount may hold them).
// With honourOverrides, a mount whose whole <project>/[<env>/] directory a --path-map entry
// routes elsewhere is not shared, whatever it holds or whether it could be listed.
func (m *PathMapper) crossMountEvidence(ownMount, projectName, envName string, honourOverrides bool) (evidence, shared []string) {
	scope := projectName + "/"
	if envName != "" {
		scope += envName + "/"
	}
	mounts := make([]string, 0, len(m.kvMounts))
	for _, km := range m.kvMounts {
		mounts = append(mounts, km.Path)
	}
	sort.Strings(mounts)
	for _, mount := range mounts {
		state := m.crossMountState(mount, projectName, envName)
		switch {
		case mount == ownMount:
			state = crossMountPolicyMount
		case honourOverrides:
			if ov, routed := m.overrideRouting(mount, scope); routed {
				state = crossMountMapped + ov.prefix
			}
		}
		line := mount + scope + ": " + state
		evidence = append(evidence, line)
		if state != crossMountPolicyMount && state != crossMountAbsent && !strings.HasPrefix(state, crossMountMapped) {
			shared = append(shared, line)
		}
	}
	return evidence, shared
}

// overrideRouting reports the --path-map entry, if any, that takes the whole directory
// <mount>[data/]<scope> ("team-a/prod/") to its own scope: the importer routes every path under
// an override prefix by that override, not by name. An entry deeper than the directory takes
// only part of it, so the rest still lands by name.
func (m *PathMapper) overrideRouting(mount, scope string) (pathOverride, bool) {
	dir := mount
	for _, km := range m.kvMounts {
		if km.Path == mount && km.KVVersion == 2 {
			dir += "data/"
		}
	}
	dir += scope
	for _, ov := range m.overrides {
		if strings.HasPrefix(dir, dirPrefix(ov.prefix)) {
			return ov, true
		}
	}
	return pathOverride{}, false
}

func (m *PathMapper) crossMountState(mount, projectName, envName string) string {
	listing, ok := m.kvTree[mount]
	if !ok || !listing.RootListed {
		return crossMountNotListed
	}
	p, ok := listing.Projects[projectName]
	switch {
	case !ok:
		return crossMountAbsent
	case envName == "":
		return crossMountPresent // a project grant covers everything under <project>/.
	case !p.Listed:
		return crossMountNotListed
	case slices.Contains(p.Envs, envName):
		return crossMountPresent
	default:
		return crossMountAbsent
	}
}

// sharedScopeReason reports why res cannot be granted for rawPolicyPath when a --path-map
// entry that the policy does not cover maps into an overlapping scope: the grant would also
// reach that override's secrets. "" means no such override exists.
func (m *PathMapper) sharedScopeReason(rawPolicyPath string, res ScopeResolution) string {
	for _, ov := range m.overrides {
		if ov.projectID != res.ProjectID {
			continue
		}
		if ov.environmentID != res.EnvironmentID && ov.environmentID != 0 && res.EnvironmentID != 0 {
			continue
		}
		if globCovers(rawPolicyPath, dirPrefix(ov.prefix)) {
			continue
		}
		return fmt.Sprintf("%q resolves to project %d / environment %d, but --path-map %q also maps other Vault paths into that scope: a grant there would reach those secrets too, which this policy never allowed — map each Vault subtree to its own environment, or grant manually", rawPolicyPath, res.ProjectID, res.EnvironmentID, ov.prefix)
	}
	return ""
}

// dirPrefix treats a --path-map prefix as a directory: "secret/data" and "secret/data/" both
// mean everything under "secret/data/".
func dirPrefix(prefix string) string {
	return strings.TrimSuffix(prefix, "/") + "/"
}

// globCovers reports whether Vault policy path policyPath matches every path under dir: only a
// trailing-glob path whose literal part is a prefix of dir does. An exact path never covers a
// directory.
func globCovers(policyPath, dir string) bool {
	literal, wildcard := wildcardSplit(policyPath)
	return wildcard && !strings.ContainsAny(literal, "*+") && strings.HasPrefix(dir, literal)
}

// isKVMetadataPath reports whether rawPolicyPath is under a KV v2 mount's metadata/ segment.
func (m *PathMapper) isKVMetadataPath(rawPolicyPath string) bool {
	km, ok := m.kvMountFor(rawPolicyPath)
	if !ok || km.KVVersion != 2 {
		return false
	}
	rest := strings.TrimPrefix(rawPolicyPath, km.Path)
	return rest == "metadata" || strings.HasPrefix(rest, "metadata/")
}

// kvMountFor finds the KV mount rawPolicyPath falls under (longest-path match, so a mount path
// that is itself a prefix of another mount's path never wins incorrectly).
func (m *PathMapper) kvMountFor(rawPolicyPath string) (KVMountInfo, bool) {
	var best KVMountInfo
	bestLen := -1
	for _, km := range m.kvMounts {
		if strings.HasPrefix(rawPolicyPath, km.Path) && len(km.Path) > bestLen {
			best, bestLen = km, len(km.Path)
		}
	}
	return best, bestLen >= 0
}

// stripMountAndKVInfix finds the KV mount rawPolicyPath falls under (kvMountFor) and returns
// the mount-relative remainder with KV v2's fixed "data/"/"metadata/" routing segment removed.
// ok=false means rawPolicyPath is not under any known KV mount at all.
func (m *PathMapper) stripMountAndKVInfix(rawPolicyPath string) (mount, rest string, ok bool) {
	best, found := m.kvMountFor(rawPolicyPath)
	if !found {
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
