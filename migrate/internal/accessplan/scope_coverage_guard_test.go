package accessplan

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

// TestBuildPolicyItems_CreateNeverWiderThanPolicy is the class guard for the RD-SMT-SPIKE-1
// widening (ADR-114's governing rule): for every Create item BuildPolicyItems proposes, every
// secret the routing model below places in the granted scope must be readable under the source
// policy path by Vault's own glob rules, and secrets.read must come from a "read" capability.
//
// It enumerates policy paths (three mounts, up to three segments from a small alphabet that
// includes "+", three glob suffixes) against several --path-map configurations, and checks each
// Create against a corpus of secret paths with an oracle written independently of pathmapper.go
// (a regexp of Vault's glob syntax, a directory-prefix routing model).
//
// What it does NOT check: a scope reachable from a second KV mount through the default
// convention ("secret/data/team-a/prod/x" and "kv1/team-a/prod/x" both route to team-a/prod) —
// the routing model below keeps each secret on its own mount's convention only. A scope that a
// --path-map entry targets is modelled as holding only override subtrees (the override declares
// the scope's content). Nor does it know which Vault paths an operator actually imported into an
// environment: plan-access never sees that, and neither does this test.
func TestBuildPolicyItems_CreateNeverWiderThanPolicy(t *testing.T) {
	mounts := []KVMountInfo{{Path: "secret/", KVVersion: 2}, {Path: "kv1/", KVVersion: 1}}
	projects := []ProjectRef{{ID: 1, Name: "team-a"}, {ID: 2, Name: "team-b"}}
	envs := map[int][]EnvironmentRef{1: {{ID: 10, Name: "dev"}, {ID: 11, Name: "prod"}}, 2: {{ID: 20, Name: "prod"}}}
	configs := [][]string{
		nil,
		{"secret/data=1:10"},
		{"secret/data/=1:10"},
		{"secret/data/payments=1:10"},
		{"secret/data/pay=1:10"},
		{"secret/data/payments/=1:10", "secret/data/mobile-app/=1:10"},
		{"secret/data/team-a=2:20", "secret/data/team-a/dev=1:10"},
		{"secret/data/payments=1:0"},
		{"kv1/payments=1:11"},
		{"secret/metadata=1:10"},
	}
	segs := []string{"team-a", "team-b", "prod", "dev", "payments", "db", "+"}
	secretSegs := []string{"team-a", "team-b", "prod", "dev", "payments", "paymentsx", "mobile-app", "db"}
	capSets := [][]string{{"read"}, {"read", "list"}, {"list"}, {"create", "update"}, {"list", "create"}}

	var policyPaths []string
	for _, prefix := range []string{"secret/data/", "secret/metadata/", "kv1/"} {
		for _, rel := range segmentCombos(segs, 3) {
			for _, suffix := range []string{"", "/*", "*"} {
				p := prefix + rel + suffix
				if rel == "" && suffix == "/*" {
					continue
				}
				policyPaths = append(policyPaths, p)
			}
		}
	}
	var secrets []string
	for _, rel := range segmentCombos(secretSegs, 3) {
		if rel == "" {
			continue
		}
		secrets = append(secrets, "secret/data/"+rel, "kv1/"+rel)
	}

	creates := 0
	for _, cfg := range configs {
		m, err := NewPathMapper(projects, envs, mounts, cfg)
		if err != nil {
			t.Fatalf("NewPathMapper(%v): %v", cfg, err)
		}
		router := newScopeRouter(t, projects, envs, cfg)
		for _, path := range policyPaths {
			match := vaultGlob(path)
			for _, caps := range capSets {
				items := BuildPolicyItems([]healthscan.Policy{{Name: "p", Blocks: []healthscan.PolicyPathBlock{{Path: path, Capabilities: caps}}}}, m)
				for _, it := range items {
					if it.Outcome != Create {
						continue
					}
					creates++
					if slices.Contains(it.ProposedPermissions, "secrets.read") && !slices.Contains(caps, "read") {
						t.Fatalf("config %v: %s %v -> secrets.read without a read capability", cfg, path, caps)
					}
					for _, s := range secrets {
						p, e, routed := router.route(s, mountOf(path))
						if !routed || p != it.ProposedProjectID || (it.ProposedEnvironmentID != 0 && e != it.ProposedEnvironmentID) {
							continue
						}
						if !match.MatchString(s) {
							t.Fatalf("config %v: %s %v -> Create at (%d,%d), which grants %q, but Vault's glob %q does not match it",
								cfg, path, caps, it.ProposedProjectID, it.ProposedEnvironmentID, s, path)
						}
					}
				}
			}
		}
	}
	// A guard whose population is empty passes vacuously: the corpus must exercise real Creates.
	if creates < 20 {
		t.Fatalf("only %d Create items across the corpus — the guard is not exercising the mapper", creates)
	}
}

func segmentCombos(segs []string, maxDepth int) []string {
	out := []string{""}
	level := []string{""}
	for range maxDepth {
		var next []string
		for _, base := range level {
			for _, s := range segs {
				if base == "" {
					next = append(next, s)
				} else {
					next = append(next, base+"/"+s)
				}
			}
		}
		out = append(out, next...)
		level = next
	}
	return out
}

// vaultGlob compiles a Vault ACL path to a regexp: "+" matches one whole segment, a trailing
// "*" matches any suffix, everything else is literal.
func vaultGlob(path string) *regexp.Regexp {
	literal, wildcard := strings.CutSuffix(path, "*")
	parts := strings.Split(literal, "/")
	for i, p := range parts {
		if p == "+" {
			parts[i] = "[^/]+"
		} else {
			parts[i] = regexp.QuoteMeta(p)
		}
	}
	expr := "^" + strings.Join(parts, "/")
	if wildcard {
		expr += ".*"
	}
	return regexp.MustCompile(expr + "$")
}

// scopeRouter is the oracle's model of which Keyorix scope a secret path lands in: the longest
// --path-map prefix taken as a directory, else "<mount>[data/]<project>/<env>/<leaf...>".
type scopeRouter struct {
	overrides []pathOverride
	projects  map[string]ProjectRef
	envs      map[int]map[string]EnvironmentRef
}

func newScopeRouter(t *testing.T, projects []ProjectRef, envs map[int][]EnvironmentRef, raw []string) scopeRouter {
	t.Helper()
	r := scopeRouter{projects: map[string]ProjectRef{}, envs: map[int]map[string]EnvironmentRef{}}
	for _, p := range projects {
		r.projects[p.Name] = p
	}
	for pid, list := range envs {
		r.envs[pid] = map[string]EnvironmentRef{}
		for _, e := range list {
			r.envs[pid][e.Name] = e
		}
	}
	for _, s := range raw {
		ov, err := parsePathOverride(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		r.overrides = append(r.overrides, ov)
	}
	slices.SortFunc(r.overrides, func(a, b pathOverride) int { return len(b.prefix) - len(a.prefix) })
	return r
}

func mountOf(path string) string {
	mount, _, _ := strings.Cut(path, "/")
	return mount
}

// route places secret in a scope. Default-convention routing applies only on policyMount (see
// the guard's doc comment); --path-map routing applies on every mount.
func (r scopeRouter) route(secret, policyMount string) (project, env int, ok bool) {
	for _, ov := range r.overrides {
		if strings.HasPrefix(secret, strings.TrimSuffix(ov.prefix, "/")+"/") {
			return ov.projectID, ov.environmentID, true
		}
	}
	if mountOf(secret) != policyMount {
		return 0, 0, false
	}
	var rel string
	switch {
	case strings.HasPrefix(secret, "secret/data/"):
		rel = strings.TrimPrefix(secret, "secret/data/")
	case strings.HasPrefix(secret, "kv1/"):
		rel = strings.TrimPrefix(secret, "kv1/")
	default:
		panic(fmt.Sprintf("corpus secret %q is outside the modelled mounts", secret))
	}
	parts := strings.Split(rel, "/")
	if len(parts) < 3 {
		return 0, 0, false
	}
	p, found := r.projects[parts[0]]
	if !found {
		return 0, 0, false
	}
	e, found := r.envs[p.ID][parts[1]]
	if !found {
		return 0, 0, false
	}
	// An override declares which Vault subtree a scope is (ADR-114): the convention no longer
	// fills a scope that any --path-map entry targets.
	for _, ov := range r.overrides {
		if ov.projectID == p.ID && (ov.environmentID == 0 || ov.environmentID == e.ID) {
			return 0, 0, false
		}
	}
	return p.ID, e.ID, true
}
