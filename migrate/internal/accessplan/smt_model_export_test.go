package accessplan

// RD-SMT-SPIKE-1: the SMT subset check in docs/formal/smt/ reads one model per case
// (cases/<case>.model.json): the Vault rules of one role's attached policy set and the
// Keyorix grants this package proposes for it. This test is the only producer of those
// models, so the solver always checks what BuildPolicyItems really does, not a hand
// copy of it:
//
//   - every policy text is extracted from the file that seeds a real Vault (the
//     vault-migration testbed, the migration demo, journey4, the health-scan policy),
//     never retyped into the case;
//   - every grant comes from NewPathMapper + BuildPolicyItems on that text.
//
// A drift in either (a policy edited in seed.sh, a mapping rule changed here) makes the
// committed model stale and this test red. Regenerate with:
//
//	go test ./internal/accessplan -run TestSMTModels -update-smt-models
//
// then re-run the solver (docs/formal/smt/check.py) and its tests.

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

var updateSMTModels = flag.Bool("update-smt-models", false, "rewrite docs/formal/smt/cases/*.model.json")

const smtCasesDir = "../../../docs/formal/smt/cases"

type smtPolicySource struct {
	File   string `json:"file"`   // repo-relative
	Policy string `json:"policy"` // policy name inside File (ignored for a whole .hcl file)
}

type smtImport struct {
	Mount         string `json:"mount"`       // KV mount path, trailing slash ("secret/")
	PathPrefix    string `json:"path_prefix"` // --vault-path, mount-relative ("" = whole mount)
	ProjectID     int    `json:"project_id"`
	EnvironmentID int    `json:"environment_id"`
}

type smtCaseInput struct {
	Case         string                   `json:"case"`
	Description  string                   `json:"description"`
	Constructed  bool                     `json:"constructed"`
	Sources      []smtPolicySource        `json:"policy_sources"`
	InlineHCL    map[string]string        `json:"inline_policies,omitempty"` // constructed cases only
	KVMounts     []KVMountInfo            `json:"kv_mounts"`
	Projects     []ProjectRef             `json:"projects"`
	Environments map[int][]EnvironmentRef `json:"environments"`
	PathMap      []string                 `json:"path_map"`
	Imports      []smtImport              `json:"imports"`
	// KVListing is what plan-access lists under each KV mount's project-named roots, per mount
	// path: "<project>" or "<project>/<env>" keys. Every KV mount counts as listed; a mount
	// absent here holds nothing named after a Keyorix project (true of every seeded Vault).
	KVListing map[string][]string `json:"kv_listing,omitempty"`
}

type smtRule struct {
	Policy       string   `json:"policy"`
	Path         string   `json:"path"`
	Capabilities []string `json:"capabilities"`
}

type smtGrant struct {
	Permissions   []string `json:"permissions"`
	ProjectID     int      `json:"project_id"`
	EnvironmentID int      `json:"environment_id"`
	SourceRef     string   `json:"source_ref"`
}

type smtUnmappable struct {
	SourceRef string `json:"source_ref"`
	Category  string `json:"category"`
}

type smtMount struct {
	Path      string `json:"path"`
	KVVersion int    `json:"kv_version"`
}

type smtModel struct {
	Case        string          `json:"case"`
	Description string          `json:"description"`
	Constructed bool            `json:"constructed"`
	Sources     []string        `json:"sources"`
	KVMounts    []smtMount      `json:"kv_mounts"`
	VaultRules  []smtRule       `json:"vault_rules"`
	Imports     []smtImport     `json:"imports"`
	Grants      []smtGrant      `json:"grants"`
	Unmappable  []smtUnmappable `json:"unmappable"`
}

// shellPolicyRE matches the seed scripts' `... "sys/policies/acl/<name>" \` + newline +
// `  '<json body>'` request shape (seed.sh's req and the demo's vreq both use it).
var shellPolicyRE = regexp.MustCompile(`sys/policies/acl/([A-Za-z0-9_-]+)" \\\n\s*'(\{[^\n]*\})'`)

// goPolicyRE matches journey4's `policyHCL = ` + "`...`" literal.
var goPolicyRE = regexp.MustCompile("policyName = \"([^\"]+)\"\\s*\\n\\s*\\S*policyHCL = `([^`]*)`")

func extractPolicy(t *testing.T, src smtPolicySource) healthscan.Policy {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../../..", src.File))
	if err != nil {
		t.Fatalf("read policy source %s: %v", src.File, err)
	}
	text := string(raw)
	switch {
	case strings.HasSuffix(src.File, ".hcl"):
		return healthscan.Policy{Name: src.Policy, HCL: text, Blocks: healthscan.ParsePolicyHCL(text)}
	case strings.HasSuffix(src.File, ".go"):
		for _, m := range goPolicyRE.FindAllStringSubmatch(text, -1) {
			if m[1] == src.Policy {
				return healthscan.Policy{Name: m[1], HCL: m[2], Blocks: healthscan.ParsePolicyHCL(m[2])}
			}
		}
	default:
		for _, m := range shellPolicyRE.FindAllStringSubmatch(text, -1) {
			if m[1] != src.Policy {
				continue
			}
			var body struct {
				Policy string `json:"policy"`
			}
			if err := json.Unmarshal([]byte(m[2]), &body); err != nil {
				t.Fatalf("%s: policy %s body is not JSON: %v", src.File, src.Policy, err)
			}
			return healthscan.Policy{Name: m[1], HCL: body.Policy, Blocks: healthscan.ParsePolicyHCL(body.Policy)}
		}
	}
	t.Fatalf("policy %q not found in %s: the case no longer reads a real seeded policy", src.Policy, src.File)
	return healthscan.Policy{}
}

func buildSMTModel(t *testing.T, in smtCaseInput) smtModel {
	t.Helper()
	var policies []healthscan.Policy
	var sources []string
	for _, src := range in.Sources {
		policies = append(policies, extractPolicy(t, src))
		sources = append(sources, src.File+"#"+src.Policy)
	}
	names := make([]string, 0, len(in.InlineHCL))
	for name := range in.InlineHCL {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !in.Constructed {
			t.Fatalf("case %s: inline_policies are allowed only in a constructed case", in.Case)
		}
		policies = append(policies, healthscan.Policy{Name: name, HCL: in.InlineHCL[name], Blocks: healthscan.ParsePolicyHCL(in.InlineHCL[name])})
		sources = append(sources, "inline#"+name)
	}
	if len(policies) == 0 {
		t.Fatalf("case %s: no policies", in.Case)
	}

	mapper, err := NewPathMapper(in.Projects, in.Environments, in.KVMounts, in.PathMap)
	if err != nil {
		t.Fatalf("case %s: NewPathMapper: %v", in.Case, err)
	}
	listing := map[string][]string{}
	for _, km := range in.KVMounts {
		listing[km.Path] = in.KVListing[km.Path]
	}
	mapper.SetKVTree(kvTree(listing)) // as plan-access lists the Vault the case was seeded from.
	out := smtModel{Case: in.Case, Description: in.Description, Constructed: in.Constructed,
		Sources: sources, Imports: in.Imports, Grants: []smtGrant{}, Unmappable: []smtUnmappable{}}
	for _, km := range in.KVMounts {
		out.KVMounts = append(out.KVMounts, smtMount(km))
	}
	for _, p := range policies {
		if len(p.Blocks) == 0 {
			t.Fatalf("case %s: policy %s parsed to zero stanzas", in.Case, p.Name)
		}
		for _, b := range p.Blocks {
			out.VaultRules = append(out.VaultRules, smtRule{Policy: p.Name, Path: b.Path, Capabilities: b.Capabilities})
		}
	}
	for _, it := range BuildPolicyItems(policies, mapper) {
		switch it.Outcome {
		case Create:
			out.Grants = append(out.Grants, smtGrant{Permissions: it.ProposedPermissions,
				ProjectID: it.ProposedProjectID, EnvironmentID: it.ProposedEnvironmentID, SourceRef: it.SourceRef})
		case Unmappable:
			out.Unmappable = append(out.Unmappable, smtUnmappable{SourceRef: it.SourceRef, Category: string(it.Category)})
		default:
			t.Fatalf("case %s: unexpected outcome %q from BuildPolicyItems", in.Case, it.Outcome)
		}
	}
	return out
}

func TestSMTModels_MatchAccessplanOnRealPolicies(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join(smtCasesDir, "*.input.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) == 0 {
		t.Fatalf("no cases under %s", smtCasesDir)
	}
	real := 0
	for _, inPath := range inputs {
		raw, err := os.ReadFile(inPath)
		if err != nil {
			t.Fatal(err)
		}
		var in smtCaseInput
		if err := json.Unmarshal(raw, &in); err != nil {
			t.Fatalf("%s: %v", inPath, err)
		}
		if want := strings.TrimSuffix(filepath.Base(inPath), ".input.json"); in.Case != want {
			t.Fatalf("%s: case %q does not match its file name", inPath, in.Case)
		}
		if !in.Constructed {
			real++
		}
		got, err := json.MarshalIndent(buildSMTModel(t, in), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, '\n')
		modelPath := strings.TrimSuffix(inPath, ".input.json") + ".model.json"
		if *updateSMTModels {
			if err := os.WriteFile(modelPath, got, 0o644); err != nil { // #nosec G306 -- committed test fixture
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(modelPath)
		if err != nil {
			t.Fatalf("%s: %v (regenerate with -update-smt-models)", modelPath, err)
		}
		if string(want) != string(got) {
			t.Errorf("%s is stale: accessplan or a seeded policy changed; regenerate with -update-smt-models and re-run docs/formal/smt/check.py\n--- got ---\n%s", modelPath, got)
		}
	}
	// The spike's claim is "5 real policies"; keep the count honest.
	if real < 5 {
		t.Fatalf("only %d non-constructed cases; the spike claims at least 5 real ones", real)
	}
	t.Logf("smt models: %d cases (%d from real seeded policies)", len(inputs), real)
}
