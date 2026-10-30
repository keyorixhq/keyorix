package docsdrift

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// HELM-PILOT-TAILS-2: every chart value the docs tell a user to set must exist in
// deploy/helm/keyorix/values.yaml. Helm accepts `--set no.such.key=1` silently, so a
// renamed or misspelled key in the docs (web.replicaCount for web.replicas) leaves the
// operator with a working install that ignores their setting.
//
// What it reads: every `--set`, `--set-string` and `--set-file` key in docs/**/*.md,
// README.md and the chart README (a command's backslash continuations are joined, so
// `--set` on a continuation line is seen), plus the first-column keys of the chart
// README's value tables. What it does NOT read: YAML `values:` blocks (no marker says
// which chart a block belongs to), keys written without `--set`, and the reverse
// direction (a values.yaml key that no doc mentions is fine).
//
// Skipped on purpose: the `keyorix ... --set` CLI flag (secret description/tags), and
// docs/k8s-operator.md, whose helm commands install the operator and sync agent charts
// with their own values.

const keyorixChartValues = "deploy/helm/keyorix/values.yaml"

// chartDocSkip lists docs whose `--set` keys belong to another chart.
var chartDocSkip = map[string]string{
	"docs/k8s-operator.md": "installs the operator / k8s-sync charts, which have their own values",
}

// valuesKeysWithoutDefault are real, documented chart inputs that values.yaml
// deliberately does not declare (an empty placeholder would let a render succeed
// without them); the chart fails the render when they are unset.
var valuesKeysWithoutDefault = map[string]string{
	"postgresql.auth.password": "no default on purpose: secret.yaml fails the render when unset",
}

var (
	setFlagRe  = regexp.MustCompile(`--set(?:-string|-file)?[ =]+['"]?([A-Za-z_][A-Za-z0-9_.\[\]-]*)`)
	cliSetRe   = regexp.MustCompile(`\bkeyorix\s+(?:secret|project|env|environment)\b`)
	readmeKeyR = regexp.MustCompile("^\\|\\s*`([A-Za-z_][A-Za-z0-9_.\\[\\]-]*)`\\s*\\|")
	indexRe    = regexp.MustCompile(`\[[0-9]*\]`)
)

// chartKeysInDocs returns doc path -> keys it tells users to set on the keyorix chart.
func chartKeysInDocs(t testing.TB, root string) map[string][]string {
	t.Helper()
	files := []string{"README.md", "deploy/helm/keyorix/README.md"}
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".md") {
			rel, _ := filepath.Rel(root, p)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk docs: %v", err)
	}
	out := map[string][]string{}
	for _, rel := range files {
		if _, skip := chartDocSkip[rel]; skip {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) //nolint:gosec // repo-relative doc path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		out[rel] = extractSetKeys(string(b), rel == "deploy/helm/keyorix/README.md")
	}
	return out
}

// extractSetKeys finds the `--set` keys in markdown text; tableKeys also reads the
// first column of `| `key` | ... |` rows (the chart README's value tables).
func extractSetKeys(md string, tableKeys bool) []string {
	md = strings.ReplaceAll(md, "\\\n", " ")
	seen := map[string]bool{}
	var keys []string
	add := func(k string) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for line := range strings.SplitSeq(md, "\n") {
		if m := readmeKeyR.FindStringSubmatch(line); tableKeys && m != nil && strings.Contains(m[1], ".") {
			add(m[1])
		}
		if cliSetRe.MatchString(line) {
			continue
		}
		for _, m := range setFlagRe.FindAllStringSubmatch(line, -1) {
			add(m[1])
		}
	}
	return keys
}

// chartValueKeyExists reports whether key (indices stripped) resolves in the values tree. Below a
// node that is null, empty or a scalar/list the rest of the path is free-form
// (postgresql.settings.max_connections, resources.limits.cpu) and accepted.
func chartValueKeyExists(values map[string]any, key string) bool {
	var cur any = values
	for seg := range strings.SplitSeq(indexRe.ReplaceAllString(key, ""), ".") {
		m, ok := cur.(map[string]any)
		if !ok || len(m) == 0 {
			return true
		}
		next, ok := m[seg]
		if !ok {
			return false
		}
		cur = next
	}
	return true
}

func TestEveryDocumentedChartSetKeyExistsInValues(t *testing.T) {
	g := guardrules.Rollout(t)
	root := filepath.Join("..", "..")
	b, err := os.ReadFile(filepath.Join(root, keyorixChartValues)) //nolint:gosec // fixed repo path
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(b, &values); err != nil {
		t.Fatalf("parse %s: %v", keyorixChartValues, err)
	}
	docs := chartKeysInDocs(t, root)
	total := 0
	var paths []string
	for p := range docs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		for _, k := range docs[p] {
			total++
			if _, ok := valuesKeysWithoutDefault[k]; ok {
				continue
			}
			if !chartValueKeyExists(values, k) {
				g.Errorf("%s tells users to set %q, which is not in %s: fix the key in the doc (helm ignores an unknown --set key without an error)", p, k, keyorixChartValues)
			}
		}
	}
	if total < 10 {
		g.Fatalf("only %d chart keys found in the docs: the extraction is broken", total)
	}
	g.Logf("%d chart keys checked across %d docs", total, len(docs))
}

func TestChartSetKeyExtraction(t *testing.T) {
	md := "helm install kx ./chart \\\n  --set a.b=1 \\\n  --set-file c.d=f\n" +
		"keyorix secret tags --id 4 --set prod\n" +
		"| `x.y` | `\"\"` | doc |\n| `plain` | `1` | doc |\n" +
		"`--set 'e.f[0].g=1'`\n"
	got := strings.Join(extractSetKeys(md, true), ",")
	if want := "x.y,a.b,c.d,e.f[0].g"; got != want && got != "a.b,c.d,x.y,e.f[0].g" {
		t.Fatalf("keys = %s", got)
	}
	values := map[string]any{"a": map[string]any{"b": 1}, "m": map[string]any{}, "e": map[string]any{"f": []any{}}}
	for key, want := range map[string]bool{"a.b": true, "a.z": false, "z": false, "m.any.thing": true, "e.f[0].g": true} {
		if chartValueKeyExists(values, key) != want {
			t.Errorf("chartValueKeyExists(%q) = %v, want %v", key, !want, want)
		}
	}
}
