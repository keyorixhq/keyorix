package docsdrift

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// RELEASE-PREP-2 item 3: the reverse of TestDocsConfigKeysExist. That test fails when a
// document names a key the code does not have; this one fails when the code has a key no
// document names.
//
// The leaf list is internal/config/testdata/config_surface_leaves.txt, which
// TestConfigSurface_LeafSetRatchet (internal/config) keeps equal to the live yaml surface of
// config.Config, so a new or renamed key lands here without anyone remembering to add it.
// A leaf counts as documented when docs/CONFIGURATION.md (the reference page), the
// self-hosting guide or the quick start names it as
//
//   - its full dotted path, anywhere in the text (prose, table, code block), or
//   - a key path of a ```yaml block (nested the way a config file is), or
//   - a first-column `key` of a table under a heading that names the parent in backticks
//     (`### gRPC keepalive (`server.grpc.keepalive`)` + `| `time` | ...`), or
//   - its last segment, when that segment contains an underscore and no other leaf of the
//     surface ends in the same segment (`key_dir_lock`, `max_connection_idle`): a bare
//     `pooler` or `enabled` proves nothing and never counts.
//
// The bare-name rule is a deliberate leniency: a document that mentions the name in
// unrelated prose satisfies it. What the test does NOT check is that the description is
// right, that the type or default is stated, or that the key is explained rather than
// listed.
//
// Keys that were already undocumented when the check was added are listed in
// testdata/undocumented_config_leaves.txt. The list can only shrink: a key that is not
// documented and not listed fails (new undocumented key), and a listed key that is
// documented now or no longer exists fails (delete the line).

const (
	configLeavesFile        = "internal/config/testdata/config_surface_leaves.txt"
	undocumentedLeavesFile  = "internal/docsdrift/testdata/undocumented_config_leaves.txt"
	undocumentedLeavesTitle = "undocumented_config_leaves.txt"
)

var (
	dottedToken   = regexp.MustCompile(`[a-z][a-z0-9_]*(?:\[\])?(?:\.[a-z][a-z0-9_]*(?:\[\])?)+`)
	headingParent = regexp.MustCompile("^#+ .*`([a-z][a-z0-9_]*(?:\\[\\])?(?:\\.[a-z][a-z0-9_]*(?:\\[\\])?)*)`")
	bareKeyRow    = regexp.MustCompile("^\\|\\s*`([a-z][a-z0-9_]*)`\\s*\\|")
)

func readLeafList(t testing.TB, rel string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var out []string
	for line := range strings.SplitSeq(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// documentedConfigLeaves returns the leaves among the given ones that the docs name.
func documentedConfigLeaves(docs []string, leaves []string) map[string]bool {
	paths := map[string]bool{}
	for _, doc := range docs {
		for _, tok := range dottedToken.FindAllString(doc, -1) {
			paths[strings.ReplaceAll(tok, "[]", "")] = true
		}
		for _, f := range fences(doc) {
			if f.Lang != "yaml" && f.Lang != "yml" {
				continue
			}
			if ps, ok := yamlDocKeyPaths(f.Body); ok {
				for _, p := range ps {
					paths[strings.ReplaceAll(p, "[]", "")] = true
				}
			}
		}
		// A table of bare keys under a heading that names their parent
		// (### gRPC keepalive (`server.grpc.keepalive`)): | `max_connection_idle` | ... |
		parent := ""
		lines, _ := proseLines(doc)
		for _, line := range lines {
			if strings.HasPrefix(line, "#") {
				parent = ""
				if m := headingParent.FindStringSubmatch(line); m != nil {
					parent = strings.ReplaceAll(m[1], "[]", "")
				}
				continue
			}
			if m := bareKeyRow.FindStringSubmatch(line); m != nil && parent != "" {
				paths[parent+"."+m[1]] = true
			}
		}
	}
	corpus := strings.ReplaceAll(strings.Join(docs, "\n"), "[]", "")

	lastCount := map[string]int{}
	for _, l := range leaves {
		lastCount[l[strings.LastIndex(l, ".")+1:]]++
	}
	out := map[string]bool{}
	for _, l := range leaves {
		last := l[strings.LastIndex(l, ".")+1:]
		switch {
		case paths[l]:
			out[l] = true
		case strings.Contains(last, "_") && lastCount[last] == 1 && regexp.MustCompile(`\b`+regexp.QuoteMeta(last)+`\b`).MatchString(corpus):
			out[l] = true
		}
	}
	return out
}

func configReferenceDocs(t testing.TB) []string {
	t.Helper()
	var docs []string
	for _, rel := range configDocs {
		docs = append(docs, readDoc(t, rel))
	}
	return docs
}

func TestEveryConfigKeyIsDocumented(t *testing.T) {
	g := guardrules.Rollout(t)
	leaves := readLeafList(g, configLeavesFile)
	if len(leaves) < 200 {
		g.Fatalf("only %d leaves read from %s", len(leaves), configLeavesFile)
	}
	for _, l := range leaves {
		if ok, bad := resolves(l); !ok {
			g.Fatalf("%s lists %q but config.Config has no field %q: the surface file is stale (TestConfigSurface_LeafSetRatchet should have failed)", configLeavesFile, l, bad)
		}
	}
	documented := documentedConfigLeaves(configReferenceDocs(g), leaves)

	known := map[string]bool{}
	for _, l := range readLeafList(g, undocumentedLeavesFile) {
		known[l] = true
	}
	onSurface := map[string]bool{}
	var missing []string
	for _, l := range leaves {
		onSurface[l] = true
		if !documented[l] && !known[l] {
			missing = append(missing, l)
		}
	}
	for _, l := range missing {
		g.Errorf("config key %q is not named in %v: document it in docs/CONFIGURATION.md (what it does, its default, when to change it). "+
			"Do not add it to %s", l, configDocs, undocumentedLeavesTitle)
	}
	var stale []string
	for l := range known {
		switch {
		case !onSurface[l]:
			stale = append(stale, l+" (no longer a config key)")
		case documented[l]:
			stale = append(stale, l+" (documented now)")
		}
	}
	sort.Strings(stale)
	for _, s := range stale {
		g.Errorf("%s lists %s: delete the line", undocumentedLeavesTitle, s)
	}
	g.Logf("%d config keys, %d documented, %d known undocumented", len(leaves), len(documented), len(known))
}

// TestEveryConfigKeyDocCheckCatchesPlantedError is the red proof for both directions:
// an undocumented key is reported, a documented one (full path, yaml nesting, unique
// underscore name) is not, and a bare single-word name does not count.
func TestEveryConfigKeyDocCheckCatchesPlantedError(t *testing.T) {
	leaves := []string{"a.documented_path", "a.b.in_yaml", "a.nested.key_dir_lock", "a.bare_word", "a.pooler", "c.pooler", "a.never_mentioned",
		"x.table.idle", "x.table.limit", "y.table.idle"}
	docs := []string{"The key `a.documented_path` does X.\n\n```yaml\na:\n  b:\n    in_yaml: 1\n```\n\nSet key_dir_lock on every replica. We say pooler a lot and bare_word.\n\n" +
		"### Table (`x.table`)\n\n| Key | Default |\n|---|---|\n| `idle` | 1m |\n\n### No parent here\n\n| `limit` | 2 |\n"}
	got := documentedConfigLeaves(docs, leaves)
	for _, want := range []string{"a.documented_path", "a.b.in_yaml", "a.nested.key_dir_lock", "a.bare_word", "x.table.idle"} {
		if !got[want] {
			t.Errorf("%s should count as documented", want)
		}
	}
	for _, not := range []string{"a.pooler", "c.pooler", "a.never_mentioned", "x.table.limit", "y.table.idle"} {
		if got[not] {
			t.Errorf("%s must not count as documented", not)
		}
	}
}
