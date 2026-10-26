package docsdrift

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// RELEASE-PREP-2: docs/UPGRADING.md numbers its sections (6a ... 6z, then 6aa) and every other
// document, and every changelog fragment, points at them by that number. Three pull
// requests each took "the next free letter" in parallel and shipped two 6g and three 6j,
// one of them an empty heading; every reference to "6g" then meant two sections.
//
// What is checked:
//
//   - every "## <number>" heading of UPGRADING.md is unique, and none is empty (a heading
//     directly followed by another heading);
//   - every lettered section reference ("§6q", "section 6v") on a line that names UPGRADING
//     (in any docs/ file, changelog.d/ fragment, SECURITY.md or README.md), and every "§6q"
//     inside UPGRADING.md itself, names a heading that exists.
//
// 6a to 6z are all taken, so the next section is 6aa: the reference pattern accepts any
// run of letters after the 6 ("§6aa", "section 6ab"), the same ids the heading pattern
// accepts, so a section past 6z gets its references checked too.
//
// What this does NOT check: that the section a reference points at is the RIGHT one (only
// that it exists and is unique), lettered sections other than 6 (§2, §7 are also used for
// other documents' sections; every lettered UPGRADING section is a 6<letters>, and "§5b" on a
// UPGRADING line names the hardening guide), a reference whose "UPGRADING" and "§6q" sit
// on different lines of a wrapped paragraph, and bare "6j" without a "§" or "section".

var (
	upgradingHeading = regexp.MustCompile(`^## (\d+[a-z]*(?:\.\d+)?)[. ]`)
	letteredSection  = regexp.MustCompile(`(?:§|[Ss]ections? )(6[a-z]+(?:\.\d+)?)\b`)
)

// upgradingHeadings returns the section id of every heading, in order, and the ids of
// headings that are directly followed by another heading or the end of the file.
func upgradingHeadings(doc string) (ids []string, empty []string) {
	lines := strings.Split(doc, "\n")
	cur := ""
	hasBody := false
	flush := func() {
		if cur != "" && !hasBody {
			empty = append(empty, cur)
		}
	}
	for _, line := range lines {
		if m := upgradingHeading.FindStringSubmatch(line); m != nil {
			flush()
			cur, hasBody = m[1], false
			ids = append(ids, m[1])
			continue
		}
		if strings.HasPrefix(line, "## ") {
			flush()
			cur, hasBody = "", false
			continue
		}
		if cur != "" && strings.TrimSpace(line) != "" {
			hasBody = true
		}
	}
	flush()
	return ids, empty
}

func TestUpgradingSectionNumbersAreUnique(t *testing.T) {
	g := guardrules.Rollout(t)
	ids, empty := upgradingHeadings(readDoc(g, "docs/UPGRADING.md"))
	if len(ids) < 20 {
		g.Fatalf("found only %d numbered headings in UPGRADING.md; the heading pattern no longer matches", len(ids))
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			g.Errorf("UPGRADING.md has two sections numbered %q: every reference to %q is ambiguous; give one of them the next free number and update its references", id, id)
		}
		seen[id] = true
	}
	for _, id := range empty {
		g.Errorf("UPGRADING.md section %q has no body (a heading directly followed by another heading)", id)
	}
}

func TestUpgradingSectionReferencesResolve(t *testing.T) {
	g := guardrules.Rollout(t)
	root := repoRoot(g)
	ids, _ := upgradingHeadings(readDoc(g, "docs/UPGRADING.md"))
	known := map[string]bool{}
	for _, id := range ids {
		known[id] = true
	}

	var files []string
	for _, dir := range []string{"docs", "changelog.d"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(p, ".md") {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			g.Fatal(err)
		}
	}
	files = append(files, filepath.Join(root, "SECURITY.md"), filepath.Join(root, "README.md"))
	sort.Strings(files)

	checked := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			g.Fatal(err)
		}
		rel, _ := filepath.Rel(root, f)
		isUpgrading := filepath.ToSlash(rel) == "docs/UPGRADING.md"
		for i, line := range strings.Split(string(b), "\n") {
			if !isUpgrading && !strings.Contains(line, "UPGRADING") {
				continue
			}
			for _, m := range letteredSection.FindAllStringSubmatch(line, -1) {
				checked++
				if !known[m[1]] {
					g.Errorf("%s:%d: refers to UPGRADING section %q, which has no heading in docs/UPGRADING.md", filepath.ToSlash(rel), i+1, m[1])
				}
			}
		}
	}
	g.Logf("%d lettered section references checked against %d headings", checked, len(known))
	if checked < 20 {
		g.Fatalf("only %d references were found; the reference pattern no longer matches the docs", checked)
	}
}

// TestUpgradingSectionCheckCatchesPlantedErrors is the red proof: a duplicate number, an
// empty heading and a reference to a missing section are each reported.
func TestUpgradingSectionCheckCatchesPlantedErrors(t *testing.T) {
	doc := "## 6g. First\n\ntext\n\n## 6g. Second\n\ntext\n\n## 6j. Empty\n## 6r. Next\n\ntext\n"
	ids, empty := upgradingHeadings(doc)
	if strings.Join(ids, ",") != "6g,6g,6j,6r" {
		t.Fatalf("ids = %v", ids)
	}
	if len(empty) != 1 || empty[0] != "6j" {
		t.Fatalf("empty = %v, want [6j]", empty)
	}
	if m := letteredSection.FindStringSubmatch("see UPGRADING.md §6q and section 6v"); m == nil || m[1] != "6q" {
		t.Fatalf("reference pattern did not match: %v", m)
	}
	// Past 6z: a reference to 6aa must be read as 6aa (and so checked), not skipped or cut to 6a.
	if got := letteredSection.FindAllStringSubmatch("UPGRADING §6aa and section 6ab.1", -1); len(got) != 2 || got[0][1] != "6aa" || got[1][1] != "6ab.1" {
		t.Fatalf("references past 6z must be matched whole, got %v", got)
	}
	if got := letteredSection.FindAllStringSubmatch("UPGRADING §2, §7 and section 4", -1); len(got) != 0 {
		t.Fatalf("numeric-only sections must be ignored, got %v", got)
	}
}
