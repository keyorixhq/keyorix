package docsdrift

import (
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// aliasTableRow matches a renamed-settings table row of docs/CONFIGURATION.md:
// | `old.path` | `new.path` |
var aliasTableRow = regexp.MustCompile("(?m)^\\| `([^`]+)` \\| `([^`]+)` \\|\\s*$")

// missingAliasRows returns the "old -> new" pairs in want that doc's table does
// not list.
func missingAliasRows(doc string, want [][2]string) []string {
	have := map[[2]string]bool{}
	for _, m := range aliasTableRow.FindAllStringSubmatch(doc, -1) {
		have[[2]string{m[1], m[2]}] = true
	}
	var missing []string
	for _, p := range want {
		if !have[p] {
			missing = append(missing, p[0]+" -> "+p[1])
		}
	}
	return missing
}

// TestConfigurationDoc_ListsEveryDeprecatedAlias derives the alias list from
// config.DeprecatedSettingAliasPaths (the table Load rewrites) and requires each
// pair as a row of the renamed-settings table in docs/CONFIGURATION.md. It
// checks that code aliases are documented; a row for a removed alias is not
// flagged (TestDocsConfigKeysExist covers key existence).
func TestConfigurationDoc_ListsEveryDeprecatedAlias(t *testing.T) {
	want := config.DeprecatedSettingAliasPaths()
	if len(want) == 0 {
		t.Fatal("no deprecated aliases returned; the guard would be vacuous")
	}
	for _, m := range missingAliasRows(readDoc(t, "docs/CONFIGURATION.md"), want) {
		t.Errorf("docs/CONFIGURATION.md renamed-settings table lacks the row %s", m)
	}
}

// aliasTableHeader is the first line of the renamed-settings table in
// docs/CONFIGURATION.md; the table ends at the first line that is not a row.
const aliasTableHeader = "| Deprecated name | Current name |"

// staleAliasRows returns the "old -> new" rows of doc's renamed-settings table
// (only that table: other two-column tables are not read) that are not in want.
// A missing header is reported as a single entry, so a renamed heading cannot
// turn the check vacuous.
func staleAliasRows(doc string, want [][2]string) []string {
	_, rest, ok := strings.Cut(doc, aliasTableHeader+"\n")
	if !ok {
		return []string{"table header " + aliasTableHeader + " not found"}
	}
	have := map[[2]string]bool{}
	for _, p := range want {
		have[p] = true
	}
	var stale []string
	for line := range strings.SplitSeq(rest, "\n") {
		if !strings.HasPrefix(line, "|") {
			break
		}
		m := aliasTableRow.FindStringSubmatch(line)
		if m == nil {
			continue // the |---|---| separator
		}
		if !have[[2]string{m[1], m[2]}] {
			stale = append(stale, m[1]+" -> "+m[2])
		}
	}
	return stale
}

// TestConfigurationDoc_AliasTableHasNoStaleRows is the other direction of the
// test above: a row whose alias was removed from (or renamed in) the registry
// fails here, so the table and config.DeprecatedSettingAliasPaths agree exactly.
func TestConfigurationDoc_AliasTableHasNoStaleRows(t *testing.T) {
	want := config.DeprecatedSettingAliasPaths()
	if len(want) == 0 {
		t.Fatal("no deprecated aliases returned; the guard would be vacuous")
	}
	for _, s := range staleAliasRows(readDoc(t, "docs/CONFIGURATION.md"), want) {
		t.Errorf("docs/CONFIGURATION.md renamed-settings table has a row with no registry alias: %s", s)
	}
}

func TestConfigurationDocStaleAliasCheckCatchesPlantedError(t *testing.T) {
	doc := aliasTableHeader + "\n|---|---|\n| `a.old` | `a.insecure_new` |\n| `gone.old` | `gone.insecure_new` |\n\n| `other.table` | `x` |\n"
	got := staleAliasRows(doc, [][2]string{{"a.old", "a.insecure_new"}})
	if len(got) != 1 || !strings.HasPrefix(got[0], "gone.old") {
		t.Fatalf("stale = %v, want only gone.old (the row after the blank line is another table)", got)
	}
	if got := staleAliasRows("no table here\n", nil); len(got) != 1 {
		t.Fatalf("a missing header must be reported, got %v", got)
	}
}

func TestConfigurationDocAliasCheckCatchesPlantedError(t *testing.T) {
	doc := "| `a.old` | `a.insecure_new` |\n| `b.old` | `b.insecure_new` |\n"
	got := missingAliasRows(doc, [][2]string{{"a.old", "a.insecure_new"}, {"c.old", "c.insecure_new"}})
	if len(got) != 1 || !strings.HasPrefix(got[0], "c.old") {
		t.Fatalf("missing = %v, want only c.old", got)
	}
}
