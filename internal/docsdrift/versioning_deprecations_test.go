package docsdrift

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// aliasRow matches one `{"old.path", "new.path"},` row of deprecatedSettingAliases.
var aliasRow = regexp.MustCompile(`(?m)^\s*\{"([^"]+)",\s*"([^"]+)"\},\s*$`)

// TestVersioningDoc_ListsEveryDeprecatedConfigAlias fails when a deprecated config
// key in internal/config/insecure_settings_aliases.go is missing from the
// "Current deprecations" table in docs/VERSIONING.md. It reads the Go source as
// text: the slice is unexported, and this package holds docs checks only. It does
// NOT check CLI flags or formats (those rows are maintained by hand); it states
// that limit so a green run is not read as "the whole table is complete".
func TestVersioningDoc_ListsEveryDeprecatedConfigAlias(t *testing.T) {
	root := repoRoot(t)
	src, err := os.ReadFile(filepath.Join(root, "internal", "config", "insecure_settings_aliases.go"))
	if err != nil {
		t.Fatal(err)
	}
	doc := readDoc(t, "docs/VERSIONING.md")

	rows := aliasRow.FindAllStringSubmatch(string(src), -1)
	if len(rows) == 0 {
		t.Fatal("found no deprecatedSettingAliases rows: the regexp no longer matches the source layout")
	}
	for _, r := range rows {
		oldKey, newKey := r[1], r[2]
		if !strings.Contains(doc, "`"+oldKey+"`") || !strings.Contains(doc, "`"+newKey+"`") {
			t.Errorf("docs/VERSIONING.md section 4 does not list deprecated key %q -> %q", oldKey, newKey)
		}
	}
}
