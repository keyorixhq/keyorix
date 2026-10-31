package statemap

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The drills under scripts/drills run on SQLite by default, and a step written for SQLite (sqlite3 on
// the database file, a data-directory trick) silently never ran on the PostgreSQL pilot installs:
// AUDIT-SEAL-TAILS-3 left accept-loss.sh unrun on Postgres. This guard fails when a drill script
// switches on DRILL_BACKEND towards SQLite without any PostgreSQL branch, and when a drill is missing
// from scripts/drills/README.md (whose backends column is the coverage table the docs repeat).
//
// What it recognises (the idioms the scripts use today; extend the regexps with a new idiom):
//   - a SQLite switch: DRILL_BACKEND compared with "sqlite" ( = , == , != , case pattern "sqlite") );
//   - a PostgreSQL branch: DRILL_BACKEND compared with "postgres", or a `drill_skip postgres` line
//     (the explicit, printed skip).
//
// What it does NOT prove: that the PostgreSQL branch is right (the drills run on Postgres for that),
// nor that a SQLite-only command (sqlite3, ulimit -f) outside any switch is covered.

var (
	drillSQLiteSwitch = regexp.MustCompile(`DRILL_BACKEND"?\s*(=|==|!=)\s*"?sqlite"?|^\s*"?sqlite"?\)`)
	// a hand-written "skipped" message instead of `drill_skip <backend> <reason>` (SKIP <backend>: <reason>)
	drillAdHocSkip      = regexp.MustCompile(`\b(echo|ok|step)\b.*\bskipped\b`)
	drillPostgresBranch = regexp.MustCompile(`DRILL_BACKEND"?\s*(=|==|!=)\s*"?postgres"?|drill_skip\s+postgres\b|^\s*"?postgres"?\)`)
)

// drillBackendSwitchViolations returns one line per problem in a drill script's text.
func drillBackendSwitchViolations(script string) []string {
	var out, sqliteLines []string
	hasPostgres := false
	for i, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if drillAdHocSkip.MatchString(line) {
			out = append(out, "ad-hoc skip message, use `drill_skip <backend> <reason>` (line "+strconv.Itoa(i+1)+"): "+trimmed)
		}
		if drillSQLiteSwitch.MatchString(line) {
			sqliteLines = append(sqliteLines, strings.TrimSpace(line)+" (line "+strconv.Itoa(i+1)+")")
		}
		if drillPostgresBranch.MatchString(line) {
			hasPostgres = true
		}
	}
	if len(sqliteLines) > 0 && !hasPostgres {
		out = append(out, "switches on DRILL_BACKEND towards SQLite with no PostgreSQL branch or `drill_skip postgres <reason>`: "+sqliteLines[0])
	}
	return out
}

func TestDrillScripts_BackendSwitchHasPostgresBranch_Fixtures(t *testing.T) {
	const sqliteOnly = `#!/usr/bin/env bash
if [ "$DRILL_BACKEND" = "sqlite" ]; then
    sqlite3 "$d/keyorix.db" "DELETE FROM audit_events"
fi
`
	const bothBranches = `#!/usr/bin/env bash
if [ "$DRILL_BACKEND" = "postgres" ]; then
    pg_sql exec "DELETE FROM audit_events"
else
    sqlite3 "$d/keyorix.db" "DELETE FROM audit_events"
fi
`
	const explicitSkip = `#!/usr/bin/env bash
[ "$DRILL_BACKEND" = "sqlite" ] || { drill_skip postgres "diskfull: SQLite data directory"; return 0; }
`
	const adHocSkip = `#!/usr/bin/env bash
[ "$DRILL_BACKEND" = "sqlite" ] || { echo "==> diskfull: skipped (needs sqlite)"; return 0; }
[ "$DRILL_BACKEND" = "postgres" ] || true
`
	const commentOnly = `#!/usr/bin/env bash
# if DRILL_BACKEND = "sqlite" we would call sqlite3 here
echo hello
`
	const caseSwitch = `case "$DRILL_BACKEND" in
sqlite) sqlite3 x ;;
esac
`
	for _, tc := range []struct {
		name, script  string
		wantViolation bool
	}{
		{"sqlite-only switch is a violation", sqliteOnly, true},
		{"sqlite-only case switch is a violation", caseSwitch, true},
		{"a hand-written 'skipped' echo is a violation", adHocSkip, true},
		{"both branches pass", bothBranches, false},
		{"sqlite switch with an explicit SKIP postgres passes", explicitSkip, false},
		{"a comment is not a switch", commentOnly, false},
	} {
		got := drillBackendSwitchViolations(tc.script)
		if (len(got) > 0) != tc.wantViolation {
			t.Errorf("%s: violations = %v, want violation=%v", tc.name, got, tc.wantViolation)
		}
	}
}

func TestDrillScripts_BackendSwitchHasPostgresBranch(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "scripts", "drills")
	scripts, err := filepath.Glob(filepath.Join(dir, "*.sh"))
	if err != nil || len(scripts) == 0 {
		t.Fatalf("no drill scripts found under %s (err %v)", dir, err)
	}
	var problems []string
	readme, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		problems = append(problems, "scripts/drills/README.md (the drill / backends / runtime / proves table) is missing")
	}
	for _, path := range scripts {
		name := filepath.Base(path)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range drillBackendSwitchViolations(string(body)) {
			problems = append(problems, name+": "+v)
		}
		if name == "lib.sh" || name == "load.sh" { // libraries, not drills
			continue
		}
		if !strings.Contains(string(readme), "`"+name+"`") {
			problems = append(problems, name+": not listed in scripts/drills/README.md")
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// drillCoverageRows returns "drill | backends" for each table row of a markdown file whose first
// cell is a backticked drill name; the later columns (README: runtime, what it proves) are ignored.
func drillCoverageRows(md string) []string {
	var rows []string
	for line := range strings.SplitSeq(md, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "| "), " | ")
		if len(cells) < 2 {
			continue
		}
		rows = append(rows, strings.TrimSpace(cells[0])+" | "+strings.TrimSpace(cells[1]))
	}
	return rows
}

// The covered-backends table in docs/operator/drill-disaster.md repeats the first two columns of
// scripts/drills/README.md; a drill whose coverage changes must change both.
func TestDrillScripts_DocsCoverageTableMatchesReadme(t *testing.T) {
	root := repoRoot(t)
	readme, err := os.ReadFile(filepath.Join(root, "scripts", "drills", "README.md"))
	if err != nil {
		t.Fatalf("scripts/drills/README.md: %v", err)
	}
	doc, err := os.ReadFile(filepath.Join(root, "docs", "operator", "drill-disaster.md"))
	if err != nil {
		t.Fatalf("docs/operator/drill-disaster.md: %v", err)
	}
	want, got := drillCoverageRows(string(readme)), drillCoverageRows(string(doc))
	if len(want) == 0 {
		t.Fatal("no drill rows found in scripts/drills/README.md")
	}
	if strings.Join(want, "\n") != strings.Join(got, "\n") {
		t.Errorf("docs/operator/drill-disaster.md covered-backends table differs from scripts/drills/README.md\nREADME:\n  %s\ndocs:\n  %s",
			strings.Join(want, "\n  "), strings.Join(got, "\n  "))
	}
}
