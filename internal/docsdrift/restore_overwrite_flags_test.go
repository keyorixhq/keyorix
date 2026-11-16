package docsdrift

// restore_overwrite_flags_test.go -- KEY-ROTATION-TAILS-NOV-1 item 2. Since
// KEY-ROTATION-SAFETY-1 (#4311) `admin restore --overwrite-existing` refuses a
// target database that holds data unless --replace-existing-data is given too
// (server/admin/restore_populated_guard.go). A document that tells an operator
// to restore over a working deployment with --overwrite-existing alone sends
// them into that refusal. This guard fails on such a line.
//
// # What it recognises
//
//   - TRIGGER: one text unit that names `admin restore` and, later in the same
//     sentence or table cell, `--overwrite-existing`. A unit is one markdown
//     paragraph / list item / table row outside fenced code, or one command
//     line inside fenced code with its backslash continuations joined.
//   - PASS: the unit names --replace-existing-data, or the unit or the lines
//     next to it (restoreFlagsWindow lines before and after) say the target is
//     empty: an empty / fresh / freshly migrated database, schema, target or
//     data directory (restoreEmptyTarget).
//
// # What it does not recognise
//
//   - CHANGELOG.md and changelog.d/ (history: they describe the flag as it was
//     when the entry was written) and docs/demo/** (DEMO-LOCAL-2 owns it; see
//     restoreFlagsExemptions).
//   - The units in restoreFlagsUnitExemptions, each with its reason.
//   - A restore described without the literal `admin restore` (for example
//     "re-run the restore with --overwrite-existing"): it is a phrase guard.
//   - Whether the "empty target" sentence is about the same restore. Being next
//     to the command is the whole check.

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

const restoreFlagsWindow = 3

var (
	restoreEmptyTarget = regexp.MustCompile(`(?i)\b(?:empty|fresh|freshly (?:created|migrated))(?: \w+)? ` +
		`(?:database|db|schema|target|data ?dir(?:ectory)?)\b|\bholds no data\b`)
	restoreSentenceEnd = regexp.MustCompile(`\.\s+[A-Z]|\|`)
)

// restoreFlagsExemptions are repo-relative path prefixes the guard skips, each
// with the reason and what removes the exemption.
var restoreFlagsExemptions = map[string]string{
	"docs/demo/": "owned by DEMO-LOCAL-2 (docs/demo/GOLDEN-PATH.md is a KEY-ROTATION-TAILS-NOV-1 leftover); remove when that lane adds the flag",
}

// restoreFlagsUnitExemption skips the one unit of file whose text contains
// needle: a line that is right as it stands (an older binary that has no
// --replace-existing-data, recorded output, a description of what the flag
// leaves behind). TestRestoreOverwriteFlagsExemptionsExist fails when the unit
// is gone or no longer triggers.
type restoreFlagsUnitExemption struct{ file, needle, reason string }

var restoreFlagsUnitExemptions = []restoreFlagsUnitExemption{
	{"docs/operator/upgrade-rollback.md", "backend ./keyorix-server admin restore --input /tmp/backup.tar.gz --overwrite-existing --allow-rollback",
		"rollback with the v0.96.x binary after DROP SCHEMA: an empty database, and that binary has no --replace-existing-data (the bullets below say so)"},
	{"docs/operator/upgrade-rollback.md", "keyorix-server admin restore --input keyorix-backup-pre-upgrade.tar.gz --overwrite-existing --allow-rollback --config keyorix.yaml",
		"SQLite rollback run with the old binary, which has no --replace-existing-data"},
	{"docs/operator/key-rotation-runbook.md", "$ keyorix-server admin restore --input ./backups/pre-rotation-2.tar.gz --overwrite-existing",
		"recorded rehearsal output; the paragraph above says it predates --replace-existing-data and that both commands now need it"},
	{"docs/operator/key-rotation-runbook.md", "files that `admin restore --overwrite-existing` leaves",
		"describes the *.pre-restore-* files the flag leaves, with or without --replace-existing-data; not an instruction"},
	{"docs/operator/restore-failure-modes.md", "keyorix-server admin restore --input ./backup.tar.gz --overwrite-existing --config ./keyorix.yaml",
		"re-run after --recover of a PostgreSQL restore killed in the load: the target holds only the empty schema (the paragraph above)"},
	{"docs/operator/startup-refusals.md", "Real output (an `admin backup` taken before the loss",
		"describes how recorded output was produced"},
}

func restoreFlagsUnitExempt(rel, text string) bool {
	for _, e := range restoreFlagsUnitExemptions {
		if e.file == rel && strings.Contains(text, e.needle) {
			return true
		}
	}
	return false
}

// restoreOverwriteWithoutReplace reports whether text names `admin restore`
// and then, before the sentence or table cell ends, --overwrite-existing,
// without --replace-existing-data.
func restoreOverwriteWithoutReplace(text string) bool {
	if strings.Contains(text, "--replace-existing-data") {
		return false
	}
	rest := text
	for {
		i := strings.Index(rest, "admin restore")
		if i < 0 {
			return false
		}
		rest = rest[i+len("admin restore"):]
		j := strings.Index(rest, "--overwrite-existing")
		if j < 0 {
			return false
		}
		if !restoreSentenceEnd.MatchString(rest[:j]) {
			return true
		}
	}
}

// restoreUnits returns the prose units (markdownUnits) and the fenced command
// lines of doc, the latter with backslash continuations joined.
func restoreUnits(doc string) []wordingUnit {
	units := markdownUnits(doc)
	for _, f := range fences(doc) {
		var cur []string
		start := 0
		for i, line := range f.Lines {
			t := strings.TrimSpace(line)
			if len(cur) == 0 {
				start = f.Line + i
			}
			cur = append(cur, strings.TrimSuffix(t, `\`))
			if !strings.HasSuffix(t, `\`) {
				units = append(units, wordingUnit{line: start, text: collapseSpace(strings.Join(cur, " "))})
				cur = nil
			}
		}
		if len(cur) > 0 {
			units = append(units, wordingUnit{line: start, text: collapseSpace(strings.Join(cur, " "))})
		}
	}
	return units
}

// restoreFlagsFindings returns one message per unit of doc that restores over
// a target with --overwrite-existing alone and does not say the target is empty.
func restoreFlagsFindings(rel, doc string) []string {
	lines := strings.Split(doc, "\n")
	var out []string
	for _, u := range restoreUnits(doc) {
		if !restoreOverwriteWithoutReplace(u.text) || restoreFlagsUnitExempt(rel, u.text) {
			continue
		}
		lo := max(u.line-1-restoreFlagsWindow, 0)
		hi := min(u.line+restoreFlagsWindow+strings.Count(u.text, " ")/8, len(lines))
		near := u.text + " " + collapseSpace(strings.Join(lines[lo:hi], " "))
		if restoreEmptyTarget.MatchString(near) {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d: `admin restore ... --overwrite-existing` without --replace-existing-data: "+
			"over a target that holds data the restore refuses (#4311). Add --replace-existing-data, or say next to it "+
			"that the target is an empty database", rel, u.line))
	}
	return out
}

// restoreFlagsDocs lists the documents the guard reads: docs/**/*.md and the
// repository's top-level *.md, without CHANGELOG.md and the exemptions.
func restoreFlagsDocs(t testing.TB, root string) []string {
	t.Helper()
	var out []string
	top, err := filepath.Glob(filepath.Join(root, "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range top {
		if filepath.Base(m) != "CHANGELOG.md" {
			out = append(out, filepath.Base(m))
		}
	}
	err = filepath.WalkDir(filepath.Join(root, "docs"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		for prefix := range restoreFlagsExemptions {
			if strings.HasPrefix(rel+"/", prefix) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if !d.IsDir() && strings.HasSuffix(rel, ".md") {
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func TestRestoreOverwriteExistingDocsNameReplaceExistingData(t *testing.T) {
	g := guardrules.Rollout(t)
	root := repoRoot(t)
	docs := restoreFlagsDocs(t, root)
	if len(docs) < 200 {
		t.Fatalf("read only %d documents; the walk or the filters broke silently", len(docs))
	}
	triggered := 0
	for _, rel := range docs {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- walked path under the repo root
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range restoreUnits(string(b)) {
			if strings.Contains(u.text, "admin restore") && strings.Contains(u.text, "--overwrite-existing") {
				triggered++
			}
		}
		for _, f := range restoreFlagsFindings(rel, string(b)) {
			g.Error(f)
		}
	}
	if triggered == 0 {
		t.Fatal("no document names `admin restore` with --overwrite-existing; the unit split broke silently")
	}
}

// TestRestoreOverwriteFlagsExemptionsExist keeps an exemption from outliving
// its directory.
func TestRestoreOverwriteFlagsExemptionsExist(t *testing.T) {
	root := repoRoot(t)
	for prefix, reason := range restoreFlagsExemptions {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("exemption %s has no reason", prefix)
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(prefix))); err != nil {
			t.Errorf("exempted path %s no longer exists (%v): remove the exemption", prefix, err)
		}
	}
	for _, e := range restoreFlagsUnitExemptions {
		if strings.TrimSpace(e.reason) == "" {
			t.Errorf("exemption %s %q has no reason", e.file, e.needle)
		}
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(e.file))) // #nosec G304 -- fixed repo-relative path
		if err != nil {
			t.Errorf("exempted file %s: %v: remove the exemption", e.file, err)
			continue
		}
		live := false
		for _, u := range restoreUnits(string(b)) {
			if strings.Contains(u.text, e.needle) && restoreOverwriteWithoutReplace(u.text) {
				live = true
			}
		}
		if !live {
			t.Errorf("exemption %s %q no longer matches a unit that triggers the guard: remove it", e.file, e.needle)
		}
	}
}

// TestRestoreOverwriteFlagsScanner_Calibration is the guard's red/green proof.
// The red cases are the real lines this item fixed.
func TestRestoreOverwriteFlagsScanner_Calibration(t *testing.T) {
	cases := []struct {
		name, doc string
		want      int
	}{
		{"SELF_HOSTING section 5 command (real old line)", "Then restore:\n\n```bash\n" +
			"docker compose run --rm -v /tmp:/tmp --entrypoint /app/keyorix-server \\\n" +
			"  backend ./keyorix-server admin restore --input /tmp/backup.tar.gz --overwrite-existing\n```\n", 1},
		{"recovery-options table cell (real old line)", "| **Who runs it** | Host operator: " +
			"`admin restore --input <archive> --overwrite-existing` | Host operator, master passphrase | Host operator, as A |\n", 1},
		{"continuation line joined", "```bash\nkeyorix-server admin restore --input b.tgz \\\n  --overwrite-existing --allow-rollback\n```\n", 1},
		{"both flags is green", "```bash\nkeyorix-server admin restore --input b.tgz --overwrite-existing --replace-existing-data\n```\n", 0},
		{"both flags across a continuation is green", "```bash\nkeyorix-server admin restore --input b.tgz \\\n  --overwrite-existing \\\n  --replace-existing-data\n```\n", 0},
		{"empty-target sentence next to it is green", "Re-running a restore into an empty database:\n\n" +
			"```bash\nkeyorix-server admin restore --input b.tgz --overwrite-existing\n```\n", 0},
		{"flag in a later sentence is not a trigger", "Run `admin restore`. Pass --overwrite-existing only when told.\n", 0},
		{"flag in a different table cell is not a trigger", "| `admin restore` | --overwrite-existing |\n", 0},
		{"unrelated empty word far away stays red", "The bucket is empty.\n\n\n\n\n\n\n\n" +
			"```bash\nkeyorix-server admin restore --input b.tgz --overwrite-existing\n```\n", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := restoreFlagsFindings("x.md", c.doc); len(got) != c.want {
				t.Errorf("got %d findings, want %d: %v", len(got), c.want, got)
			}
		})
	}
}
