package docsdrift

// kek_derived_wording_test.go -- LEAK-WORDING-TAILS-1. The evidence-signing key
// and the audit-checkpoint key are derived from the KEK (deriveEvidenceSignKey,
// deriveAuditCheckpointKey, info strings "...-kek-v2"), not from the DEK. The
// retired "-v1" scheme was DEK-derived, and for a long time the proto, the
// OpenAPI document and a dozen comments kept saying so. This guard fails when a
// non-ADR document or a Go comment calls such a key DEK-derived.
//
// # What it recognises
//
//   - TRIGGER: "DEK-derived" / "DEK derived", or "derived from (the) DEK".
//   - CONTEXT: the same text unit also says "checkpoint" or "evidence". The unit
//     is one Go comment block, one markdown paragraph / list item / table row,
//     one "//" block of the proto, or one description scalar of openapi.yaml. It
//     is wider than the single sentence the brief asked for on purpose: the real
//     wording put the key's origin in a different sentence from the word
//     "checkpoint" ("Write a signed checkpoint ... (ADR-029). Requires encryption
//     (the signing key is DEK-derived)"), which a sentence window misses.
//   - HISTORY: a unit that also says "not DEK-derived", "-v1" or "retired" is
//     the explanation of the old scheme and is left alone. ("superseded" is not
//     on the list: the old OpenAPI text said "a superseded DEK version".)
//
// # What it does not recognise
//
//   - String literals (a runtime error message that says the signing key "is
//     derived from the DEK" is not a comment), _test.go files, the CLI module
//     (separate go.mod), generated TypeScript (derived from openapi.yaml), ADRs
//     (docs/adr-*.md: Andrei edits those), changelog fragments and CHANGELOG.md.
//   - A paraphrase ("the key is bound to the DEK", "under the data key"). It is
//     a phrase guard, not a model of what the text means.
//   - A DEK-derived key that is not a checkpoint or evidence key (a per-row MAC
//     in docs/specs/audit-request-id.md): out of context, so out of scope.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

var (
	dekDerivedClaim = regexp.MustCompile(`(?i)\bDEK[- ]derived\b|\bderived from (?:the |a |an )?DEK\b`)
	keyContextWord  = regexp.MustCompile(`(?i)\bcheckpoints?\b|\bevidence\b`)
	dekHistory      = regexp.MustCompile(`(?i)\bnot (?:the )?DEK[- ]derived\b|\bnot derived from (?:the )?DEK\b|-v1\b|\bretired\b`)
)

// wordingUnit is one run of text judged as a whole.
type wordingUnit struct {
	line int
	text string
}

// wordingExemptions are repo-relative files the guard skips, each with the
// reason and what removes the exemption.
var wordingExemptions = map[string]string{
	// Generated from cli/cmd/compliance.go:354-355 (TestCLIReferenceIsFresh); the
	// CLI lane fixes the source and regenerates. Remove when that lands.
	"docs/cli-reference.md": "generated from cli/cmd/compliance.go; the CLI lane regenerates it",
	// A startup comment outside LEAK-WORDING-TAILS-1's file list. Remove when it
	// says KEK (the key is encSvc.AuditCheckpointKey(), KEK-derived).
	"server/wire_encryption.go": "comment at line ~26 still says DEK; outside the lane's file list",
}

// wordingFindings returns one message per unit that calls a checkpoint or
// evidence key DEK-derived.
func wordingFindings(rel string, units []wordingUnit) []string {
	var out []string
	for _, u := range units {
		m := dekDerivedClaim.FindString(u.text)
		if m == "" || !keyContextWord.MatchString(u.text) || dekHistory.MatchString(u.text) {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d: %q beside checkpoint/evidence -- these keys are KEK-derived "+
			"(deriveEvidenceSignKey, deriveAuditCheckpointKey); say KEK-derived, or add \"not DEK-derived\" / \"retired -v1\" if you mean the old scheme", rel, u.line, m))
	}
	return out
}

func goCommentUnits(fset *token.FileSet, f *ast.File) []wordingUnit {
	var out []wordingUnit
	for _, g := range f.Comments {
		out = append(out, wordingUnit{line: fset.Position(g.Pos()).Line, text: collapseSpace(g.Text())})
	}
	return out
}

// protoCommentUnits groups consecutive "//" lines.
func protoCommentUnits(src string) []wordingUnit {
	var out []wordingUnit
	var cur []string
	start := 0
	flush := func() {
		if len(cur) > 0 {
			out = append(out, wordingUnit{line: start, text: collapseSpace(strings.Join(cur, " "))})
		}
		cur = nil
	}
	for i, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "//") {
			flush()
			continue
		}
		if len(cur) == 0 {
			start = i + 1
		}
		cur = append(cur, strings.TrimPrefix(t, "//"))
	}
	flush()
	return out
}

var (
	listItemStart = regexp.MustCompile(`^\s*(?:[-*+]|\d+[.)])\s`)
	yamlTextKey   = regexp.MustCompile(`^(\s*)(?:- )?(?:description|summary):\s*(>-?|\|-?)?\s*(.*)$`)
)

// markdownUnits returns the document's paragraphs, list items and table rows,
// outside fenced code.
func markdownUnits(doc string) []wordingUnit {
	lines, nums := proseLines(doc)
	var out []wordingUnit
	var cur []string
	start, prev := 0, 0
	flush := func() {
		if len(cur) > 0 {
			out = append(out, wordingUnit{line: start, text: collapseSpace(strings.Join(cur, " "))})
		}
		cur = nil
	}
	for i, line := range lines {
		t := strings.TrimSpace(line)
		switch {
		case t == "" || (prev != 0 && nums[i] != prev+1):
			flush()
		}
		prev = nums[i]
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "|") || strings.HasPrefix(t, "#") || listItemStart.MatchString(line) {
			flush()
		}
		if len(cur) == 0 {
			start = nums[i]
		}
		cur = append(cur, t)
		if strings.HasPrefix(t, "|") || strings.HasPrefix(t, "#") {
			flush()
		}
	}
	flush()
	return out
}

// yamlTextUnits returns each description / summary value of an OpenAPI document,
// folded or inline.
func yamlTextUnits(src string) []wordingUnit {
	lines := strings.Split(src, "\n")
	var out []wordingUnit
	for i := range lines {
		m := yamlTextKey.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		indent, marker, inline := len(m[1]), m[2], m[3]
		parts := []string{inline}
		if marker != "" {
			for j := i + 1; j < len(lines); j++ {
				t := strings.TrimSpace(lines[j])
				if t != "" && len(lines[j])-len(strings.TrimLeft(lines[j], " ")) <= indent {
					break
				}
				parts = append(parts, t)
			}
		}
		out = append(out, wordingUnit{line: i + 1, text: collapseSpace(strings.Join(parts, " "))})
	}
	return out
}

func collapseSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

// scanWording walks the repository and returns every finding.
func scanWording(t testing.TB, root string) (findings []string, scanned int) {
	t.Helper()
	fset := token.NewFileSet()
	skipped := map[string]bool{".git": true, ".scratch": true, ".claude": true, "node_modules": true, "vendor": true, "testdata": true, "tmp": true}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			if skipped[d.Name()] {
				return filepath.SkipDir
			}
			if _, statErr := os.Stat(filepath.Join(p, "go.mod")); statErr == nil {
				return filepath.SkipDir // a separate module (cli/, operator/, ...)
			}
			return nil
		}
		if _, skip := wordingExemptions[rel]; skip {
			return nil
		}
		var units []wordingUnit
		switch {
		case strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go"):
			f, perr := parser.ParseFile(fset, p, nil, parser.ParseComments|parser.SkipObjectResolution)
			if perr != nil {
				return fmt.Errorf("parsing %s: %w", rel, perr)
			}
			units = goCommentUnits(fset, f)
		case strings.HasPrefix(rel, "docs/") && strings.HasSuffix(rel, ".md") && !strings.HasPrefix(d.Name(), "adr-"):
			b, rerr := os.ReadFile(p) // #nosec G304 -- walked path under the repo root
			if rerr != nil {
				return rerr
			}
			units = markdownUnits(string(b))
		case rel == "server/proto/keyorix.proto":
			b, rerr := os.ReadFile(p) // #nosec G304 -- fixed path
			if rerr != nil {
				return rerr
			}
			units = protoCommentUnits(string(b))
		case rel == "server/http/handlers/openapi.yaml":
			b, rerr := os.ReadFile(p) // #nosec G304 -- fixed path
			if rerr != nil {
				return rerr
			}
			units = yamlTextUnits(string(b))
		default:
			return nil
		}
		scanned++
		findings = append(findings, wordingFindings(rel, units)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return findings, scanned
}

func TestNoDEKDerivedWordingForKEKDerivedKeys(t *testing.T) {
	g := guardrules.Rollout(t)
	findings, scanned := scanWording(t, repoRoot(t))
	if scanned < 500 {
		t.Fatalf("scanned only %d files; the walk or the file filters broke silently", scanned)
	}
	sort.Strings(findings)
	for _, f := range findings {
		g.Error(f)
	}
}

// TestDEKDerivedWordingExemptionsExist keeps the exemption list from outliving
// its file. It does not require the file to still carry the wording: the owner
// of a regenerated file must not have to touch this test.
func TestDEKDerivedWordingExemptionsExist(t *testing.T) {
	root := repoRoot(t)
	for rel, reason := range wordingExemptions {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("exemption %s has no reason", rel)
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Errorf("exempted file %s no longer exists (%v): remove the exemption", rel, err)
		}
	}
}

// TestDEKDerivedWordingScanner_Calibration is the guard's red/green proof. The
// red cases are the real wording this lane removed, not invented shapes.
func TestDEKDerivedWordingScanner_Calibration(t *testing.T) {
	type tc struct {
		name  string
		units []wordingUnit
		want  int
	}
	proto := protoCommentUnits(`  // Write a signed checkpoint of the verified audit-chain head on demand (ADR-029).
  // Requires encryption (the signing key is DEK-derived) and a chain that verifies.
  rpc WriteAuditCheckpoint(google.protobuf.Empty) returns (WriteAuditCheckpointResponse);
`)
	yaml := yamlTextUnits(`      description: >-
        Recomputes the HMAC over the supplied evidence-pack bytes with the server's
        DEK-derived signing key and compares it to the detached signature. A signature
        made under a superseded DEK version is reported as unverifiable.
      operationId: verifyComplianceEvidence
`)
	md := markdownUnits(`# Keys

| 4 | checkpoint key | KEK-derived, not DEK-derived, after #502 |
| 5 | audit-checkpoint key | the key is DEK-derived |

- a per-row MAC would need a DEK-derived key on the write path
- an unrelated list item about evidence packs
`)
	goSrc := "package x\n\n// startAuditCheckpointScheduler is enabled whenever a signing key is available\n" +
		"// (the key is DEK-derived), so a checkpoint is signed.\nfunc f() {}\n\n" +
		"// notary: the checkpoint key is KEK-derived; the retired -v1 scheme was DEK-derived.\nfunc g() {}\n"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", goSrc, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	cases := []tc{
		{"proto: origin in the next sentence (real old wording)", proto, 1},
		{"openapi: evidence pack, DEK-derived (real old wording)", yaml, 1},
		{"markdown: only the unqualified checkpoint row is red", md, 1},
		{"go comment: red, then the historical one is green", goCommentUnits(fset, f), 1},
		{"KEK-derived is green", []wordingUnit{{1, "the checkpoint key is KEK-derived"}}, 0},
		{"derived from the DEK is red", []wordingUnit{{1, "the evidence key is derived from the DEK"}}, 1},
		{"DEK-derived without a checkpoint or evidence word is green", []wordingUnit{{1, "a per-row MAC needs a DEK-derived key"}}, 0},
		{"not DEK-derived explanation is green", []wordingUnit{{1, "the checkpoint key is KEK-derived, not DEK-derived"}}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := wordingFindings("x", c.units); len(got) != c.want {
				t.Errorf("got %d findings, want %d: %v", len(got), c.want, got)
			}
		})
	}
}
