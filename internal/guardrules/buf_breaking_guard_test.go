package guardrules

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// bufBreakingInvocation matches a `buf breaking` command line or the
// bufbuild/buf-breaking-action GitHub Action.
var bufBreakingInvocation = regexp.MustCompile(`\bbuf\s+breaking\b|\bbuf-breaking-action\b`)

// bufBreakingHits returns the 1-based line numbers of text that run `buf breaking`.
// Comment lines (leading '#') are prose, not invocations, and are skipped.
func bufBreakingHits(text string) []int {
	var hits []int
	for i, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if bufBreakingInvocation.MatchString(line) {
			hits = append(hits, i+1)
		}
	}
	return hits
}

// TestBufBreakingIsNotRunInCI keeps the ADR-105 conformance row honest
// (REVIEW-4097-DEEP-2). docs/adr-conformance-enforced.d/
// ADR-105-CREATESECRET-HELD-FIELD-NUMBERS-STAY-RESERVED.tsv says "buf breaking is
// not run in CI so [TestCreateSecretRequest_HeldFieldNumbers_CompiledDescriptor]
// is the only automated check". That is true while no workflow, scripts/ci file
// or Makefile target runs `buf breaking`. The day one does, the claim is stale:
// this test fails so the author updates the row (and the header comment of
// server/grpc/proto_reserved_fields_test.go) in the same PR.
//
// It is a read-only scan of .github/workflows, scripts/ci and the Makefile.
// Other places (docs, shell scripts elsewhere) are not looked at, and a
// `buf breaking` hidden behind a variable or a script outside those three is
// not seen.
func TestBufBreakingIsNotRunInCI(t *testing.T) {
	g := Rollout(t)
	root := srcpath.RepoRoot()

	var files []string
	files = append(files, filepath.Join(root, "Makefile"))
	for _, dir := range []string{".github/workflows", "scripts/ci"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // a missing directory has nothing to scan
			}
			if d.IsDir() {
				if skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			// Go tests under scripts/ci quote command lines as fixtures; they run nothing.
			if !strings.HasSuffix(p, "_test.go") {
				files = append(files, p)
			}
			return nil
		})
	}

	scanned := 0
	for _, f := range files {
		data, err := os.ReadFile(f) // #nosec G304 -- paths built from the repo root and a fixed list
		if err != nil {
			continue
		}
		scanned++
		rel, _ := filepath.Rel(root, f)
		for _, line := range bufBreakingHits(string(data)) {
			g.Errorf("%s:%d runs `buf breaking`. docs/adr-conformance-enforced.d/"+
				"ADR-105-CREATESECRET-HELD-FIELD-NUMBERS-STAY-RESERVED.tsv says \"buf breaking is "+
				"not run in CI\": update that row and the comment in "+
				"server/grpc/proto_reserved_fields_test.go to match, then adjust or retire this guard.", rel, line)
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no files: the repo-root layout changed, so this guard checks nothing")
	}
}

// TestBufBreakingGuard_Matcher shows the matcher both ways: it flags real
// invocations and ignores prose, so a green TestBufBreakingIsNotRunInCI means
// something.
func TestBufBreakingGuard_Matcher(t *testing.T) {
	for name, tc := range map[string]struct {
		text string
		want []int
	}{
		"make recipe":      {"proto-breaking:\n\tbuf breaking --against '.git#branch=main'\n", []int{2}},
		"workflow run":     {"      - run: buf breaking --against origin/main\n", []int{1}},
		"workflow action":  {"      - uses: bufbuild/buf-breaking-action@v1\n", []int{1}},
		"extra spaces":     {"buf   breaking", []int{1}},
		"comment only":     {"# buf breaking is not run in CI\n", nil},
		"buf lint":         {"\tbuf lint\n\tbuf generate\n", nil},
		"word boundary":    {"debuf breaking-news\n", nil},
		"second occurence": {"echo ok\nbuf breaking\n", []int{2}},
	} {
		t.Run(name, func(t *testing.T) {
			got := bufBreakingHits(tc.text)
			if len(got) != len(tc.want) {
				t.Fatalf("hits = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("hits = %v, want %v", got, tc.want)
				}
			}
		})
	}
}
