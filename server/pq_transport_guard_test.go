package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestPQTransport_NothingNarrowsTheKeyExchange_RepoWide (RD-PQTLS-1): the hybrid
// post-quantum key exchange is lost silently if a non-test Go file assigns
// tls.Config.CurvePreferences, or an image/chart/compose/script/config file mentions
// the GODEBUG switch `tlsmlkem`. Enumeration, stated so a reviewer can check it: every
// file under the repository root except .git, .scratch, node_modules, docs/, changelog.d/,
// Markdown files and *_test.go; Go files are matched for a `CurvePreferences:` literal
// field or `.CurvePreferences =` assignment, every other file for the text `tlsmlkem`.
// It does not see a GODEBUG set by the operator's own environment or orchestrator.
func TestPQTransport_NothingNarrowsTheKeyExchange_RepoWide(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	assign := regexp.MustCompile(`CurvePreferences\s*(:|=[^=])`)
	skipDir := map[string]bool{".git": true, ".scratch": true, "node_modules": true, "docs": true, "changelog.d": true, ".demo-native": true}
	var offenders []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if skipDir[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".md") || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 2<<20 {
			return nil
		}
		b, err := os.ReadFile(path) // #nosec G304 -- repo files walked by this test
		if err != nil {
			return nil
		}
		s := string(b)
		rel, _ := filepath.Rel(root, path)
		if !strings.HasSuffix(path, ".go") && strings.Contains(s, "tlsmlkem") {
			offenders = append(offenders, rel+": mentions tlsmlkem")
		}
		if strings.HasSuffix(path, ".go") && assign.MatchString(s) {
			offenders = append(offenders, rel+": assigns CurvePreferences")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("something narrows or disables the post-quantum key exchange (see docs/post-quantum-transport.md):\n  %s", strings.Join(offenders, "\n  "))
	}
}
