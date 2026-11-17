package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #3743: every key in ignoredSettingPaths will be rejected after the next minor
// release, so an operator must be told to remove it. The list comes from code;
// each path must appear in an upgrade note (docs/UPGRADING.md or a fragment in
// docs/upgrading.d/). It checks that the path is named there, not that the note
// is good.
func TestIgnoredSettingPaths_AreInAnUpgradeNote(t *testing.T) {
	if len(ignoredSettingPaths) == 0 {
		t.Fatal("ignoredSettingPaths is empty; the guard would be vacuous")
	}
	var notes strings.Builder
	files, err := filepath.Glob("../../docs/upgrading.d/*.md")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, "../../docs/UPGRADING.md")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		notes.Write(b)
	}
	for _, p := range ignoredSettingPaths {
		if !strings.Contains(notes.String(), "`"+p+"`") && !strings.Contains(notes.String(), `"`+p+`"`) {
			t.Errorf("ignored config key %q is not named in docs/UPGRADING.md or docs/upgrading.d/: add an upgrade note telling operators to remove it", p)
		}
	}
}
