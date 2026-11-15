package main

// MQ-LEG-OVERHEAD-1 P2: the leg-completeness assertions run as steps of the
// static-analysis job. The ruleset still requires the context
// `assert-leg-completeness`, so the job of that name must keep existing and
// must stay skipped (a skipped job satisfies a required context and takes no
// runner). These checks keep both halves honest: nothing is dropped from the
// moved assertions, and none of them can hide another step's failure.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type foldStep struct {
	Name string `yaml:"name"`
	If   string `yaml:"if"`
	Run  string `yaml:"run"`
}

type foldJob struct {
	If    string     `yaml:"if"`
	Steps []foldStep `yaml:"steps"`
}

func loadFoldJobs(t *testing.T) map[string]foldJob {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]foldJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatalf("ci.yml: %v", err)
	}
	return wf.Jobs
}

// The required context keeps reporting, as a job that never gets a runner.
func TestLegCompletenessContextIsAnAlwaysSkippedPlaceholder(t *testing.T) {
	j, ok := loadFoldJobs(t)["assert-leg-completeness"]
	if !ok {
		t.Fatal("ci.yml lost the job assert-leg-completeness: the ruleset requires that context, so it would never report and every PR would wait on it")
	}
	if strings.TrimSpace(j.If) == "" {
		t.Fatal("assert-leg-completeness has no if: it would take a runner on every event")
	}
	// Skipped on every event ci.yml triggers on.
	for _, ev := range []string{"pull_request", "merge_group", "push", "schedule", "workflow_dispatch"} {
		on, err := evalIf(j.If, resolver(ev, map[string]string{}))
		if err != nil {
			t.Fatalf("assert-leg-completeness if %q: %v", j.If, err)
		}
		if on {
			t.Fatalf("assert-leg-completeness (placeholder for the required context) would run on %s; a live job here runs the assertions twice", ev)
		}
	}
	for _, s := range j.Steps {
		if strings.Contains(s.Run, "assert_") {
			t.Fatalf("placeholder job assert-leg-completeness has an assertion step %q: the assertions belong to static-analysis", s.Name)
		}
	}
}

// Every assertion function the old job called is still called, exactly once,
// by a static-analysis step that cannot be skipped by an earlier red step.
func TestLegCompletenessAssertionsRunInStaticAnalysis(t *testing.T) {
	jobs := loadFoldJobs(t)
	sa, ok := jobs["static-analysis"]
	if !ok {
		t.Fatal("ci.yml has no job static-analysis")
	}
	want := []string{
		"assert_leg_completeness",
		"assert_pinned_leg_packages_valid",
		"assert_all_shards_complete",
		"assert_test_weights_valid",
		"assert_matrix_consistent .github/workflows/ci.yml",
	}
	for _, fn := range want {
		var hits []foldStep
		for _, s := range sa.Steps {
			for line := range strings.SplitSeq(s.Run, "\n") {
				if strings.TrimSpace(line) == fn {
					hits = append(hits, s)
				}
			}
		}
		if len(hits) != 1 {
			t.Fatalf("static-analysis runs %q in %d steps, want exactly 1", fn, len(hits))
		}
	}
	// No step of the group may be skipped because an earlier one failed: each
	// must start with the not-cancelled guard, so one red step never hides
	// another (govulncheck, gosec and the five assertions all report).
	guard := "success() || failure()"
	for i, s := range sa.Steps {
		isAssert := strings.Contains(s.Run, "assert_")
		isGosec := s.Name == "gosec"
		if !isAssert && !isGosec {
			continue
		}
		if !strings.Contains(s.If, guard) {
			t.Errorf("static-analysis step %d %q has if=%q; it must contain %q so an earlier failure does not skip it", i, s.Name, s.If, guard)
		}
	}
}
