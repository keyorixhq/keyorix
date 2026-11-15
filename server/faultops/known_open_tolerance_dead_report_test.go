package faultops

// known_open_tolerance_dead_report_test.go — both directions of how
// TestKnownOpenTolerances_AreLoadBearing reports a dead row (FLAKE-ROOT-NOV-4
// item 2): as a logged closed finding on a pull_request / merge_group run, as a
// failure under KEYORIX_GUARD_ROLLOUT=enforce (main push, nightly).

import (
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// deadReportTB records what the report would have logged or failed with. It
// embeds testing.TB only for the methods the report does not use.
type deadReportTB struct {
	testing.TB
	errs, logs []string
}

func (r *deadReportTB) Errorf(f string, a ...any) { r.errs = append(r.errs, fmt.Sprintf(f, a...)) }
func (r *deadReportTB) Logf(f string, a ...any)   { r.logs = append(r.logs, fmt.Sprintf(f, a...)) }
func (r *deadReportTB) Helper()                   {}

func TestKnownOpenToleranceDeadRowIsReportedAsClosedFinding(t *testing.T) {
	dead := []string{"REST POST /x/GetFoo/error#1", "REST POST /y/GetBar/error#2"}

	t.Setenv(guardrules.EnvRollout, "")
	r := &deadReportTB{TB: t}
	reportDeadKnownOpenTolerances(r, dead)
	if len(r.errs) != 0 {
		t.Fatalf("a dead row must not fail a queue run (it only means a PR fixed the bug), got %v", r.errs)
	}
	if len(r.logs) != len(dead) {
		t.Fatalf("want one FINDING CLOSED line per dead row (%d), got %v", len(dead), r.logs)
	}
	for i, label := range dead {
		if !strings.Contains(r.logs[i], "FINDING CLOSED: knownOpenTolerances/"+label) {
			t.Errorf("log line %d does not name %q as a closed finding: %q", i, label, r.logs[i])
		}
	}

	t.Setenv(guardrules.EnvRollout, "enforce")
	r = &deadReportTB{TB: t}
	reportDeadKnownOpenTolerances(r, dead)
	if len(r.errs) != len(dead) {
		t.Fatalf("under %s=enforce every dead row must fail, got errs=%v logs=%v", guardrules.EnvRollout, r.errs, r.logs)
	}

	// Nothing dead, nothing reported, in either mode.
	r = &deadReportTB{TB: t}
	reportDeadKnownOpenTolerances(r, nil)
	if len(r.errs)+len(r.logs) != 0 {
		t.Fatalf("no dead rows must report nothing, got errs=%v logs=%v", r.errs, r.logs)
	}
}
