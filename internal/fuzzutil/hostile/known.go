package hostile

import (
	"fmt"
	"os"
	"strings"
)

// Known is a triaged finding a target declares, so the native fuzzer (which
// stops at its first failure) can keep exploring past it while the finding
// stays open. It is the in-repo, reviewed counterpart of KX_HOSTILE_ALLOW.
//
// A violation is suppressed only when ALL of these hold: its text starts with
// Prefix, ErrContains (when set) is a substring of some error the call
// returned, and When (when set) returns true for the harness state. Anything
// else, including a different violation in the same run, is still reported.
//
// What a Known entry does NOT verify: that the suppressed hit has the same root
// cause as the triaged one beyond what Prefix/ErrContains/When check. Keep the
// three as narrow as the finding allows; a broad Prefix hides novel findings
// of the same oracle class.
type Known struct {
	// ID is stable (cited from the report and the reproducer test), never reused.
	ID string
	// Class is the triage classification (HARDENING, DEFECT, ...).
	Class string
	// Prefix the violation text must start with (oracle tag and call label).
	Prefix string
	// ErrContains, when set, must be a substring of an error the call returned.
	ErrContains string
	// When, when set, narrows the match further on the harness state.
	When func(h *Harness) bool
	// Repro is the minimised program the reproducer test replays.
	Repro Program
}

func (k Known) matches(h *Harness, v string) bool {
	if !strings.HasPrefix(v, k.Prefix) {
		return false
	}
	if k.ErrContains != "" {
		found := false
		for _, e := range h.Errors() {
			if strings.Contains(e, k.ErrContains) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return k.When == nil || k.When(h)
}

// known returns the ID of the first Known entry that matches v, or "".
func (h *Harness) known(v string) string {
	for _, k := range h.cfg.Known {
		if k.matches(h, v) {
			return k.ID
		}
	}
	return ""
}

// Errors returns the text of every error a Run call returned so far.
func (h *Harness) Errors() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.errs...)
}

// Evaluate closes the servers, applies the end-of-call oracles (as Finish
// does) and returns every violation, including the ones a Known entry or
// KX_HOSTILE_ALLOW would suppress. Reproducer tests use it; fuzz bodies use
// Finish.
func (h *Harness) Evaluate() []string {
	h.Finish(func(string, ...any) {})
	return h.Violations()
}

// TB is the part of testing.TB the reproducer needs.
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// RequireKnownReproduces is the reproducer for a Known entry: h must be a
// harness that ran k.Repro (k does not need to be in its Config), and the run
// must produce a violation k matches, or t fails. It goes red when the finding
// is fixed, which is the signal to delete the entry and keep the program as an
// ordinary regression seed.
func RequireKnownReproduces(t TB, k Known, h *Harness) {
	t.Helper()
	vs := h.Evaluate()
	for _, v := range vs {
		if k.matches(h, v) {
			return
		}
	}
	t.Fatalf("known finding %s no longer reproduces with program %s (violations: %v): if it was fixed, delete the Known entry and keep the program as a regression seed", k.ID, k.Repro, vs)
}

func (h *Harness) reportKnown(id, v string) {
	fmt.Fprintf(os.Stderr, "HOSTILE-KNOWN[%s]: %s | program: %s\n", id, v, h.cfg.Program)
}
