package healthscan

import (
	"context"
	"fmt"
)

// Severity is a check's risk level. SeverityInfo is a legitimate outcome for a check that found
// nothing wrong (e.g. reporting the detected Vault version) — not every Finding is a problem.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding is one check's result: id, severity, evidence, why it matters, and a concrete
// remediation — the shape G2's spec requires for every check. Remediation is empty for an
// info-severity finding that isn't a problem (nothing to remediate).
type Finding struct {
	ID           string
	Title        string
	Severity     Severity
	Evidence     string
	WhyItMatters string
	Remediation  string
}

// NotChecked records a check this scan could not run — almost always a Vault 403 for a path the
// configured token/policy doesn't grant. PolicyLine is the exact healthscan-policy.hcl stanza
// that would enable it, so the report can tell the operator precisely what to add.
type NotChecked struct {
	ID         string
	Reason     string
	PolicyLine string
}

// Result is what a CheckFunc returns: exactly one of Finding or NotChecked is non-nil.
// A non-nil Err means the check itself failed unexpectedly (not a permission denial) — Run
// still never aborts the scan for this; it folds Err into a NotChecked entry so one check's
// failure (a malformed response, an unreachable path) can never take down the whole report. See
// Run's doc comment.
type Result struct {
	Finding    *Finding
	NotChecked *NotChecked
	Err        error
}

// CheckFunc is one health-scan check.
type CheckFunc func(ctx context.Context, c *Client) Result

// Check pairs a CheckFunc with the metadata Run and the report need about it without invoking
// it: an id (matching Finding.ID/NotChecked.ID when it runs) and a human title, used when Err
// forces a synthetic NotChecked entry.
type Check struct {
	ID    string
	Title string
	Fn    CheckFunc
}

// registry holds every check registered via RegisterCheck. G1 ships this empty; G2 populates it
// (one RegisterCheck call per check file's init(), so adding a check never requires touching
// this file or Run).
var registry []Check

// RegisterCheck adds chk to the set Run executes. Called from each check file's init().
// Panics on a duplicate ID — a coding mistake (copy-pasted check file, ID typo colliding with an
// existing one) that must fail loudly at program startup, not silently shadow a check or merge
// two checks' results under one ID in the report.
func RegisterCheck(chk Check) {
	for _, existing := range registry {
		if existing.ID == chk.ID {
			panic(fmt.Sprintf("healthscan: duplicate check id %q (already registered as %q)", chk.ID, existing.Title))
		}
	}
	registry = append(registry, chk)
}

// Checks returns every registered check, in registration order. Exported for tests (own-package
// tests use registry directly; report_test.go's redaction test uses this to run the skeleton
// end to end without a check list of its own).
func Checks() []Check {
	out := make([]Check, len(registry))
	copy(out, registry)
	return out
}

// Run executes every registered check against c. See RunChecks — Run is just
// RunChecks(ctx, c, addr, generatedBy, registry), split out so tests can exercise a specific,
// hermetic check list without depending on (or polluting) the global registry.
func Run(ctx context.Context, c *Client, addr string, generatedBy string) *Report {
	return RunChecks(ctx, c, addr, generatedBy, registry)
}

// RunChecks executes checks against c, converting each Result into either a Finding or a
// NotChecked entry on the returned Report. A check that panics (an unhandled shape in a real
// Vault response, for instance) is recovered and folded into a NotChecked entry the same way an
// explicit Err is — "exit code 0 always unless the tool itself failed" (SESSION-G1) means one
// check's crash must never take the whole scan down.
func RunChecks(ctx context.Context, c *Client, addr string, generatedBy string, checks []Check) *Report {
	r := &Report{GeneratedBy: generatedBy, VaultAddr: addr}
	for _, chk := range checks {
		res := runOne(ctx, chk, c)
		switch {
		case res.Err != nil:
			r.NotChecked = append(r.NotChecked, NotChecked{
				ID:     chk.ID,
				Reason: fmt.Sprintf("check failed unexpectedly: %s", res.Err),
			})
		case res.NotChecked != nil:
			r.NotChecked = append(r.NotChecked, *res.NotChecked)
		case res.Finding != nil:
			r.Findings = append(r.Findings, *res.Finding)
		default:
			// A check that legitimately has nothing to report (e.g. inapplicable to this
			// deployment shape) is neither a finding nor a gap — silently omitted, not an error.
		}
	}
	return r
}

func runOne(ctx context.Context, chk Check, c *Client) (res Result) {
	defer func() {
		if p := recover(); p != nil {
			res = Result{Err: fmt.Errorf("panic: %v", p)}
		}
	}()
	return chk.Fn(ctx, c)
}
