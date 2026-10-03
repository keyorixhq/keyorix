// Package report writes keyorix-migrate's per-item result report — JSON (machine-readable,
// one object per line, flushed per item so a killed-mid-run process leaves a valid prefix —
// docs/design-keyorix-migrate.md's "Resume" section) and a human-readable line to stdout.
// Neither format ever carries a secret value or an unsanitized error that could echo one —
// see docs/design-keyorix-migrate.md's "Never log, print, or report a secret value".
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/keyorixhq/keyorix/migrate/internal/plan"
)

// Line is one JSON report entry. Deliberately has no field that could carry a secret value —
// this is the whole contract the canary-value test (docs/design-keyorix-migrate.md) checks.
type Line struct {
	Source  string `json:"source"`           // human-readable locator (path), no value.
	Target  string `json:"target"`           // Keyorix secret name.
	Outcome string `json:"outcome"`          // create|update|skip|conflict|error.
	Ran     bool   `json:"ran"`              // whether Apply actually wrote anything.
	Reason  string `json:"reason,omitempty"` // e.g. "already up to date", a conflict explanation.
	Error   string `json:"error,omitempty"`  // sanitized error message, if any.
	DryRun  bool   `json:"dry_run"`          // true when this line came from a plan, not an apply.
	// ErrorKind classifies an error outcome whose remediation differs from a generic failure.
	// Currently only ErrorKindValueTooLarge (#2544); empty for every other line.
	ErrorKind string `json:"error_kind,omitempty"`
}

// ErrorKindValueTooLarge marks an item whose value exceeds the target Keyorix server's
// max_secret_size — fixed by raising that limit or splitting the value, not by retrying.
const ErrorKindValueTooLarge = "value_too_large"

// humanValueTooLarge is the status column shown instead of "error" for that class, so it is
// distinguishable when skimming the human output.
const humanValueTooLarge = "toolarge"

// Writer writes one JSON Line per call to jsonOut (a json.Encoder per line, so each write is
// flushed independently — not buffered into one array written at the end) and a
// human-readable summary line per call to humanOut.
type Writer struct {
	enc      *json.Encoder
	humanOut io.Writer
}

func New(jsonOut, humanOut io.Writer) *Writer {
	return &Writer{enc: json.NewEncoder(jsonOut), humanOut: humanOut}
}

// PlanLine reports one planned (not yet executed) item — used for the default dry-run output.
func (w *Writer) PlanLine(item plan.Item) error {
	l := Line{
		Source:  item.Entry.Path,
		Target:  item.Entry.Name,
		Outcome: string(item.Outcome),
		Reason:  item.Reason,
		DryRun:  true,
	}
	status := l.Outcome
	if item.Outcome == plan.Error {
		l.Error = item.Reason
		l.Reason = ""
		if item.ValueTooLarge {
			l.ErrorKind = ErrorKindValueTooLarge
			status = humanValueTooLarge
		}
	}
	if _, err := fmt.Fprintf(w.humanOut, "%-8s %-40s -> %s%s\n", status, l.Source, l.Target, reasonSuffix(errOrReason(l))); err != nil {
		return err
	}
	return w.enc.Encode(l)
}

// ResultLine reports one executed item's outcome, after Apply.
func (w *Writer) ResultLine(res plan.Result) error {
	l := Line{
		Source:  res.Item.Entry.Path,
		Target:  res.Item.Entry.Name,
		Outcome: string(res.Item.Outcome),
		Ran:     res.Ran,
		Reason:  res.Item.Reason,
	}
	if res.Error != "" {
		l.Error = res.Error
		l.Outcome = string(plan.Error)
	}
	status := string(res.Item.Outcome)
	if res.Error != "" {
		status = "error"
	}
	if res.ValueTooLarge || res.Item.ValueTooLarge {
		l.ErrorKind = ErrorKindValueTooLarge
		status = humanValueTooLarge
	}
	if _, err := fmt.Fprintf(w.humanOut, "%-8s %-40s -> %s%s\n", status, l.Source, l.Target, reasonSuffix(errOrReason(l))); err != nil {
		return err
	}
	return w.enc.Encode(l)
}

func errOrReason(l Line) string {
	if l.Error != "" {
		return l.Error
	}
	return l.Reason
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return fmt.Sprintf(" (%s)", reason)
}

// Summary counts outcomes across a set of plan Items, for the final "N create, M update, ..."
// line.
func Summary(items []plan.Item) map[plan.Outcome]int {
	counts := make(map[plan.Outcome]int)
	for _, item := range items {
		counts[item.Outcome]++
	}
	return counts
}

// ValueTooLargeNotice returns a one-line callout for the end-of-run summary when any item was
// refused at plan time, or rejected at apply time, for exceeding the target's max_secret_size —
// so that class is visible without reading every "error" line (#2544). results may be nil (a
// dry run). Empty when there are none.
func ValueTooLargeNotice(items []plan.Item, results []plan.Result) string {
	n := 0
	for _, item := range items {
		if item.ValueTooLarge {
			n++
		}
	}
	for _, res := range results {
		if res.ValueTooLarge && !res.Item.ValueTooLarge {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d item(s) exceed the target's max_secret_size (error_kind=%s): raise secrets.limits.max_secret_size on the Keyorix server or split the value; every other item was processed normally", n, ErrorKindValueTooLarge)
}
