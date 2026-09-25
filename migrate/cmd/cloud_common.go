package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/keyorixhq/keyorix/migrate/internal/cloudentry"
	"github.com/keyorixhq/keyorix/migrate/internal/plan"
	"github.com/keyorixhq/keyorix/migrate/internal/report"
	"github.com/keyorixhq/keyorix/migrate/internal/target"
)

// buildCloudPlanEntries maps a cloud source's entries into plan.Entry the same way
// cmd/vault.go maps vaultsource.Entry: sanitizeSecretName(RawName), or
// sanitizeSecretName(RawName + "-" + Field) when the source exploded a JSON object. Shared by
// cmd/aws.go, cmd/azure.go, and cmd/gcp.go since the mapping is identical for all three cloud
// sources — one function and one collision test, not three near-duplicate copies.
func buildCloudPlanEntries(sourceKind string, entries []cloudentry.Entry, sourceID func(cloudentry.Entry) string) []plan.Entry {
	out := make([]plan.Entry, 0, len(entries))
	for _, e := range entries {
		name := sanitizeSecretName(e.RawName)
		if e.Field != "" {
			name = sanitizeSecretName(e.RawName + "-" + e.Field)
		}
		out = append(out, plan.Entry{
			SourceKind:      sourceKind,
			Path:            e.Locator,
			Name:            name,
			Value:           e.Value,
			Metadata:        e.Metadata,
			SourceID:        sourceID(e),
			SourceVersion:   e.Version,
			SourceCreatedAt: e.CreatedAt,
		})
	}
	return out
}

// splitIntraBatchNameCollisions separates entries whose target Name is claimed by exactly one
// "winner" entry in this run from every other entry reusing that Name. Unlike plan.BuildPlan's
// Conflict (a collision against a PRE-EXISTING Keyorix secret, checked one item at a time
// against the live target), this catches two source items colliding with EACH OTHER within the
// same run, before either has been created — plan.BuildPlan's independent per-item LookupByName
// calls cannot see this: both would read not-found and each plan as Create, and applying both
// would create two secrets under a request for one name (or silently overwrite, depending on the
// target API's own uniqueness behavior). This is a real risk --split-json introduces (two
// distinct provider secrets, or a whole secret and one of its own exploded fields, whose
// sanitized names coincide) and, per the same-review-round Vault fix, a real risk
// sanitizeSecretName's own lossy collapsing introduces there too (e.g. "a/b/c" and "a/b-c" both
// sanitize to "a-b-c") — see cmd/vault.go's own call site.
//
// The winner is chosen deterministically: entries are considered in SourceID order, not the
// order the caller happened to build them in. A source's own List() order (map iteration, an
// API's pagination order, several providers' entries concatenated) is not guaranteed stable
// across runs; if the winner depended on that incidental order, which of two colliding items
// gets created and which gets flagged conflict would be nondeterministic run to run for
// identical input, merely reshuffled. Sorting by SourceID first makes the winner a fixed
// property of the two colliding entries themselves, not of how they arrived. The caller's
// original order is preserved for the RETURNED unique/collided slices (report readability) —
// only the winner decision itself is order-independent.
func splitIntraBatchNameCollisions(entries []plan.Entry) (unique []plan.Entry, collided []plan.Item) {
	sorted := make([]plan.Entry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].SourceID < sorted[j].SourceID })

	winner := make(map[string]plan.Entry, len(sorted))
	for _, e := range sorted {
		if _, seen := winner[e.Name]; !seen {
			winner[e.Name] = e
		}
	}

	for _, e := range entries {
		w := winner[e.Name]
		if e.SourceID == w.SourceID {
			unique = append(unique, e)
			continue
		}
		collided = append(collided, plan.Item{
			Entry:   e,
			Outcome: plan.Conflict,
			Reason: fmt.Sprintf(
				"secret name %q collides between two source items in this same run: %q (source-id %s) and %q (source-id %s) — rename one side",
				e.Name, w.Path, w.SourceID, e.Path, e.SourceID,
			),
		})
	}
	return unique, collided
}

// runCloudPlan is the dry-run/apply/report tail shared by cmd/aws.go, cmd/azure.go, and
// cmd/gcp.go — identical to cmd/vault.go's runVault tail from "print or apply the plan" onward,
// factored out once the three cloud commands needed the exact same sequence: print the plan and
// stop (default), or re-preflight immediately before executing (the plan may have been shown
// minutes earlier) and apply it, always finishing with the outcome summary.
func runCloudPlan(ctx context.Context, tgt *target.Client, keyorixTok string, items []plan.Item, built []plan.Item, apply, force bool, reportPath string) error {
	var reportFile *os.File
	jsonOut := io.Discard
	if reportPath != "" {
		f, err := os.Create(reportPath) // #nosec G304 -- operator-supplied output path, a CLI flag, not user/network input
		if err != nil {
			return fmt.Errorf("create report file: %w", err)
		}
		defer f.Close() //nolint:errcheck
		reportFile = f
		jsonOut = reportFile
	}
	w := report.New(jsonOut, os.Stdout)

	if !apply {
		for _, item := range items {
			if err := w.PlanLine(item); err != nil {
				return fmt.Errorf("write report: %w", err)
			}
		}
		printCloudSummary(items)
		_, _ = fmt.Fprintln(os.Stdout, "\nDry run only — pass --apply to execute this plan.")
		return nil
	}

	// Re-check the token immediately before executing, not just at the top of the run — the
	// dry-run plan may have been shown seconds or minutes earlier (matches cmd/vault.go's own
	// "Pre-flight check" re-check).
	if err := tgt.Preflight(ctx, keyorixTok); err != nil {
		return err
	}

	// items is always constructed as skippedItems ++ collided ++ built, in that exact order
	// (cmd/aws.go, cmd/azure.go, cmd/gcp.go) — the non-built prefix never wrote anything, and
	// results (produced from built, in the same order) fills the rest positionally.
	results := plan.Apply(ctx, tgt, built, force)
	nonBuilt := len(items) - len(built)
	allResults := make([]plan.Result, 0, len(items))
	for i, item := range items {
		if i < nonBuilt {
			allResults = append(allResults, plan.Result{Item: item, Ran: false})
			continue
		}
		allResults = append(allResults, results[i-nonBuilt])
	}
	for _, res := range allResults {
		if err := w.ResultLine(res); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
	}
	printCloudSummary(items)
	return nil
}

func printCloudSummary(items []plan.Item) {
	counts := report.Summary(items)
	_, _ = fmt.Fprintf(os.Stdout, "\n%d create, %d update, %d skip, %d conflict, %d error\n",
		counts[plan.Create], counts[plan.Update], counts[plan.Skip], counts[plan.Conflict], counts[plan.Error])
}
