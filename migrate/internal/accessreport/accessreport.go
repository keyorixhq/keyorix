// Package accessreport writes ADR-114's plan-access report: JSON (machine-readable), Markdown,
// and HTML, mirroring migrate/internal/healthscan's existing three-file convention for `vault
// scan` (docs/adr-114-vault-access-model-migration.md's "Report format"). Never writes a
// credential value or a Vault token — every Item this package renders carries only names,
// scopes, and permissions, never a secret.
package accessreport

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"sort"

	"github.com/keyorixhq/keyorix/migrate/internal/accessplan"
)

// Line is one JSON report entry — a flat, serializable mirror of accessplan.Item.
type Line struct {
	Kind                  string   `json:"kind"`
	Outcome               string   `json:"outcome"`
	SourceRef             string   `json:"source_ref"`
	Category              string   `json:"category,omitempty"`
	Reason                string   `json:"reason,omitempty"`
	ConflictReason        string   `json:"conflict_reason,omitempty"`
	ProposedName          string   `json:"proposed_name,omitempty"`
	ProposedProjectID     int      `json:"proposed_project_id,omitempty"`
	ProposedEnvironmentID int      `json:"proposed_environment_id,omitempty"`
	ProposedPermissions   []string `json:"proposed_permissions,omitempty"`
	ProposedIdentityType  string   `json:"proposed_identity_type,omitempty"`
	ProposedOIDCIssuer    string   `json:"proposed_oidc_issuer,omitempty"`
	ProposedOIDCSubject   string   `json:"proposed_oidc_subject,omitempty"`
	ProposedRoleRef       string   `json:"proposed_role_ref,omitempty"`
	ProposedMachineRef    string   `json:"proposed_machine_ref,omitempty"`
	// ProvenanceKey carries the migrate.source-id apply-access needs to tag a created
	// object's Description with — present in the JSON report (never in Markdown/HTML, which
	// are for human review only) so `apply-access --plan <file>` can read it back.
	ProvenanceKey string `json:"provenance_key,omitempty"`
}

func toLine(it accessplan.Item) Line {
	return Line{
		Kind: string(it.Kind), Outcome: string(it.Outcome), SourceRef: it.SourceRef,
		Category: string(it.Category), Reason: it.Reason, ConflictReason: it.ConflictReason,
		ProposedName: it.ProposedName, ProposedProjectID: it.ProposedProjectID,
		ProposedEnvironmentID: it.ProposedEnvironmentID, ProposedPermissions: it.ProposedPermissions,
		ProposedIdentityType: it.ProposedIdentityType, ProposedOIDCIssuer: it.ProposedOIDCIssuer,
		ProposedOIDCSubject: it.ProposedOIDCSubject, ProposedRoleRef: it.ProposedRoleRef,
		ProposedMachineRef: it.ProposedMachineRef, ProvenanceKey: it.ProvenanceKey,
	}
}

// toItem reconstructs the accessplan.Item fields apply-access needs to execute an item — the
// inverse of toLine, used by ReadJSON. ExistingID and ConflictReason are deliberately NOT
// round-tripped: apply-access always re-derives those fresh via accessplan.Reconcile against
// LIVE Keyorix state (ADR-114: "re-derives and re-checks the plan immediately before executing
// each item... never trusting the file's snapshot").
func (l Line) toItem() accessplan.Item {
	return accessplan.Item{
		Kind: accessplan.ObjectKind(l.Kind), Outcome: accessplan.Outcome(l.Outcome), SourceRef: l.SourceRef,
		Category: accessplan.UnmappableCategory(l.Category), Reason: l.Reason,
		ProposedName: l.ProposedName, ProposedProjectID: l.ProposedProjectID,
		ProposedEnvironmentID: l.ProposedEnvironmentID, ProposedPermissions: l.ProposedPermissions,
		ProposedIdentityType: l.ProposedIdentityType, ProposedOIDCIssuer: l.ProposedOIDCIssuer,
		ProposedOIDCSubject: l.ProposedOIDCSubject, ProposedRoleRef: l.ProposedRoleRef,
		ProposedMachineRef: l.ProposedMachineRef, ProvenanceKey: l.ProvenanceKey,
	}
}

// maxPlanFileBytes bounds how much of a plan-access report ReadJSON will read. The file is
// operator-supplied (a CLI flag, see vaultapplyaccess.go's `#nosec G304` on the os.Open call),
// but json.NewDecoder still fully buffers each decoded value into memory before any validation
// runs -- generous enough for even a very large access plan, while ruling out an accidental or
// corrupted multi-GB file taking down the migration run with an out-of-memory kill.
const maxPlanFileBytes = 256 << 20 // 256MB

// ReadJSON reads a plan-access JSON report (one Line object per line) back into Items, in file
// order — apply-access's starting point before re-deriving and cross-checking against live
// Vault/Keyorix state.
func ReadJSON(r io.Reader) (accessplan.Plan, error) {
	dec := json.NewDecoder(io.LimitReader(r, maxPlanFileBytes))
	var items []accessplan.Item
	for dec.More() {
		var l Line
		if err := dec.Decode(&l); err != nil {
			return accessplan.Plan{}, err
		}
		items = append(items, l.toItem())
	}
	return accessplan.Plan{Items: items}, nil
}

// Summary counts every item by outcome, for the report's header.
type Summary struct {
	Create, Skip, Conflict, Unmappable int
}

func summarize(items []accessplan.Item) Summary {
	var s Summary
	for _, it := range items {
		switch it.Outcome {
		case accessplan.Create:
			s.Create++
		case accessplan.Skip:
			s.Skip++
		case accessplan.Conflict:
			s.Conflict++
		case accessplan.Unmappable:
			s.Unmappable++
		}
	}
	return s
}

// WriteJSON writes one JSON object per line (flushed independently, matching
// migrate/internal/report's existing per-line-flush convention) so a killed-mid-run reader
// still sees a valid prefix.
func WriteJSON(w io.Writer, p accessplan.Plan) error {
	enc := json.NewEncoder(w)
	for _, it := range p.Items {
		if err := enc.Encode(toLine(it)); err != nil {
			return err
		}
	}
	return nil
}

// WriteMarkdown writes a human-readable report, grouped by outcome (Unmappable first — that's
// where a reviewer's attention belongs) then by kind.
func WriteMarkdown(w io.Writer, p accessplan.Plan, vaultAddr string) error {
	s := summarize(p.Items)
	if _, err := fmt.Fprintf(w, "# Vault access-model migration plan\n\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Vault: %s\n\n", vaultAddr); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%d to create, %d already migrated (skip), %d conflicts, %d unmappable (human review).\n\n",
		s.Create, s.Skip, s.Conflict, s.Unmappable); err != nil {
		return err
	}

	for _, outcome := range []accessplan.Outcome{accessplan.Unmappable, accessplan.Conflict, accessplan.Create, accessplan.Skip} {
		group := itemsWithOutcome(p.Items, outcome)
		if len(group) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "## %s (%d)\n\n", outcomeHeading(outcome), len(group)); err != nil {
			return err
		}
		for _, it := range group {
			if err := writeMarkdownItem(w, it); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeMarkdownItem(w io.Writer, it accessplan.Item) error {
	switch it.Outcome {
	case accessplan.Unmappable:
		_, err := fmt.Fprintf(w, "- **%s** [%s] %s — %s\n", it.SourceRef, it.Category, it.Kind, it.Reason)
		return err
	case accessplan.Conflict:
		_, err := fmt.Fprintf(w, "- **%s** %s %q — %s\n", it.SourceRef, it.Kind, it.ProposedName, it.ConflictReason)
		return err
	case accessplan.Create:
		return writeCreateItem(w, it)
	default: // Skip
		_, err := fmt.Fprintf(w, "- **%s** %s %q — already migrated\n", it.SourceRef, it.Kind, proposedLabel(it))
		return err
	}
}

func writeCreateItem(w io.Writer, it accessplan.Item) error {
	switch it.Kind {
	case accessplan.KindRole:
		_, err := fmt.Fprintf(w, "- **%s** role %q — grants %v at project %d, environment %s\n",
			it.SourceRef, it.ProposedName, it.ProposedPermissions, it.ProposedProjectID, environmentLabel(it.ProposedEnvironmentID))
		return err
	case accessplan.KindMachineIdentity:
		_, err := fmt.Fprintf(w, "- **%s** machine identity %q (%s)\n", it.SourceRef, it.ProposedName, it.ProposedIdentityType)
		return err
	case accessplan.KindMachineRoleGrant:
		_, err := fmt.Fprintf(w, "- **%s** grant role %q to machine %q\n", it.SourceRef, it.ProposedRoleRef, it.ProposedMachineRef)
		return err
	case accessplan.KindOIDCBinding:
		_, err := fmt.Fprintf(w, "- **%s** bind machine %q to issuer %q subject %q\n", it.SourceRef, it.ProposedMachineRef, it.ProposedOIDCIssuer, it.ProposedOIDCSubject)
		return err
	default:
		_, err := fmt.Fprintf(w, "- **%s** %s %q\n", it.SourceRef, it.Kind, it.ProposedName)
		return err
	}
}

func proposedLabel(it accessplan.Item) string {
	if it.ProposedName != "" {
		return it.ProposedName
	}
	if it.ProposedRoleRef != "" {
		return it.ProposedMachineRef + " -> " + it.ProposedRoleRef
	}
	return it.ProposedOIDCSubject
}

// environmentLabel renders ADR-114's env=0 sentinel as "global" rather than the bare integer —
// the report's one place a reader could otherwise mistake 0 for "environment id zero" instead
// of "every environment in this project."
func environmentLabel(id int) string {
	if id == 0 {
		return "global (every environment)"
	}
	return fmt.Sprint(id)
}

func outcomeHeading(o accessplan.Outcome) string {
	switch o {
	case accessplan.Unmappable:
		return "Needs human review (unmappable)"
	case accessplan.Conflict:
		return "Conflicts"
	case accessplan.Create:
		return "Proposed (will be created by apply-access)"
	default:
		return "Already migrated (skip)"
	}
}

func itemsWithOutcome(items []accessplan.Item, outcome accessplan.Outcome) []accessplan.Item {
	var out []accessplan.Item
	for _, it := range items {
		if it.Outcome == outcome {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SourceRef < out[j].SourceRef })
	return out
}

// WriteHTML writes a single-file HTML report — inline CSS, no external assets, matching
// healthscan's own WriteHTML convention for `vault scan`.
func WriteHTML(w io.Writer, p accessplan.Plan, vaultAddr string) error {
	s := summarize(p.Items)
	if _, err := fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>Vault access-model migration plan</title>
<style>
body{font-family:-apple-system,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.4rem} h2{font-size:1.1rem;margin-top:2rem;border-bottom:1px solid #ddd;padding-bottom:.25rem}
.unmappable{color:#92400e} .conflict{color:#991b1b} .create{color:#065f46} .skip{color:#555}
code{background:#f4f4f4;padding:0 .25rem;border-radius:3px}
li{margin:.4rem 0}
</style></head><body>
<h1>Vault access-model migration plan</h1>
<p>Vault: <code>%s</code></p>
<p>%d to create, %d already migrated (skip), %d conflicts, %d unmappable (human review).</p>
`, html.EscapeString(vaultAddr), s.Create, s.Skip, s.Conflict, s.Unmappable); err != nil {
		return err
	}

	for _, outcome := range []accessplan.Outcome{accessplan.Unmappable, accessplan.Conflict, accessplan.Create, accessplan.Skip} {
		group := itemsWithOutcome(p.Items, outcome)
		if len(group) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "<h2 class=%q>%s (%d)</h2><ul>\n", string(outcome), html.EscapeString(outcomeHeading(outcome)), len(group)); err != nil {
			return err
		}
		for _, it := range group {
			if err := writeHTMLItem(w, it); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(w, "</ul>\n"); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, "</body></html>\n")
	return err
}

func writeHTMLItem(w io.Writer, it accessplan.Item) error {
	_, err := fmt.Fprintf(w, "<li><code>%s</code> %s</li>\n", html.EscapeString(it.SourceRef), html.EscapeString(htmlItemBody(it)))
	return err
}

func htmlItemBody(it accessplan.Item) string {
	switch it.Outcome {
	case accessplan.Unmappable:
		return fmt.Sprintf("[%s] %s — %s", it.Category, it.Kind, it.Reason)
	case accessplan.Conflict:
		return fmt.Sprintf("%s %q — %s", it.Kind, it.ProposedName, it.ConflictReason)
	case accessplan.Skip:
		return fmt.Sprintf("%s %q — already migrated", it.Kind, proposedLabel(it))
	default:
		return fmt.Sprintf("%s %q", it.Kind, proposedLabel(it))
	}
}
