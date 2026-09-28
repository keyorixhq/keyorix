package healthscan

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
)

// Report is the result of one scan run. This is G1's skeleton shape — enough for `vault scan`
// to run end to end and emit well-formed output in all three formats with zero checks
// registered. G3 (docs/vault-health-scan.md's report spec: executive summary, score formula,
// per-check detail sections, "Migration readiness") extends this type and its writers; nothing
// here is meant to be the final report shape.
type Report struct {
	GeneratedBy string       `json:"generated_by"`
	VaultAddr   string       `json:"vault_addr"`
	Findings    []Finding    `json:"findings"`
	NotChecked  []NotChecked `json:"not_checked"`
}

// SchemaVersion is the JSON report's own schema version (docs/vault-health-scan.md's "versioned
// schema" requirement) — bumped whenever a field is added, renamed, or removed, so a consumer of
// the JSON output (the "share the JSON with us" flow, G3/G6) can tell which shape it's reading.
const SchemaVersion = 1

// jsonReport is the on-the-wire shape written by WriteJSON — SchemaVersion is a field on the
// envelope, not on Report itself, so Report's Go shape can evolve without every caller of Run
// needing to thread a schema version through.
type jsonReport struct {
	SchemaVersion int `json:"schema_version"`
	Report
}

// WriteJSON writes r as the versioned JSON report schema.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{SchemaVersion: SchemaVersion, Report: *r})
}

// WriteMarkdown writes r as a Markdown report. G1 skeleton: findings + not-checked, unordered by
// severity — G3 adds the executive summary, score, and top-5-risks ordering.
func WriteMarkdown(w io.Writer, r *Report) error {
	if _, err := fmt.Fprintf(w, "# Vault Health Scan\n\n%s against `%s`\n\n", r.GeneratedBy, r.VaultAddr); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "## Findings\n\n"); err != nil {
		return err
	}
	if len(r.Findings) == 0 {
		if _, err := fmt.Fprintf(w, "_No checks have been registered yet._\n\n"); err != nil {
			return err
		}
	}
	for _, f := range r.Findings {
		if _, err := fmt.Fprintf(w, "### [%s] %s (%s)\n\n- **Evidence:** %s\n- **Why it matters:** %s\n- **Remediation:** %s\n\n",
			f.ID, f.Title, f.Severity, f.Evidence, f.WhyItMatters, emptyDash(f.Remediation)); err != nil {
			return err
		}
	}
	if len(r.NotChecked) > 0 {
		if _, err := fmt.Fprintf(w, "## Not checked\n\n"); err != nil {
			return err
		}
		for _, nc := range r.NotChecked {
			if _, err := fmt.Fprintf(w, "- **%s**: %s%s\n", nc.ID, nc.Reason, policyLineSuffix(nc.PolicyLine)); err != nil {
				return err
			}
		}
	}
	return nil
}

// WriteHTML writes r as a single-file HTML report (inline CSS, no external assets). G1
// skeleton: G3 adds the full structure (executive summary, score, per-check detail, Migration
// readiness, footer). Every dynamic value is HTML-escaped — a Vault error message or path
// reflected into evidence/reason text must never be interpreted as markup.
func WriteHTML(w io.Writer, r *Report) error {
	if _, err := fmt.Fprintf(w, "<!doctype html><html><head><meta charset=\"utf-8\"><title>Vault Health Scan</title>"+
		"<style>body{font-family:sans-serif;max-width:60rem;margin:2rem auto;line-height:1.5}"+
		"h3{margin-bottom:.25rem}.sev-critical{color:#b00}.sev-high{color:#c60}.sev-medium{color:#996800}"+
		".sev-low{color:#555}.sev-info{color:#555}code{background:#f2f2f2;padding:.1rem .3rem}</style></head><body>\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "<h1>Vault Health Scan</h1><p>%s against <code>%s</code></p>\n",
		html.EscapeString(r.GeneratedBy), html.EscapeString(r.VaultAddr)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "<h2>Findings</h2>\n"); err != nil {
		return err
	}
	if len(r.Findings) == 0 {
		if _, err := fmt.Fprintf(w, "<p><em>No checks have been registered yet.</em></p>\n"); err != nil {
			return err
		}
	}
	for _, f := range r.Findings {
		if _, err := fmt.Fprintf(w, "<h3 class=\"sev-%s\">[%s] %s (%s)</h3><ul>"+
			"<li><strong>Evidence:</strong> %s</li>"+
			"<li><strong>Why it matters:</strong> %s</li>"+
			"<li><strong>Remediation:</strong> %s</li></ul>\n",
			html.EscapeString(string(f.Severity)), html.EscapeString(f.ID), html.EscapeString(f.Title), html.EscapeString(string(f.Severity)),
			html.EscapeString(f.Evidence), html.EscapeString(f.WhyItMatters), html.EscapeString(emptyDash(f.Remediation))); err != nil {
			return err
		}
	}
	if len(r.NotChecked) > 0 {
		if _, err := fmt.Fprintf(w, "<h2>Not checked</h2><ul>\n"); err != nil {
			return err
		}
		for _, nc := range r.NotChecked {
			if _, err := fmt.Fprintf(w, "<li><strong>%s</strong>: %s%s</li>\n",
				html.EscapeString(nc.ID), html.EscapeString(nc.Reason), html.EscapeString(policyLineSuffix(nc.PolicyLine))); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "</ul>\n"); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "</body></html>\n"); err != nil {
		return err
	}
	return nil
}

func emptyDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func policyLineSuffix(policyLine string) string {
	if policyLine == "" {
		return ""
	}
	return fmt.Sprintf(" (enable with: %s)", policyLine)
}
