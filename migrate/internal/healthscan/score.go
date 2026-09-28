package healthscan

import "sort"

// severityWeight is the point deduction per finding severity — the whole of Score's formula.
// Stated here and echoed verbatim in every report (ScoreFormula) so a reader never has to trust
// the number without seeing exactly how it was derived (SESSION-G3: "score 0–100 with the
// formula stated").
var severityWeight = map[Severity]int{
	SeverityCritical: 25,
	SeverityHigh:     15,
	SeverityMedium:   8,
	SeverityLow:      3,
	SeverityInfo:     0,
}

// ScoreFormula is the exact prose this package's Score function implements — kept as a single
// source of truth so the report text and the arithmetic can never drift apart.
const ScoreFormula = "Score = 100 - (25 x critical findings + 15 x high + 8 x medium + 3 x low), floored at 0. Info-severity findings and \"migration-readiness\" (an inventory fact, not a risk) don't affect the score."

// Score computes the 0-100 executive-summary score from findings' severities.
// "migration-readiness" is excluded deliberately — it's an inventory fact about what
// keyorix-migrate can import, not a risk assessment about this Vault.
func Score(findings []Finding) int {
	total := 100
	for _, f := range findings {
		if f.ID == "migration-readiness" {
			continue
		}
		total -= severityWeight[f.Severity]
	}
	if total < 0 {
		return 0
	}
	return total
}

var severityRank = map[Severity]int{
	SeverityCritical: 4,
	SeverityHigh:     3,
	SeverityMedium:   2,
	SeverityLow:      1,
	SeverityInfo:     0,
}

// TopRisks returns up to n findings with actual risk weight (severity above info, excluding the
// migration-readiness inventory fact), ranked most-severe first. Ties break on ID for a
// deterministic, reproducible ordering across runs against the same Vault state.
func TopRisks(findings []Finding, n int) []Finding {
	var risky []Finding
	for _, f := range findings {
		if f.ID == "migration-readiness" || f.Severity == SeverityInfo {
			continue
		}
		risky = append(risky, f)
	}
	sort.SliceStable(risky, func(i, j int) bool {
		if severityRank[risky[i].Severity] != severityRank[risky[j].Severity] {
			return severityRank[risky[i].Severity] > severityRank[risky[j].Severity]
		}
		return risky[i].ID < risky[j].ID
	})
	if len(risky) > n {
		risky = risky[:n]
	}
	return risky
}
