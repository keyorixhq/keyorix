package docsdrift

import (
	"strconv"
	"strings"
	"testing"
)

// pgsslmodeClaim is the one sentence that says what PGSSLMODE does to the
// default sslmode (internal/config/database_tls.go resolveDatabaseTLS: a dsn
// with no sslmode takes PGSSLMODE, else pgx's "prefer").
const pgsslmodeClaim = "`PGSSLMODE` overrides the `prefer` default"

// pgsslmodeDocProblems checks that doc states the PGSSLMODE-vs-prefer claim
// exactly once, inside the "### PostgreSQL TLS" section, and that no other
// prose line (fenced examples are not read) names both PGSSLMODE and `prefer`,
// which would be a second, driftable statement of the same rule.
func pgsslmodeDocProblems(doc string) []string {
	var problems []string
	if n := strings.Count(doc, pgsslmodeClaim); n != 1 {
		problems = append(problems, "the claim "+pgsslmodeClaim+" appears "+strconv.Itoa(n)+" times, want exactly 1")
	}
	_, rest, ok := strings.Cut(doc, "\n### PostgreSQL TLS\n")
	if !ok {
		return append(problems, "section '### PostgreSQL TLS' not found")
	}
	section, _, _ := strings.Cut(rest, "\n### ")
	if !strings.Contains(section, pgsslmodeClaim) {
		problems = append(problems, "the claim is not inside the '### PostgreSQL TLS' section")
	}
	inFence := false
	for line := range strings.SplitSeq(doc, "\n") {
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			continue
		}
		if inFence || strings.Contains(line, pgsslmodeClaim) {
			continue
		}
		if strings.Contains(line, "PGSSLMODE") && strings.Contains(line, "`prefer`") {
			problems = append(problems, "second statement of the PGSSLMODE/prefer rule: "+strings.TrimSpace(line))
		}
	}
	return problems
}

// TestConfigurationDoc_PGSSLMODERuleStatedOnce keeps the rule in one place, in
// the PostgreSQL TLS section, so a code change has one sentence to update.
func TestConfigurationDoc_PGSSLMODERuleStatedOnce(t *testing.T) {
	for _, p := range pgsslmodeDocProblems(readDoc(t, "docs/CONFIGURATION.md")) {
		t.Error("docs/CONFIGURATION.md: " + p)
	}
}

func TestConfigurationDocPGSSLMODECheckCatchesPlantedError(t *testing.T) {
	good := "intro\n\n### PostgreSQL TLS\n\nx. **" + pgsslmodeClaim + ", and nothing else.**\n\n```\n# no PGSSLMODE: `prefer`\n```\n\n### Next\n"
	if p := pgsslmodeDocProblems(good); len(p) != 0 {
		t.Fatalf("clean doc flagged: %v", p)
	}
	dup := strings.Replace(good, "intro", "the dsn has none, `PGSSLMODE`; otherwise `prefer`.", 1)
	if p := pgsslmodeDocProblems(dup); len(p) != 1 {
		t.Fatalf("a second prose statement must be flagged once, got %v", p)
	}
	if p := pgsslmodeDocProblems(strings.Replace(good, pgsslmodeClaim, "x", 1)); len(p) == 0 {
		t.Fatal("a missing claim must be flagged")
	}
	moved := strings.Replace(good, "### Next", "### Next\n"+pgsslmodeClaim, 1)
	moved = strings.Replace(moved, pgsslmodeClaim+", and nothing else.", "gone", 1)
	if p := pgsslmodeDocProblems(moved); len(p) == 0 {
		t.Fatal("a claim outside the TLS section must be flagged")
	}
}
