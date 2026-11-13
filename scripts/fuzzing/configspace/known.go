package configspace

import (
	_ "embed"
	"fmt"
	"maps"
	"strconv"
	"strings"
)

//go:embed known.tsv
var knownTSV string

// Classes a known.tsv row may carry. Anything more serious is triaged privately and is
// never listed in this public file: such a finding stays novel in every run.
var knownClasses = map[string]bool{"HARDENING": true, "DEFECT": true, "EXPECTED-DIFFERENCE": true}

// KnownFinding is one triaged finding of an earlier campaign (known.tsv). A run tags
// a finding with the row's ID when invariant, stage, key AND minimised assignment are
// all equal, and reports it exactly as before; tagging never removes or downgrades a
// finding.
//
// What this does NOT verify: that the triage verdict is right (that is the report's
// job), or that a fix landed. A finding whose minimisation ends on a different
// assignment is not matched and shows up as novel; TestKnownFindingsReproduce, not the
// matching, is what notices a row whose behaviour has changed.
type KnownFinding struct {
	ID, Class, Inv, Stage, Key string
	MinAssign                  map[string]int
	Note                       string
}

// ParseKnown parses known.tsv: id, class, inv, stage, key, min_assign
// (param=index,... or -), note. Blank lines and lines starting with # are skipped.
func ParseKnown(m *Model, text string) ([]KnownFinding, error) {
	var out []KnownFinding
	seen := map[string]bool{}
	n := -1
	for line := range strings.SplitSeq(text, "\n") {
		n++
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		col := strings.Split(line, "\t")
		if len(col) != 7 {
			return nil, fmt.Errorf("known.tsv:%d: %d columns, want 7", n+1, len(col))
		}
		k := KnownFinding{ID: col[0], Class: col[1], Inv: col[2], Stage: col[3], Key: col[4], Note: col[6]}
		switch {
		case seen[k.ID]:
			return nil, fmt.Errorf("known.tsv:%d: duplicate id %s", n+1, k.ID)
		case !strings.HasPrefix(k.ID, "CSK-"):
			return nil, fmt.Errorf("known.tsv:%d: id %q does not start with CSK-", n+1, k.ID)
		case !knownClasses[k.Class]:
			return nil, fmt.Errorf("known.tsv:%d: class %q may not be listed here", n+1, k.Class)
		case k.Stage != "inproc" && k.Stage != "proc":
			return nil, fmt.Errorf("known.tsv:%d: stage %q", n+1, k.Stage)
		case k.Key == "" || k.Note == "":
			return nil, fmt.Errorf("known.tsv:%d: empty key or note", n+1)
		}
		seen[k.ID] = true
		if col[5] != "-" {
			k.MinAssign = map[string]int{}
			for a := range strings.SplitSeq(col[5], ",") {
				id, idx, ok := strings.Cut(a, "=")
				vi, err := strconv.Atoi(idx)
				p := m.Param(id)
				if !ok || err != nil || p == nil || vi < 0 || vi >= len(p.Values) {
					return nil, fmt.Errorf("known.tsv:%d: assignment %q is not a model param=value-index", n+1, a)
				}
				k.MinAssign[id] = vi
			}
		}
		out = append(out, k)
	}
	return out, nil
}

// matchKnown returns the ID of the row u matches, or "".
func matchKnown(known []KnownFinding, u *UniqueFinding) string {
	for _, k := range known {
		if k.Inv == u.Inv && k.Stage == u.Stage && k.Key == u.Key && maps.Equal(k.MinAssign, u.MinAssign) {
			return k.ID
		}
	}
	return ""
}
