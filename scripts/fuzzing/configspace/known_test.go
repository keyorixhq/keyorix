package configspace

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestKnownTableParses checks the embedded known.tsv, and that the parser refuses the
// rows it must refuse (a class that may not be public, a duplicate id, an assignment
// that is not a model value).
func TestKnownTableParses(t *testing.T) {
	m := mustModel(t)
	known, err := ParseKnown(m, knownTSV)
	if err != nil {
		t.Fatal(err)
	}
	if len(known) == 0 {
		t.Fatal("known.tsv has no rows")
	}
	row := "CSK-900\tHARDENING\tI2\tinproc\tinvalid-accepted:x\tbreakglass.role=2\tnote"
	if _, err := ParseKnown(m, row); err != nil {
		t.Fatalf("well-formed row refused: %v", err)
	}
	for name, bad := range map[string]string{
		"private class":   strings.Replace(row, "HARDENING", "SECURITY-DEFECT", 1),
		"vulnerability":   strings.Replace(row, "HARDENING", "VULNERABILITY", 1),
		"artifact":        strings.Replace(row, "HARDENING", "ARTIFACT", 1),
		"duplicate id":    row + "\n" + row,
		"unknown param":   strings.Replace(row, "breakglass.role=2", "nope=0", 1),
		"index too large": strings.Replace(row, "breakglass.role=2", "breakglass.role=99", 1),
		"bad stage":       strings.Replace(row, "inproc", "static", 1),
		"short row":       "CSK-901\tHARDENING\tI2",
	} {
		if _, err := ParseKnown(m, bad); err == nil {
			t.Errorf("%s: row accepted", name)
		}
	}
}

// TestFinishTagsKnownAndKeepsNovel checks that finish tags a finding matching a row,
// still writes and counts every finding, treats a finding whose minimised assignment
// differs from the row as novel, and lists the row nothing matched as unseen.
func TestFinishTagsKnownAndKeepsNovel(t *testing.T) {
	out := t.TempDir()
	r := &runState{
		o: RunOptions{Model: mustModel(t), Out: out, Work: t.TempDir(), Known: []KnownFinding{
			{ID: "CSK-T1", Class: "HARDENING", Inv: "I2", Stage: "inproc", Key: "k-known"},
			{ID: "CSK-T2", Class: "HARDENING", Inv: "I2", Stage: "inproc", Key: "k-other-min", MinAssign: map[string]int{"breakglass.role": 1}},
		}},
		cases: map[string]*Case{}, procOut: map[string]string{},
	}
	r.sum.Findings = map[string]int{}
	r.findings = []Finding{
		{Inv: "I2", Sev: "S2", Stage: "inproc", Case: "c1", Key: "k-known"},
		{Inv: "I2", Sev: "S2", Stage: "inproc", Case: "c2", Key: "k-novel"},
		{Inv: "I2", Sev: "S2", Stage: "inproc", Case: "c3", Key: "k-other-min"},
	}
	sum, err := r.finish()
	if err != nil {
		t.Fatal(err)
	}
	if sum.Unique != 3 || sum.Known != 1 || sum.Novel != 2 || sum.Findings["I2/S2"] != 3 {
		t.Fatalf("summary unique=%d known=%d novel=%d I2/S2=%d, want 3 1 2 3", sum.Unique, sum.Known, sum.Novel, sum.Findings["I2/S2"])
	}
	if !slices.Equal(sum.KnownUnseen, []string{"CSK-T2"}) {
		t.Fatalf("unseen = %v, want [CSK-T2]", sum.KnownUnseen)
	}
	got := map[string]string{}
	for _, u := range readFindings(t, filepath.Join(out, "findings.jsonl")) {
		got[u.Key] = u.Known
	}
	want := map[string]string{"k-known": "CSK-T1", "k-novel": "", "k-other-min": ""}
	for k, id := range want {
		if g, ok := got[k]; !ok || g != id {
			t.Errorf("findings.jsonl %s: present=%v known=%q, want known=%q", k, ok, g, id)
		}
	}
}

func readFindings(t *testing.T, path string) []UniqueFinding {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []UniqueFinding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var u UniqueFinding
		if err := json.Unmarshal(sc.Bytes(), &u); err != nil {
			t.Fatal(err)
		}
		out = append(out, u)
	}
	return out
}

// TestKnownFindingsReproduce replays every known.tsv row once and fails for each row
// that no longer produces its finding: the behaviour changed (a fix landed, or the
// harness moved), so the row must be re-triaged or removed. Process-stage rows need
// CONFIGSPACE_BIN; every row needs CONFIGSPACE_TEMPLATE (a baseline made by TestMatrix).
// Skipped without them, so it runs only next to a campaign, not in plain go test.
//
// What it does NOT verify: that a row's classification is still right while it
// reproduces, or anything about findings that are not in known.tsv.
func TestKnownFindingsReproduce(t *testing.T) {
	tplDir := os.Getenv("CONFIGSPACE_TEMPLATE")
	if tplDir == "" {
		t.Skip("set CONFIGSPACE_TEMPLATE (and CONFIGSPACE_BIN for process rows) to replay known.tsv")
	}
	bin := os.Getenv("CONFIGSPACE_BIN")
	tpl, err := LoadTemplate(tplDir)
	if err != nil {
		t.Fatal(err)
	}
	m := mustModel(t)
	known, err := ParseKnown(m, knownTSV)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	var aliasFs []Finding
	aliasRan := false
	for _, k := range known {
		var fs []Finding
		switch {
		case strings.HasPrefix(k.Key, "alias-"):
			if !aliasRan {
				aliasRan = true
				res := map[string]InProcResult{}
				for _, ac := range AliasCases() {
					if err := ac.Materialize(m, tpl, work, true); err != nil {
						t.Fatal(err)
					}
					res[ac.ID] = RunInProc(m, ac)
					_ = os.RemoveAll(ac.Dir)
				}
				aliasFs = CheckAliases(res)
			}
			fs = aliasFs
		case k.Stage == "proc":
			if bin == "" {
				t.Logf("%s: process row skipped (no CONFIGSPACE_BIN)", k.ID)
				continue
			}
			c := &Case{ID: "known-" + k.ID, Kind: "solo", Assign: k.MinAssign}
			if err := c.Materialize(m, tpl, work, false); err != nil {
				t.Fatal(err)
			}
			ip := RunInProc(m, c)
			httpOn, grpcOn := enabledFlags(c, ip)
			fs = CheckProc(m, c, ip, RunProc(bin, c, httpOn, grpcOn, 30*time.Second, 15*time.Second))
			_ = os.RemoveAll(c.Dir)
		default:
			c := &Case{ID: "known-" + k.ID, Kind: "solo", Assign: k.MinAssign}
			if err := c.Materialize(m, tpl, work, true); err != nil {
				t.Fatal(err)
			}
			res := RunInProc(m, c)
			fs = CheckInProc(m, c, res)
			_ = os.RemoveAll(c.Dir)
		}
		if !slices.ContainsFunc(fs, func(f Finding) bool { return f.Inv == k.Inv && f.Key == k.Key }) {
			t.Errorf("%s (%s) no longer reproduces: re-triage it, and remove the row if it was fixed", k.ID, k.Key)
		}
	}
}
