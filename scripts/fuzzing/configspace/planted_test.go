package configspace

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type expectation struct {
	ID, Patch, Inv, Stage, Prefix string
	NeedsBin                      bool
}

func loadExpectations(t *testing.T) []expectation {
	t.Helper()
	f, err := os.Open(filepath.Join("planted", "expect.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []expectation
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		c := strings.Split(line, "\t")
		if len(c) != 6 {
			t.Fatalf("bad expect.tsv line %q", line)
		}
		out = append(out, expectation{ID: c[0], Patch: c[1], NeedsBin: c[2] == "1", Inv: c[3], Stage: c[4], Prefix: c[5]})
	}
	return out
}

func TestPlantedExpectationsWellFormed(t *testing.T) {
	for _, e := range loadExpectations(t) {
		if _, err := os.Stat(filepath.Join("planted", e.Patch)); err != nil {
			t.Errorf("%s: %v", e.ID, err)
		}
	}
}

// TestPlanted is driven by planted/selftest.sh. With CONFIGSPACE_PLANTED=<id> it runs the
// campaign on a tree carrying that planted defect and requires the oracle to report it;
// with CONFIGSPACE_PLANTED=control it runs on the unpatched tree and requires that none
// of the planted findings appear.
func TestPlanted(t *testing.T) {
	which := os.Getenv("CONFIGSPACE_PLANTED")
	if which == "" {
		t.Skip("driven by planted/selftest.sh")
	}
	exps := loadExpectations(t)
	var want []expectation
	needBin := which == "control"
	for _, e := range exps {
		if which == "control" || e.ID == which {
			want = append(want, e)
			if e.NeedsBin {
				needBin = true
			}
		}
	}
	if len(want) == 0 {
		t.Fatalf("unknown planted id %q", which)
	}
	tpl, err := LoadTemplate(os.Getenv("CONFIGSPACE_TEMPLATE"))
	if err != nil {
		t.Fatal(err)
	}
	bin := ""
	if needBin {
		bin = os.Getenv("CONFIGSPACE_BIN")
		if bin == "" {
			t.Fatal("CONFIGSPACE_BIN is required for this planted defect")
		}
	}
	out := t.TempDir()
	o := RunOptions{Model: mustModel(t), Template: tpl, Work: t.TempDir(), Out: out, Bin: bin,
		Mutations: 0, ProcMutants: 0, ProcInvalid: 0, Seed: 20261107, Log: t.Logf}
	if _, err := Run(o); err != nil {
		t.Fatal(err)
	}
	var keys []string
	f, err := os.Open(filepath.Join(out, "findings.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var u UniqueFinding
		if err := json.Unmarshal(sc.Bytes(), &u); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, u.Inv+"|"+u.Stage+"|"+u.Key)
	}
	for _, e := range want {
		found := false
		for _, k := range keys {
			if strings.HasPrefix(k, e.Inv+"|"+e.Stage+"|"+e.Prefix) {
				found = true
				break
			}
		}
		if which == "control" && found {
			t.Errorf("control run reported planted defect %s (%s)", e.ID, e.Prefix)
		}
		if which != "control" && !found {
			for _, k := range keys {
				if strings.HasPrefix(k, e.Inv+"|"+e.Stage+"|") && strings.Contains(k, strings.SplitN(e.Prefix, ":", 2)[0]) {
					t.Logf("  near miss: %s", k)
				}
			}
			t.Errorf("planted defect %s (%s %s %s) was not found by the oracle", e.ID, e.Inv, e.Stage, e.Prefix)
		}
		t.Logf("planted %s: found=%v", e.ID, found)
	}
}
