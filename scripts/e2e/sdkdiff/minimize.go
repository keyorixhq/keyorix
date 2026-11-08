package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// reproduces runs sc alone on fresh servers and reports whether a finding with signature sig appears.
func reproduces(r *Runner, sc Scenario, sig string) (bool, error) {
	res, err := r.RunBatch([]Scenario{sc})
	if err != nil {
		return false, err
	}
	outs := map[string]Outcome{}
	for n, l := range res {
		if len(l) > 0 {
			outs[n] = l[0]
		}
	}
	fs, _ := r.Analyse(sc, outs)
	for _, f := range fs {
		if f.Sig() == sig {
			return true, nil
		}
	}
	return false, nil
}

func cloneSC(sc Scenario) Scenario {
	b, _ := json.Marshal(sc)
	var o Scenario
	_ = json.Unmarshal(b, &o)
	return o
}

// dropStep removes step k and repairs references.
func dropStep(sc Scenario, k int) Scenario {
	o := cloneSC(sc)
	o.Steps = append(o.Steps[:k], o.Steps[k+1:]...)
	for i := range o.Steps {
		for j := range o.Steps[i].Args {
			a := &o.Steps[i].Args[j]
			if a.Ref == nil {
				continue
			}
			switch {
			case a.Ref.Step == k:
				*a = S("0")
			case a.Ref.Step > k:
				a.Ref.Step--
			}
		}
	}
	return o
}

// minimize greedily shrinks sc (steps, modifiers, then argument contents) while sig keeps reproducing.
func minimize(r *Runner, sc Scenario, sig string, budget int) (Scenario, int, error) {
	tests := 0
	try := func(c Scenario) bool {
		if tests >= budget {
			return false
		}
		tests++
		ok, err := reproduces(r, c, sig)
		return err == nil && ok
	}
	cur := cloneSC(sc)
	for changed := true; changed; {
		changed = false
		for k := len(cur.Steps) - 1; k >= 0 && len(cur.Steps) > 1; k-- {
			if c := dropStep(cur, k); try(c) {
				cur, changed = c, true
			}
		}
		for i := range cur.Steps {
			for _, mod := range []func(*Step){
				func(s *Step) { s.Fault = nil }, func(s *Step) { s.Token = "" }, func(s *Step) { s.Base = "" }, func(s *Step) { s.TimeoutMs = 0 }} {
				c := cloneSC(cur)
				before, _ := json.Marshal(c.Steps[i])
				mod(&c.Steps[i])
				after, _ := json.Marshal(c.Steps[i])
				if string(before) != string(after) && try(c) {
					cur, changed = c, true
				}
			}
			for j := range cur.Steps[i].Args {
				a := cur.Steps[i].Args[j]
				if a.Null || a.Ref != nil || a.Str == "" {
					continue
				}
				for _, cand := range shrinkCandidates(a.Str) {
					c := cloneSC(cur)
					c.Steps[i].Args[j] = S(cand)
					if try(c) {
						cur, changed = c, true
						break
					}
				}
			}
		}
	}
	return cur, tests, nil
}

func shrinkCandidates(s string) []string {
	rs := []rune(s)
	out := []string{""}
	if len(rs) > 1 {
		out = append(out, string(rs[:len(rs)/2]), string(rs[len(rs)/2:]))
	}
	if len(rs) <= 48 {
		for i := range rs {
			out = append(out, string(rs[:i])+string(rs[i+1:]))
		}
	}
	return out
}

func loadScenarioFile(path string) (Scenario, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator path
	if err != nil {
		return Scenario{}, err
	}
	var sc Scenario
	return sc, json.Unmarshal(b, &sc)
}

func cmdReplay(args []string) error {
	var c common
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	c.flags(fs)
	in := fs.String("in", "", "scenario json file")
	sig := fs.String("sig", "", "signature that must reproduce")
	n := fs.Int("n", 3, "replays")
	_ = fs.Parse(args)
	sc, err := loadScenarioFile(*in)
	if err != nil {
		return err
	}
	r, err := c.runner()
	if err != nil {
		return err
	}
	defer r.Close()
	hits := 0
	for i := 0; i < *n; i++ {
		ok, err := reproduces(r, sc, *sig)
		if err != nil {
			return err
		}
		fmt.Printf("replay %d/%d reproduced=%v\n", i+1, *n, ok)
		if ok {
			hits++
		}
	}
	fmt.Printf("RESULT %d/%d\n", hits, *n)
	if hits < *n {
		os.Exit(3)
	}
	return nil
}

func cmdMinimize(args []string) error {
	var c common
	fs := flag.NewFlagSet("minimize", flag.ExitOnError)
	c.flags(fs)
	in := fs.String("report", "", "report.json from run")
	only := fs.String("sig", "", "only signatures containing this text (default: all)")
	budget := fs.Int("budget", 120, "max reproduction tests per signature")
	replays := fs.Int("replays", 3, "replays of the minimised scenario")
	_ = fs.Parse(args)
	raw, err := os.ReadFile(*in) // #nosec G304 -- operator path
	if err != nil {
		return err
	}
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return err
	}
	r, err := c.runner()
	if err != nil {
		return err
	}
	defer r.Close()
	if err := os.MkdirAll(c.out, 0o750); err != nil {
		return err
	}
	type row struct {
		Sig      string   `json:"sig"`
		Min      Scenario `json:"min"`
		Tests    int      `json:"tests"`
		Replayed int      `json:"replayed_ok"`
		Of       int      `json:"of"`
	}
	var rows []row
	for sig, st := range rep.Sigs {
		if *only != "" && !strings.Contains(sig, *only) {
			continue
		}
		if st.Smallest == nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "minimising %s (from %s)\n", sig, st.Smallest.ID)
		if ok, _ := reproduces(r, *st.Smallest, sig); !ok {
			rows = append(rows, row{Sig: sig, Min: *st.Smallest, Of: 0})
			fmt.Fprintf(os.Stderr, "  does not reproduce alone: state-coupled / non-deterministic\n")
			continue
		}
		m, tests, err := minimize(r, *st.Smallest, sig, *budget)
		if err != nil {
			return err
		}
		ok := 0
		for i := 0; i < *replays; i++ {
			if y, _ := reproduces(r, m, sig); y {
				ok++
			}
		}
		rows = append(rows, row{Sig: sig, Min: m, Tests: tests, Replayed: ok, Of: *replays})
		fmt.Fprintf(os.Stderr, "  -> %d steps, replay %d/%d\n", len(m.Steps), ok, *replays)
	}
	b, _ := json.MarshalIndent(rows, "", " ")
	return os.WriteFile(filepath.Join(c.out, "minimised.json"), b, 0o600) // #nosec G306,G703 -- operator path
}

var plantExpect = map[string]struct{ Cat, SDK string }{
	"P1": {"W2", "python"}, "P1b": {"R2", "python"}, "P2": {"W2", "node"}, "P3": {"E1", "go"}, "P4": {"W1", "python"},
	"P5": {"W3", "node"}, "P6": {"W2", "java"}, "P6b": {"R2", "java"}, "P7": {"W4", "python"},
}

// baselineProblem says why a baseline report cannot stand in for the unplanted run over these SDKs and
// scenarios, or "" when it can. A signature counts as new when the baseline lacks it, so a baseline that
// compared less than this run (a failed batch, a silent SDK) would credit a plant with old signatures.
func baselineProblem(base *Report, sdks []string, scenarios int) string {
	if np := base.notRun(); len(np) > 0 {
		return "it did not compare everything: " + strings.Join(np, "; ")
	}
	if !slices.Equal(base.SDKs, sdks) {
		return fmt.Sprintf("it ran SDKs %v, this run has %v", base.SDKs, sdks)
	}
	if base.Scenarios != scenarios {
		return fmt.Sprintf("it ran %d scenarios, this run has %d", base.Scenarios, scenarios)
	}
	return ""
}

func cmdValidate(args []string) error {
	var c common
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	c.flags(fs)
	in := fs.String("in", "", "validation scenarios jsonl")
	baseline := fs.String("baseline", "", "report.json of the unplanted run over the same scenarios and SDKs")
	plants := fs.String("plants", "", "comma list of plants to check (P1..P7)")
	controls := fs.Bool("controls", false, "run the self-pair control (SDK list should contain kind@2 twins)")
	batch := fs.Int("batch", 25, "scenarios per server lifetime")
	_ = fs.Parse(args)
	scs, err := readJSONL(*in)
	if err != nil {
		return err
	}
	var results []string
	failed := false // a missed plant, a failed control or a run that did not execute
	if *controls {
		rep := newReport(&c)
		if err := runScenarios(&c, scs, *batch, rep, true); err != nil {
			return err
		}
		_ = rep.save(filepath.Join(c.out, "control-selfpair"))
		line, ok := controlC1(rep)
		results = append(results, line)
		if !ok {
			failed = true
		}
	}
	if *plants != "" {
		raw, err := os.ReadFile(*baseline) // #nosec G304 -- operator path
		if err != nil {
			return err
		}
		var base Report
		if err := json.Unmarshal(raw, &base); err != nil {
			return err
		}
		for p := range strings.SplitSeq(*plants, ",") {
			exp, ok := plantExpect[p]
			if !ok {
				return fmt.Errorf("unknown plant %s", p)
			}
			pc := c
			pc.plant = p
			rep := newReport(&pc)
			if err := runScenarios(&pc, scs, *batch, rep, true); err != nil {
				return err
			}
			_ = rep.save(filepath.Join(c.out, "plant-"+p))
			if np := rep.notRun(); len(np) > 0 {
				results = append(results, fmt.Sprintf("PLANT %s NOT RUN: %s", p, strings.Join(np, "; ")))
				failed = true
				continue
			}
			hit := ""
			for sig, st := range rep.Sigs {
				if _, inBase := base.Sigs[sig]; inBase || st.First.Cat != exp.Cat {
					continue
				}
				if plantedIsOddOneOut(st.First.Blocks, exp.SDK) {
					hit = sig
				}
			}
			if hit != "" {
				results = append(results, fmt.Sprintf("PLANT %s DETECTED as new signature %s", p, hit))
			} else {
				results = append(results, fmt.Sprintf("PLANT %s MISSED (expected %s involving %s)", p, exp.Cat, exp.SDK))
				failed = true
			}
		}
	}
	b, _ := json.MarshalIndent(results, "", " ")
	_ = os.MkdirAll(c.out, 0o750)
	_ = os.WriteFile(filepath.Join(c.out, "validation.json"), b, 0o600) // #nosec G306,G703 -- operator path
	for _, l := range results {
		fmt.Println(l)
	}
	if failed {
		return fmt.Errorf("validation failed (see lines above)")
	}
	return nil
}

// plantedIsOddOneOut reports whether the planted SDK kind sits in a minority block of the partition
// (PREREGISTRATION section 6: the odd-one-out block must contain it). Being in some block is not
// enough: every SDK that ran is in one.
func plantedIsOddOneOut(blocks [][]string, kind string) bool {
	if len(blocks) < 2 {
		return false
	}
	total := 0
	for _, b := range blocks {
		total += len(b)
	}
	for _, b := range blocks {
		for _, n := range b {
			if kindOf(n) == kind && 2*len(b) < total {
				return true
			}
		}
	}
	return false
}

// twinsSplit reports whether any SDK and its kind@N twin sit in different blocks of one finding.
func twinsSplit(blocks [][]string) bool {
	where := map[string]int{}
	for i, b := range blocks {
		for _, n := range b {
			where[n] = i
		}
	}
	for n, i := range where {
		if strings.Contains(n, "@") {
			if j, ok := where[kindOf(n)]; ok && j != i {
				return true
			}
		}
	}
	return false
}
