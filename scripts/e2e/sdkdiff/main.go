package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type common struct {
	server, snapshot, work, root, build, sdksDir, spec, sdks, plant, out string
	par                                                                  int
	shim                                                                 bool
}

func (c *common) flags(fs *flag.FlagSet) {
	fs.StringVar(&c.server, "server", "", "keyorix-server binary")
	fs.StringVar(&c.snapshot, "snapshot", "", "seeded snapshot dir (from `seed`)")
	fs.StringVar(&c.work, "work", os.TempDir(), "temp dir for server copies")
	fs.StringVar(&c.root, "root", ".", "sdkdiff source dir (contains drivers/)")
	fs.StringVar(&c.build, "build", "", "built driver artefacts dir")
	fs.StringVar(&c.sdksDir, "sdks-dir", "", "checkout of keyorix-sdks")
	fs.StringVar(&c.spec, "spec", "", "openapi.yaml")
	fs.StringVar(&c.sdks, "sdks", "go,node,python", "comma list; kind@suffix makes an extra independent instance")
	fs.StringVar(&c.plant, "plant", "", "planted defect id (P1..P7), validation only")
	fs.StringVar(&c.out, "out", "out", "output dir")
	fs.IntVar(&c.par, "par", 2, "SDKs run in parallel")
	fs.BoolVar(&c.shim, "shim", false, "adapt server answers to the SDKs' PascalCase key style (amendment A1)")
}

func (c *common) runner() (*Runner, error) {
	for _, p := range []*string{&c.server, &c.snapshot, &c.work, &c.root, &c.build, &c.sdksDir, &c.spec} {
		if *p != "" {
			if a, err := filepath.Abs(*p); err == nil {
				*p = a
			}
		}
	}
	r := &Runner{ServerBin: c.server, Snapshot: c.snapshot, Work: c.work, Par: c.par, Shim: c.shim, SDKs: strings.Split(c.sdks, ","),
		DS: DriverSet{Root: c.root, Build: c.build, SDKsDir: c.sdksDir, Plant: c.plant}}
	if c.spec != "" {
		s, err := loadSpec(c.spec)
		if err != nil {
			return nil, err
		}
		r.Spec = s
	}
	var man map[string]float64
	if b, err := os.ReadFile(filepath.Join(c.snapshot, "sdkdiff-seed.json")); err == nil { // #nosec G304 -- operator path
		_ = json.Unmarshal(b, &man)
	}
	r.Mask = Masking{ProjectMax: man["project_max"], EnvMax: man["env_max"]}
	return r, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sdkdiff seed|gen|run|replay|minimize|validate [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "seed":
		err = cmdSeed(os.Args[2:])
	case "gen":
		err = cmdGen(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "replay":
		err = cmdReplay(os.Args[2:])
	case "minimize":
		err = cmdMinimize(os.Args[2:])
	case "validate":
		err = cmdValidate(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sdkdiff:", err)
		os.Exit(1)
	}
}

func cmdSeed(args []string) error {
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	server := fs.String("server", "", "keyorix-server binary")
	out := fs.String("out", "", "snapshot dir to create (must not exist)")
	_ = fs.Parse(args)
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s exists", *out)
	}
	bin, err := filepath.Abs(*server)
	if err != nil {
		return err
	}
	dir, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	return buildSnapshot(bin, dir)
}

func writeJSONL(path string, scs []Scenario) error {
	f, err := os.Create(path) // #nosec G304 -- operator path
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck
	w := bufio.NewWriter(f)
	for _, s := range scs {
		b, _ := json.Marshal(s)
		_, _ = w.Write(append(b, '\n'))
	}
	return w.Flush()
}

func readJSONL(path string) ([]Scenario, error) {
	f, err := os.Open(path) // #nosec G304 -- operator path
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	var out []Scenario
	rd := bufio.NewReaderSize(f, 1<<24)
	for {
		line, err := rd.ReadBytes('\n')
		if len(strings.TrimSpace(string(line))) > 0 {
			var s Scenario
			if e := json.Unmarshal(line, &s); e != nil {
				return nil, e
			}
			out = append(out, s)
		}
		if err != nil {
			break
		}
	}
	return out, nil
}

func cmdGen(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	phase := fs.String("phase", "A", "A (matrix) or B (random)")
	from := fs.Int64("from", 1, "first seed (B)")
	to := fs.Int64("to", 100, "last seed (B)")
	out := fs.String("out", "scenarios.jsonl", "output file")
	_ = fs.Parse(args)
	var scs []Scenario
	switch *phase {
	case "A":
		scs = genMatrix()
	case "S":
		scs = genSink()
	default:
		for s := *from; s <= *to; s++ {
			scs = append(scs, genRandom(s))
		}
	}
	return writeJSONL(*out, scs)
}

// SigStat aggregates findings with one signature.
type SigStat struct {
	Sig      string    `json:"sig"`
	Count    int       `json:"count"`
	First    Finding   `json:"first"`
	Examples []string  `json:"examples"`
	Smallest *Scenario `json:"smallest"`
}

func scSize(s Scenario) int { b, _ := json.Marshal(s); return len(b) + 1000*len(s.Steps) }

// Report is the machine-readable result of a run.
type Report struct {
	Started   string                    `json:"started"`
	SDKs      []string                  `json:"sdks"`
	Plant     string                    `json:"plant"`
	Scenarios int                       `json:"scenarios"`
	Sigs      map[string]*SigStat       `json:"sigs"`
	Harness   []string                  `json:"harness"`
	Coverage  map[string]map[string]int `json:"coverage"`
	Info      map[string]int            `json:"info"`
	InfoEx    map[string][]string       `json:"info_examples"`
}

func newReport(c *common) *Report {
	return &Report{Started: time.Now().UTC().Format(time.RFC3339), SDKs: strings.Split(c.sdks, ","), Plant: c.plant,
		Sigs: map[string]*SigStat{}, Coverage: map[string]map[string]int{}, Info: map[string]int{}, InfoEx: map[string][]string{}}
}

func (rep *Report) add(f Finding, sc Scenario) {
	k := f.Sig()
	st := rep.Sigs[k]
	if st == nil {
		st = &SigStat{Sig: k, First: f}
		rep.Sigs[k] = st
	}
	st.Count++
	if len(st.Examples) < 5 {
		st.Examples = append(st.Examples, sc.ID)
	}
	if st.Smallest == nil || scSize(sc) < scSize(*st.Smallest) {
		c := sc
		st.Smallest = &c
	}
}

func (rep *Report) cover(r *Runner, sc Scenario, outs map[string]Outcome) {
	for i, st := range sc.Steps {
		for _, n := range r.SDKs {
			v := toView(n, stepOf(outs[n], i), r.Mask, outs[n].Token)
			key := "ran"
			if v.skip != "" {
				key = v.skip
			}
			if rep.Coverage[st.Op] == nil {
				rep.Coverage[st.Op] = map[string]int{}
			}
			rep.Coverage[st.Op][n+" "+key]++
		}
		// informational: raw query style differing while semantically equal (I1)
		raw := map[string]bool{}
		sem := map[string]bool{}
		for _, n := range r.SDKs {
			for _, rc := range stepOf(outs[n], i).Reqs {
				if len(rc.Header) > 0 && rc.Faulted == "" {
					nr := normReq(rc)
					raw[nr.RawQ] = true
					sem[strings.Join(nr.Query, "&")] = true
				}
			}
		}
		if len(raw) > 1 && len(sem) == 1 {
			rep.Info["I1 raw-query-encoding-style"]++
			if len(rep.InfoEx["I1"]) < 12 {
				var l []string
				for k := range raw {
					l = append(l, clipStr(k))
				}
				sort.Strings(l)
				rep.InfoEx["I1"] = append(rep.InfoEx["I1"], strings.Join(l, " | "))
			}
		}
	}
}

func stepOf(o Outcome, i int) StepOutcome {
	if i < len(o.Steps) {
		return o.Steps[i]
	}
	return StepOutcome{}
}

// rawOut, when set, receives the full outcomes of every scenario that produced a finding
// (or of every scenario with -raw-all); it is the evidence behind the signatures.
var (
	rawOut io.Writer
	rawAll bool
)

func runScenarios(c *common, scs []Scenario, batch int, rep *Report, progress bool) error {
	r, err := c.runner()
	if err != nil {
		return err
	}
	defer r.Close()
	rep.Scenarios += len(scs)
	for i := 0; i < len(scs); i += batch {
		end := min(i+batch, len(scs))
		chunk := scs[i:end]
		res, err := r.RunBatch(chunk)
		if err != nil {
			rep.Harness = append(rep.Harness, "H1 batch error: "+err.Error())
			continue
		}
		for j, sc := range chunk {
			outs := map[string]Outcome{}
			for n, l := range res {
				if j < len(l) {
					outs[n] = l[j]
				}
			}
			fs, h := r.Analyse(sc, outs)
			rep.Harness = append(rep.Harness, h...)
			if rawOut != nil && (len(fs) > 0 || rawAll) {
				b, _ := json.Marshal(map[string]any{"scenario": sc, "outcomes": outs, "findings": fs})
				_, _ = rawOut.Write(append(b, '\n'))
			}
			rep.cover(r, sc, outs)
			for _, f := range fs {
				rep.add(f, sc)
			}
		}
		if progress {
			fmt.Fprintf(os.Stderr, "[%s] %d/%d scenarios, %d signatures, %d harness notes\n", time.Now().Format("15:04:05"), end, len(scs), len(rep.Sigs), len(rep.Harness))
		}
	}
	return nil
}

func (rep *Report) save(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(rep, "", " ")
	return os.WriteFile(filepath.Join(dir, "report.json"), b, 0o600) // #nosec G306,G703 -- operator path
}

func cmdRun(args []string) error {
	var c common
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	c.flags(fs)
	in := fs.String("in", "", "scenarios jsonl (from gen)")
	batch := fs.Int("batch", 25, "scenarios per server lifetime")
	tag := fs.String("tag", "", "only scenarios with this tag")
	limit := fs.Int("limit", 0, "max scenarios (0 = all)")
	raw := fs.Bool("raw", true, "write raw outcomes of scenarios with findings to <out>/raw.jsonl")
	fs.BoolVar(&rawAll, "raw-all", false, "write raw outcomes of every scenario")
	_ = fs.Parse(args)
	if *raw {
		if err := os.MkdirAll(c.out, 0o750); err != nil {
			return err
		}
		f, err := os.Create(filepath.Join(c.out, "raw.jsonl")) // #nosec G304 -- operator path
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck
		rawOut = f
	}
	scs, err := readJSONL(*in)
	if err != nil {
		return err
	}
	if *tag != "" {
		var f []Scenario
		for _, s := range scs {
			for _, t := range s.Tags {
				if t == *tag {
					f = append(f, s)
					break
				}
			}
		}
		scs = f
	}
	if *limit > 0 && len(scs) > *limit {
		scs = scs[:*limit]
	}
	rep := newReport(&c)
	if err := runScenarios(&c, scs, *batch, rep, true); err != nil {
		return err
	}
	if err := rep.save(c.out); err != nil {
		return err
	}
	printSummary(rep)
	return nil
}

func printSummary(rep *Report) {
	var keys []string
	for k := range rep.Sigs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("scenarios=%d signatures=%d harness-notes=%d plant=%q\n", rep.Scenarios, len(keys), len(rep.Harness), rep.Plant)
	for _, k := range keys {
		s := rep.Sigs[k]
		fmt.Printf("  %5dx %s   e.g. %s  %s\n", s.Count, k, s.Examples[0], clipStr(s.First.Detail))
	}
	for k, v := range rep.Info {
		fmt.Printf("  info %s: %d\n", k, v)
	}
}
