package configspace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RunOptions configures a matrix run.
type RunOptions struct {
	Model       *Model
	Template    *Template
	Work        string // scratch root for case directories
	Out         string // private output directory (results are written here only)
	Bin         string // keyorix-server binary; empty disables the process stage
	Mutations   int
	ProcMutants int
	ProcInvalid int
	Seed        int64
	Log         func(format string, a ...any)
}

// Summary is the aggregate of a run (no finding details).
type Summary struct {
	Params, Values, Invalid                            int
	Solo, PairAll, PairClean, PairStart, Mut, Targeted int
	PairRowsAll, PairRowsClean, PairRowsStart          int
	InProcAccepted, InProcRefused, InProcPanics        int
	ProcRun, ProcStarted, ProcRefused, ProcCrash       int
	Findings                                           map[string]int // "I3/S1" -> unique count
	Unique                                             int
	DeferredToBoot                                     int
	Elapsed                                            time.Duration
}

// UniqueFinding is a deduplicated finding with its confirmation status.
type UniqueFinding struct {
	Finding
	Count     int      `json:"count"`
	Cases     []string `json:"cases"`
	Replays   int      `json:"replays"`
	Confirmed int      `json:"confirmed"`
	Minimal   []string `json:"minimal,omitempty"`
	// MinAssign is the minimised assignment (param id -> value index), for replay.
	MinAssign map[string]int `json:"min_assign,omitempty"`
}

type runState struct {
	o        RunOptions
	findings []Finding
	sum      Summary
	cases    map[string]*Case    // by id, for replay
	soloOK   map[string]bool     // solo case accepted by Load+Validate
	soloPost map[string][]string // posture predicates holding in an accepted solo case
	procOut  map[string]string   // case id -> refused | started | crash | hang
	Deferred int
}

func (r *runState) logf(f string, a ...any) {
	if r.o.Log != nil {
		r.o.Log(f, a...)
	}
}

func (r *runState) inproc(c *Case) (InProcResult, bool) {
	if err := c.Materialize(r.o.Model, r.o.Template, r.o.Work, true); err != nil {
		r.logf("materialize %s: %v", c.ID, err)
		return InProcResult{}, false
	}
	defer os.RemoveAll(c.Dir)
	res := RunInProc(r.o.Model, c)
	switch {
	case res.Panic != "":
		r.sum.InProcPanics++
	case res.Accepted:
		r.sum.InProcAccepted++
	default:
		r.sum.InProcRefused++
	}
	return res, true
}

// Run executes every stage and writes results into o.Out.
func Run(o RunOptions) (Summary, error) {
	start := time.Now()
	if err := os.MkdirAll(o.Out, 0o700); err != nil {
		return Summary{}, err
	}
	if err := os.MkdirAll(o.Work, 0o700); err != nil {
		return Summary{}, err
	}
	r := &runState{o: o, cases: map[string]*Case{}, soloOK: map[string]bool{}, soloPost: map[string][]string{}, procOut: map[string]string{}}
	r.sum.Findings = map[string]int{}
	cn := o.Model.Counts()
	r.sum.Params, r.sum.Values, r.sum.Invalid = cn.Params, cn.Values, cn.Invalid

	// 1. solo rows, in-process
	solo := SoloCases(o.Model)
	r.sum.Solo = len(solo)
	soloRefused := map[valueKey]bool{}
	var accepted []*Case
	for _, c := range solo {
		res, ok := r.inproc(c)
		if !ok {
			continue
		}
		r.findings = append(r.findings, CheckInProc(o.Model, c, res)...)
		r.cases[c.ID] = c
		for id, vi := range c.Assign {
			v := o.Model.Param(id).Values[vi]
			if v.Class != ClassInvalid && !res.Accepted {
				soloRefused[valueKey{id, vi}] = true
			}
		}
		if res.Accepted {
			accepted = append(accepted, c)
			r.soloOK[c.ID] = true
			r.soloPost[c.ID] = res.Posture
		}
	}
	r.logf("solo rows: %d (%d accepted)", len(solo), len(accepted))

	// 2. covering arrays
	allCases, allRows, allSizes := PairwiseCases(o.Model, PairwiseOpts{Name: "pair-all", Seed: o.Seed, Tries: 16})
	cleanCases, cleanRows, cleanSizes := PairwiseCases(o.Model, PairwiseOpts{Name: "pair-clean", Seed: o.Seed + 1, Tries: 16, ExcludeSolo: soloRefused})
	startCases, startRows, startSizes := PairwiseCases(o.Model, PairwiseOpts{Name: "pair-start", Seed: o.Seed + 2, Tries: 16, StartOnly: true, ExcludeSolo: soloRefused})
	r.sum.PairAll, r.sum.PairClean, r.sum.PairStart = len(allCases), len(cleanCases), len(startCases)
	r.sum.PairRowsAll, r.sum.PairRowsClean, r.sum.PairRowsStart = len(allRows), len(cleanRows), len(startRows)
	if g := PairGaps(allSizes, allRows) + PairGaps(cleanSizes, cleanRows) + PairGaps(startSizes, startRows); g != 0 {
		return r.sum, fmt.Errorf("covering array has %d uncovered pairs", g)
	}
	for _, set := range [][]*Case{allCases, cleanCases, startCases} {
		for _, c := range set {
			res, ok := r.inproc(c)
			if !ok {
				continue
			}
			r.findings = append(r.findings, CheckInProc(o.Model, c, res)...)
			r.cases[c.ID] = c
			// an array row built only from solo-accepted values that is refused is an interaction
			if c.Kind != "pair-all" && !res.Accepted && res.Panic == "" && !strings.Contains(res.Err, "both KEYORIX_") && !explainedRefusal(o.Model, c, res.Err) {
				r.findings = append(r.findings, Finding{Inv: "I2", Sev: "S4", Stage: "inproc", Case: c.ID,
					Key: "interaction-refusal:" + refusalSig(res.Err), Title: "pairwise row of individually accepted values is refused (option interaction)", Detail: res.Err})
			}
		}
	}
	r.logf("pairwise rows: all %d, clean %d, start %d", len(allCases), len(cleanCases), len(startCases))

	// 3. mutation rows
	muts := MutationCases(o.Model, o.Mutations, o.Seed+3, 3, 9, 0.12)
	r.sum.Mut = len(muts)
	for _, c := range muts {
		res, ok := r.inproc(c)
		if !ok {
			continue
		}
		r.findings = append(r.findings, CheckInProc(o.Model, c, res)...)
		r.cases[c.ID] = c
	}

	// 4. targeted precedence and alias cases
	tg := append(PrecedenceCases(), AliasCases()...)
	r.sum.Targeted = len(tg)
	aliasRes := map[string]InProcResult{}
	for _, c := range tg {
		res, ok := r.inproc(c)
		if !ok {
			continue
		}
		r.cases[c.ID] = c
		if len(c.ID) > 5 && c.ID[:5] == "alias" {
			aliasRes[c.ID] = res
			// alias rows still get the generic checks
		}
		r.findings = append(r.findings, CheckPrecedence(c, res)...)
	}
	r.findings = append(r.findings, CheckAliases(aliasRes)...)

	// 5. process stage
	if o.Bin != "" {
		r.procStage(solo, startCases, muts)
	}

	r.sum.Elapsed = time.Since(start)
	return r.finish()
}

func explainedRefusal(m *Model, c *Case, errText string) bool {
	var tokens []string
	for _, cf := range m.TriggeredConflicts(c) {
		tokens = append(tokens, cf.Names...)
	}
	return len(tokens) > 0 && errNames(errText, tokens)
}

func refusalSig(e string) string {
	if len(e) > 80 {
		e = e[:80]
	}
	return e
}

func (r *runState) procCase(c *Case) {
	if err := c.Materialize(r.o.Model, r.o.Template, r.o.Work, false); err != nil {
		r.logf("materialize %s: %v", c.ID, err)
		return
	}
	defer os.RemoveAll(c.Dir)
	ip := RunInProc(r.o.Model, c)
	httpOn, grpcOn := enabledFlags(c, ip)
	pr := RunProc(r.o.Bin, c, httpOn, grpcOn, 30*time.Second, 15*time.Second)
	r.sum.ProcRun++
	if r.sum.ProcRun%10 == 0 {
		r.logf("process stage: %d cases run", r.sum.ProcRun)
	}
	switch {
	case pr.Signal != "":
		r.sum.ProcCrash++
		r.procOut[c.ID] = "crash"
	case pr.Started:
		r.sum.ProcStarted++
		r.procOut[c.ID] = "started"
	case pr.TimedOut:
		r.procOut[c.ID] = "hang"
	default:
		r.sum.ProcRefused++
		r.procOut[c.ID] = "refused"
	}
	fs := CheckProc(r.o.Model, c, ip, pr)
	r.findings = append(r.findings, fs...)
	if len(fs) > 0 {
		_ = os.WriteFile(filepath.Join(r.o.Out, "proc-"+c.ID+".log"), []byte(pr.Log), 0o600)
	}
}

func enabledFlags(c *Case, ip InProcResult) (bool, bool) {
	if ip.Cfg != nil {
		return ip.Cfg.Server.HTTP.Enabled, ip.Cfg.Server.GRPC.Enabled
	}
	h, _ := GetPath(c.Doc, "server.http.enabled")
	g, _ := GetPath(c.Doc, "server.grpc.enabled")
	return h == true, g == true
}

func (r *runState) procStage(solo, startCases, muts []*Case) {
	n := 0
	for _, c := range startCases {
		if r.procCaseOK(c) {
			n++
		}
	}
	// Inline secrets: each canary-valued YAML option alone, with its file-based twin
	// removed from the baseline (both set is a refusal by design), so that the secret
	// is actually in effect while the server starts and serves.
	for _, c := range solo {
		for id, vi := range c.Assign {
			p := r.o.Model.Param(id)
			v := p.Values[vi]
			sv, _ := v.V.(string)
			if p.Kind != KindYAML || !strings.HasPrefix(sv, "$CANARY:") || !v.CanStart() {
				continue
			}
			sc := &Case{ID: "sec-" + c.ID, Kind: "targeted", Assign: copyAssign(c.Assign),
				RawYAML: map[string]any{p.Path + "_file": nil}}
			r.cases[sc.ID] = sc
			r.procCase(sc)
		}
	}
	// Posture sweep: every startable solo value that puts a posture predicate in
	// effect is started once, so that the warning check (I3b) sees each of them.
	for _, c := range solo {
		if !r.soloOK[c.ID] || len(r.soloPost[c.ID]) == 0 {
			continue
		}
		ok := true
		for id, vi := range c.Assign {
			v := r.o.Model.Param(id).Values[vi]
			if !v.CanStart() || v.Class == ClassInvalid || v.Absent {
				ok = false
			}
		}
		if ok {
			r.procCase(c)
		}
	}
	// solo invalid values: boot-level behaviour of each
	cnt, refusedSample := 0, 0
	for _, c := range solo {
		for id, vi := range c.Assign {
			v := r.o.Model.Param(id).Values[vi]
			if v.Class != ClassInvalid || !v.CanStart() {
				continue
			}
			if r.soloOK[c.ID] {
				r.procCase(c) // accepted by Load+Validate: the boot must still refuse it
				cnt++
			} else if refusedSample < r.o.ProcInvalid {
				r.procCase(c) // sample of refused ones: exit code and message
				refusedSample++
			}
		}
	}
	cnt = 0
	for _, c := range muts {
		if cnt >= r.o.ProcMutants {
			break
		}
		ok := true
		for id, vi := range c.Assign {
			if !r.o.Model.Param(id).Values[vi].CanStart() {
				ok = false
			}
		}
		if ok {
			r.procCase(c)
			cnt++
		}
	}
	r.logf("process stage: %d cases", r.sum.ProcRun)
}

func (r *runState) procCaseOK(c *Case) bool { r.procCase(c); return true }

// finish deduplicates, confirms and writes results.
func (r *runState) finish() (Summary, error) {
	uniq := map[string]*UniqueFinding{}
	var order []string
	for _, f := range r.findings {
		// A value Load+Validate accept but the boot refuses is a late refusal, not an
		// accepted invalid value (RULES.md I2a asks for a non-zero exit).
		if f.Stage == "inproc" && strings.HasPrefix(f.Key, "invalid-accepted:") && r.refusedAtBoot(f) {
			r.Deferred++
			continue
		}
		k := f.Inv + "|" + f.Stage + "|" + f.Key
		u := uniq[k]
		if u == nil {
			u = &UniqueFinding{Finding: f}
			uniq[k] = u
			order = append(order, k)
		}
		u.Count++
		if len(u.Cases) < 5 {
			u.Cases = append(u.Cases, f.Case)
		}
	}
	sort.Strings(order)
	for _, k := range order {
		u := uniq[k]
		r.confirm(u)
		r.sum.Findings[u.Inv+"/"+u.Sev]++
	}
	r.sum.Unique = len(order)
	r.sum.DeferredToBoot = r.Deferred
	f, err := os.Create(filepath.Join(r.o.Out, "findings.jsonl"))
	if err != nil {
		return r.sum, err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, k := range order {
		_ = enc.Encode(uniq[k])
	}
	sj, _ := json.MarshalIndent(r.sum, "", "  ")
	_ = os.WriteFile(filepath.Join(r.o.Out, "summary.json"), sj, 0o600)
	return r.sum, nil
}

// confirm replays the first case of a finding three times and minimises its
// assignments by block-wise greedy removal while the finding persists. Process-stage
// findings get a small run budget because every run starts the real server.
func (r *runState) confirm(u *UniqueFinding) {
	if len(u.Key) > 6 && u.Key[:6] == "alias-" {
		for i := 0; i < 3; i++ {
			u.Replays++
			res := map[string]InProcResult{}
			for _, ac := range AliasCases() {
				if err := ac.Materialize(r.o.Model, r.o.Template, r.o.Work, true); err == nil {
					res[ac.ID] = RunInProc(r.o.Model, ac)
					os.RemoveAll(ac.Dir)
				}
			}
			for _, f := range CheckAliases(res) {
				if f.Key == u.Key {
					u.Confirmed++
					break
				}
			}
		}
		return
	}
	c := r.cases[u.Cases[0]]
	if c == nil {
		return
	}
	for i := 0; i < 3; i++ {
		u.Replays++
		if r.reproduces(c, u) {
			u.Confirmed++
		}
	}
	cur := copyAssign(c.Assign)
	if u.Confirmed > 0 && len(cur) > 1 {
		budget := 1 << 30
		if u.Stage == "proc" {
			budget = 16
		}
		ids := make([]string, 0, len(cur))
		for id := range cur {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for block := len(ids) / 2; block >= 1 && budget > 0; block /= 2 {
			for start := 0; start < len(ids) && budget > 0; start += block {
				trial := copyAssign(cur)
				removed := 0
				for _, id := range ids[start:min(start+block, len(ids))] {
					if _, ok := trial[id]; ok {
						delete(trial, id)
						removed++
					}
				}
				if removed == 0 {
					continue
				}
				budget--
				tc := &Case{ID: "min-" + c.ID, Kind: c.Kind, Assign: trial, RawYAML: c.RawYAML, RawEnv: c.RawEnv}
				if r.reproduces(tc, u) {
					cur = trial
				}
			}
		}
	}
	u.MinAssign = cur
	for id, vi := range cur {
		u.Minimal = append(u.Minimal, fmt.Sprintf("%s=%v", id, r.o.Model.Param(id).Values[vi].V))
	}
	sort.Strings(u.Minimal)
}

func copyAssign(a map[string]int) map[string]int {
	b := make(map[string]int, len(a))
	for k, v := range a {
		b[k] = v
	}
	return b
}

func (r *runState) reproduces(c *Case, u *UniqueFinding) bool {
	tc := &Case{ID: "rp-" + c.ID, Kind: c.Kind, Assign: c.Assign, RawYAML: c.RawYAML, RawEnv: c.RawEnv}
	if u.Stage == "proc" {
		if r.o.Bin == "" {
			return false
		}
		if err := tc.Materialize(r.o.Model, r.o.Template, r.o.Work, false); err != nil {
			return false
		}
		defer os.RemoveAll(tc.Dir)
		ip := RunInProc(r.o.Model, tc)
		httpOn, grpcOn := enabledFlags(tc, ip)
		pr := RunProc(r.o.Bin, tc, httpOn, grpcOn, 30*time.Second, 15*time.Second)
		return hasKey(CheckProc(r.o.Model, tc, ip, pr), u)
	}
	if err := tc.Materialize(r.o.Model, r.o.Template, r.o.Work, true); err != nil {
		return false
	}
	defer os.RemoveAll(tc.Dir)
	res := RunInProc(r.o.Model, tc)
	fs := CheckInProc(r.o.Model, tc, res)
	if u.Inv == "I5" {
		fs = append(fs, CheckPrecedence(tc, res)...)
	}
	return hasKey(fs, u)
}

func hasKey(fs []Finding, u *UniqueFinding) bool {
	for _, f := range fs {
		if f.Key == u.Key && f.Inv == u.Inv {
			return true
		}
	}
	return false
}

// refusedAtBoot reports whether the option/value behind an "invalid-accepted" finding is
// refused by the real boot in any process-stage case that carries it.
func (r *runState) refusedAtBoot(f Finding) bool {
	if r.procOut[f.Case] == "refused" {
		return true
	}
	parts := strings.SplitN(f.Key, ":", 3)
	if len(parts) < 3 {
		return false
	}
	id, val := parts[1], parts[2]
	p := r.o.Model.Param(id)
	if p == nil {
		return false
	}
	for cid, out := range r.procOut {
		if out != "refused" {
			continue
		}
		c := r.cases[cid]
		if c == nil {
			continue
		}
		vi, ok := c.Assign[id]
		if ok && vi < len(p.Values) && fmt.Sprint(p.Values[vi].V) == val {
			return true
		}
	}
	return false
}
