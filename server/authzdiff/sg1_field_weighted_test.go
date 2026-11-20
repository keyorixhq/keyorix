package authzdiff

// SG1: Field-weighted mutation experiment.
//
// GOAL: measure whether a weighted random walk over the authzdiff case space —
// oversampling cases where pkCustom/pkMachine holds a PARTIAL permission set —
// detects the existing planted defects in fewer samples than a uniform walk.
//
// BACKGROUND: the full sweep (TestAuthzDiffSweep) is deterministic and
// exhaustive; it always detects every plant. SG1 asks whether, in a
// budget-limited (non-exhaustive) scenario, a field-weighted sampler would
// find plants earlier than a uniform sampler.
//
// WHAT THIS DOES NOT MEASURE:
//   - Go fuzz engine mutation strategy (this is pure random sampling)
//   - FuzzAuthzSeq or the stateful sequence oracle
//   - faultops (not in scope; authzdiff result answers the KEEP/DROP question)
//   - plants outside the op-spec model's case space (env, PAT boundary edge cases)
//
// SIGNAL: HIGH_WEIGHT (5.0) for a case where Principal is pkCustom or
// pkMachine AND the variation Mask is not allPerms (partial permission set).
// Rationale: a permission-check defect surfaces when a principal LACKS the
// required permission but is wrongly allowed; partial-mask cases are the
// most likely to trigger this.
//
// OPT-IN: set SG1_FW=1 to run. Each plant requires ~1-2 min to collect the
// oracle; the simulation itself is in-memory (<1 s per plant).
//
// DECISION RULE (pre-registered, decided before any run):
//   KEEP: weighted median first-detection iteration < uniform median, and
//         improvement factor >= 1.5x, for >= 3 of the 5 tested plants.
//   DROP: otherwise.
//
// DROPPED — improvement 1.00–1.05× across all 5 plants (threshold 1.5×).
// 97%+ of the case space is already the "high-weight" class; weighting it
// further provides no discrimination power. See sg1-field-weighted-mutation.md.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	sg1HighWeight  = 5.0
	sg1NSims       = 10_000
	sg1KeepFactor  = 1.5 // minimum improvement to count as "helps"
	sg1MinKeepPlants = 3  // of 5 tested plants must meet the threshold
)

// sg1Case is the minimal fields we need from a caseResult JSONL line.
type sg1Case struct {
	Principal string `json:"principal"`
	Mask      uint16 `json:"mask"`
	Bucket    string `json:"bucket"`
}

// sg1IsHighWeight returns true when the case gets the signal weight boost:
// generated-mask principal (pkCustom or pkMachine) with a partial permission set.
func sg1IsHighWeight(c sg1Case) bool {
	pk := principalKind(c.Principal)
	return (pk == pkCustom || pk == pkMachine) && c.Mask != allPerms
}

// sg1Weight returns the sampling weight for a case under the WEIGHTED strategy.
func sg1Weight(c sg1Case) float64 {
	if sg1IsHighWeight(c) {
		return sg1HighWeight
	}
	return 1.0
}

// sg1CollectOracle runs TestAuthzDiffSweep for one op with optional overlay and
// returns all cases. This is childSweep extended to return the full case list,
// not just the count in one bucket.
func sg1CollectOracle(t *testing.T, op, overlay string) []sg1Case {
	t.Helper()
	out := filepath.Join(t.TempDir(), "res.jsonl")
	args := []string{"test", "-count=1", "-run", "^TestAuthzDiffSweep$", "-timeout", "20m"}
	if overlay != "" {
		args = append(args, "-overlay", overlay)
	}
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "GOFLAGS="+os.Getenv("GOFLAGS"),
		"AUTHZDIFF_SWEEP=1", "AUTHZDIFF_OPS="+op, "AUTHZDIFF_OUT="+out,
		"AUTHZDIFF_STRICT=", "AUTHZDIFF_PLANTS=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sg1 oracle sweep (op=%s overlay=%q) failed: %v\n%s", op, overlay, err, tail(string(b), 40))
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatalf("sg1 oracle open: %v", err)
	}
	defer func() { _ = f.Close() }()
	var cases []sg1Case
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var c sg1Case
		if json.Unmarshal(sc.Bytes(), &c) == nil {
			cases = append(cases, c)
		}
	}
	return cases
}

// sg1Stats describes one random walk's first-detection iteration.
// iteration == len(cases)+1 means the plant was not detected in the full walk.
type sg1WalkResult struct {
	median   float64
	mean     float64
	p25, p75 float64
	found    int // of sg1NSims walks that detected the plant
	total    int // == sg1NSims
}

// sg1Simulate runs sg1NSims random walks over cases, using the UNIFORM (w=nil)
// or WEIGHTED (w=sg1Weight per case) sampling strategy, and returns statistics
// about the iteration count at which the first case in targetBucket is seen.
func sg1Simulate(r *rand.Rand, cases []sg1Case, targetBucket string, weighted bool) sg1WalkResult {
	n := len(cases)
	w := make([]float64, n)
	for i, c := range cases {
		if weighted {
			w[i] = sg1Weight(c)
		} else {
			w[i] = 1.0
		}
	}

	hits := make([]int, 0, sg1NSims)
	for range sg1NSims {
		hit := sg1OneWalk(r, cases, w, targetBucket)
		hits = append(hits, hit)
	}
	sort.Ints(hits)

	found := 0
	sum := 0.0
	for _, h := range hits {
		sum += float64(h)
		if h <= n {
			found++
		}
	}

	return sg1WalkResult{
		median: float64(hits[sg1NSims/2]),
		mean:   sum / float64(sg1NSims),
		p25:    float64(hits[sg1NSims/4]),
		p75:    float64(hits[3*sg1NSims/4]),
		found:  found,
		total:  sg1NSims,
	}
}

// sg1OneWalk simulates one weighted random walk without replacement over cases
// and returns the 1-based iteration at which the first case in targetBucket is
// encountered. Returns len(cases)+1 if no case in targetBucket is found.
func sg1OneWalk(r *rand.Rand, cases []sg1Case, weights []float64, targetBucket string) int {
	n := len(cases)
	// Copy weights for in-place elimination.
	wCopy := make([]float64, n)
	copy(wCopy, weights)
	remaining := make([]int, n)
	for i := range n {
		remaining[i] = i
	}
	for iter := 1; len(remaining) > 0; iter++ {
		// Weighted selection from remaining.
		total := 0.0
		for _, wt := range wCopy[:len(remaining)] {
			total += wt
		}
		pick := r.Float64() * total
		cum := 0.0
		chosen := len(remaining) - 1
		for j, wt := range wCopy[:len(remaining)] {
			cum += wt
			if pick < cum {
				chosen = j
				break
			}
		}
		idx := remaining[chosen]
		if cases[idx].Bucket == targetBucket {
			return iter
		}
		// Remove chosen element (swap with last).
		last := len(remaining) - 1
		remaining[chosen] = remaining[last]
		wCopy[chosen] = wCopy[last]
		remaining = remaining[:last]
	}
	return n + 1
}

// sg1Improvement returns the ratio uniform/weighted (> 1 means weighted is faster).
func sg1Improvement(uniform, weighted sg1WalkResult) float64 {
	if weighted.median == 0 {
		return math.Inf(1)
	}
	return uniform.median / weighted.median
}

// sg1PlantSpec is a subset of the plant fields needed for the experiment.
type sg1PlantSpec struct {
	name   string
	file   string
	anchor string
	repl   string
	op     string
	bucket string
}

func (p sg1PlantSpec) wantBucket() string {
	if p.bucket == "" {
		return "unexplained"
	}
	return p.bucket
}

// sg1SelectedPlants is the subset of plants used for the SG1 experiment,
// chosen to cover different defect classes (perm-check removal, guard removal,
// ceiling defect, env-scope, PAT refusal).
func sg1SelectedPlants() []sg1PlantSpec {
	var out []sg1PlantSpec
	for _, pl := range plants {
		switch pl.name {
		case "name-based-role-check",        // perm-check replaced by name check
			"grpc-guard-removed",            // gRPC transport guard removed
			"router-gate-removed",           // REST router gate removed
			"fix-3990-setrole-ceiling-removed", // ceiling check removed
			"env-scope-clause-removed":      // env-scope filter removed
			out = append(out, sg1PlantSpec{
				name:   pl.name,
				file:   pl.file,
				anchor: pl.anchor,
				repl:   pl.repl,
				op:     pl.op,
				bucket: pl.bucket,
			})
		}
	}
	return out
}

// sg1Result holds one plant's measurement outcome.
type sg1Result struct {
	plant          string
	op             string
	bucket         string
	totalCases     int
	unexplained    int
	highWeight     int
	unexplHighW    int
	pBase          float64 // K/N
	pHW            float64 // K_hw / N_hw
	ratio          float64 // pHW / pBase (a priori improvement)
	uniform        sg1WalkResult
	weighted       sg1WalkResult
	simImprovement float64
}

// TestSG1FieldWeightedMutation is the SG1 measurement experiment.
// Set SG1_FW=1 to run. Each oracle collection takes ~1-2 min;
// the total run time for 5 plants is about 10-15 min.
func TestSG1FieldWeightedMutation(t *testing.T) {
	if os.Getenv("SG1_FW") == "" {
		t.Skip("set SG1_FW=1 to run the SG1 field-weighted mutation experiment")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	r := rand.New(rand.NewSource(42))

	var results []sg1Result

	selected := sg1SelectedPlants()
	if len(selected) == 0 {
		t.Fatal("no plants selected: plant names must match sg1SelectedPlants()")
	}

	for _, pl := range selected {
		t.Run(pl.name, func(t *testing.T) {
			// Build overlay.
			orig := filepath.Join(root, pl.file)
			src, err := os.ReadFile(orig)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(src), pl.anchor) != 1 {
				t.Fatalf("plant %s: anchor not found once in %s — plant drifted", pl.name, pl.file)
			}
			dir := t.TempDir()
			patched := filepath.Join(dir, filepath.Base(pl.file))
			if err := os.WriteFile(patched, []byte(strings.Replace(string(src), pl.anchor, pl.repl, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
			ov, _ := json.Marshal(map[string]any{"Replace": map[string]string{orig: patched}})
			overlay := filepath.Join(dir, "overlay.json")
			if err := os.WriteFile(overlay, ov, 0o600); err != nil {
				t.Fatal(err)
			}

			bucket := pl.wantBucket()

			t.Logf("collecting oracle for plant %s (op=%s, overlay)", pl.name, pl.op)
			planted := sg1CollectOracle(t, pl.op, overlay)
			t.Logf("plant %s: %d total cases in oracle", pl.name, len(planted))

			// Verify: control must have zero unexplained.
			t.Logf("collecting clean oracle for plant %s (no overlay)", pl.name)
			clean := sg1CollectOracle(t, pl.op, "")
			cleanUnexplained := 0
			for _, c := range clean {
				if c.Bucket == bucket {
					cleanUnexplained++
				}
			}
			if cleanUnexplained != 0 {
				t.Fatalf("plant %s: clean oracle has %d %s cases; fix pre-existing noise before measuring",
					pl.name, cleanUnexplained, bucket)
			}

			// Count cases.
			n := len(planted)
			k, nHW, kHW := 0, 0, 0
			for _, c := range planted {
				if c.Bucket == bucket {
					k++
				}
				if sg1IsHighWeight(c) {
					nHW++
					if c.Bucket == bucket {
						kHW++
					}
				}
			}
			if k == 0 {
				t.Fatalf("plant %s: zero %s cases in planted oracle (plant drifted or sweep missed it)", pl.name, bucket)
			}

			pBase := float64(k) / float64(n)
			var pHW, ratio float64
			if nHW > 0 {
				pHW = float64(kHW) / float64(nHW)
				ratio = pHW / pBase
			}

			t.Logf("plant %s: N=%d K=%d P_base=%.3f N_hw=%d K_hw=%d P_hw=%.3f ratio=%.2f",
				pl.name, n, k, pBase, nHW, kHW, pHW, ratio)

			// Simulate random walks.
			t.Logf("plant %s: simulating %d walks under UNIFORM and WEIGHTED strategies…", pl.name, sg1NSims)
			uniformRes := sg1Simulate(r, planted, bucket, false)
			weightedRes := sg1Simulate(r, planted, bucket, true)
			imp := sg1Improvement(uniformRes, weightedRes)

			t.Logf("plant %s UNIFORM: median=%g p25=%g p75=%g found=%d/%d",
				pl.name, uniformRes.median, uniformRes.p25, uniformRes.p75, uniformRes.found, uniformRes.total)
			t.Logf("plant %s WEIGHTED: median=%g p25=%g p75=%g found=%d/%d",
				pl.name, weightedRes.median, weightedRes.p25, weightedRes.p75, weightedRes.found, weightedRes.total)
			t.Logf("plant %s improvement=%.2f (uniform/weighted, >1 = weighted faster)", pl.name, imp)

			results = append(results, sg1Result{
				plant:          pl.name,
				op:             pl.op,
				bucket:         bucket,
				totalCases:     n,
				unexplained:    k,
				highWeight:     nHW,
				unexplHighW:    kHW,
				pBase:          pBase,
				pHW:            pHW,
				ratio:          ratio,
				uniform:        uniformRes,
				weighted:       weightedRes,
				simImprovement: imp,
			})
		})
	}

	// Summary.
	t.Log("=== SG1 SUMMARY ===")
	t.Logf("%-40s  %6s  %8s  %8s  %6s  %6s",
		"plant", "N", "P_base", "P_hw/P_base", "uni_med", "wgt_med")
	keeps := 0
	for _, r := range results {
		t.Logf("%-40s  %6d  %8.4f  %10.2f  %7.1f  %7.1f",
			r.plant, r.totalCases, r.pBase, r.ratio, r.uniform.median, r.weighted.median)
		if r.simImprovement >= sg1KeepFactor && r.weighted.median < r.uniform.median {
			keeps++
		}
	}
	t.Logf("Plants meeting KEEP threshold (improvement >= %.1f×): %d of %d", sg1KeepFactor, keeps, len(results))
	if keeps >= sg1MinKeepPlants {
		t.Logf("VERDICT: KEEP — field-weighted sampling shows ≥%.1f× improvement on %d+ plants", sg1KeepFactor, sg1MinKeepPlants)
	} else {
		t.Logf("VERDICT: DROP — improvement < %.1f× on too many plants (keeps=%d, need %d)", sg1KeepFactor, keeps, sg1MinKeepPlants)
	}

	// Machine-readable result line for the report.
	t.Logf("SG1-RESULT keeps=%d total=%d threshold=%.1f VERDICT=%s",
		keeps, len(results), sg1KeepFactor, func() string {
			if keeps >= sg1MinKeepPlants {
				return "KEEP"
			}
			return "DROP"
		}())

	// Write CSV for the report.
	sg1WriteCSV(t, results)
}

// sg1WriteCSV writes a machine-readable results file to .scratch/.
func sg1WriteCSV(t *testing.T, results []sg1Result) {
	t.Helper()
	dir := filepath.Join("..", "..", ".scratch")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Logf("sg1WriteCSV: mkdir %s: %v (skipping)", dir, err)
		return
	}
	path := filepath.Join(dir, "sg1-results.csv")
	f, err := os.Create(path)
	if err != nil {
		t.Logf("sg1WriteCSV: %v (skipping)", err)
		return
	}
	defer func() { _ = f.Close() }()
	fmt.Fprintf(f, "plant,op,bucket,N,K,N_hw,K_hw,P_base,P_hw,apriori_ratio,uni_median,uni_found,wgt_median,wgt_found,sim_improvement\n")
	for _, r := range results {
		fmt.Fprintf(f, "%s,%s,%s,%d,%d,%d,%d,%.4f,%.4f,%.3f,%.1f,%d,%.1f,%d,%.3f\n",
			r.plant, r.op, r.bucket,
			r.totalCases, r.unexplained, r.highWeight, r.unexplHighW,
			r.pBase, r.pHW, r.ratio,
			r.uniform.median, r.uniform.found,
			r.weighted.median, r.weighted.found,
			r.simImprovement)
	}
	t.Logf("sg1WriteCSV: wrote %s", path)
}
