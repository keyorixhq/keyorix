package authzdiff

// Authorization-decision novelty for FuzzAuthzSeqNov (see NOVELTY.md).
//
// A decision tuple is (actor, verb, resource, decision, scope): the principal
// kind that acted or was probed, the operation, the resource type, whether the
// transports allowed or denied it, and the scope it was aimed at. Plain
// coverage-guided fuzzing keeps an input when it reaches a new code EDGE; two
// different (actor, scope) pairs that run the same code are the same edge, so
// the fuzzer may drop the input that reached the second pair. With
// AUTHZNOV_FEED=1 every executed tuple also runs its own generated basic block
// (novEdge), which turns "new tuple" into "new edge" for Go's native fuzzer
// without touching the engine.
//
// The recorder is the same in both arms (it only observes); FEED only decides
// whether the tuple blocks are executed. AUTHZNOV_LOG appends one line per
// first sighting of a tuple in a process, for the analysis.

import (
	"fmt"
	"math/rand"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	novStepTuples  = 8 * int(numSeqKinds) * 3 * 3 // probe-kind index x step kind x decision x scope
	novProbeTuples = 8 * 2 * 3
	novTuples      = novStepTuples + novProbeTuples
)

func novDec(o Outcome) int {
	switch o {
	case Allowed:
		return 0
	case Denied:
		return 1
	}
	return 2
}

func novKindIdx(k principalKind) int {
	for i, p := range seqProbes {
		if p == k {
			return i
		}
	}
	return 0
}

func novScopeIdx(t tgt) int {
	for i, s := range seqTargets {
		if s == t {
			return i
		}
	}
	return 0
}

var novStepResource = [numSeqKinds]string{"role-grant", "role-grant", "account", "account", "group-membership", "group-membership", "custom-role-permission", "role-grant"}

func novStepID(actor principalKind, k seqKind, dec Outcome, t tgt) int {
	return ((novKindIdx(actor)*int(numSeqKinds)+int(k))*3+novDec(dec))*3 + novScopeIdx(t)
}

func novProbeID(probe principalKind, t tgt, dec Outcome) int {
	return novStepTuples + ((novKindIdx(probe)*2+novScopeIdx(t))*3 + novDec(dec))
}

// novName is the readable tuple, for the analysis only.
func novName(id int) string {
	if id >= novStepTuples {
		r := id - novStepTuples
		dec := r % 3
		r /= 3
		return fmt.Sprintf("probe actor=%s verb=secrets.read res=secret-value dec=%s scope=%s", seqProbes[r/2], []string{"allow", "deny", "other"}[dec], seqTargets[r%2])
	}
	sc := id % 3
	r := id / 3
	dec := r % 3
	r /= 3
	return fmt.Sprintf("step actor=%s verb=%s res=%s dec=%s scope=%s", seqProbes[r/int(numSeqKinds)], seqKindNames[r%int(numSeqKinds)], novStepResource[r%int(numSeqKinds)], []string{"allow", "deny", "other"}[dec], seqTargets[sc])
}

var (
	novSeen  [novTuples]atomic.Bool
	novExecs atomic.Int64
	novLogMu sync.Mutex
	novFeed  = os.Getenv("AUTHZNOV_FEED") == "1"
)

func novLog(format string, a ...any) {
	path := os.Getenv("AUTHZNOV_LOG")
	if path == "" {
		return
	}
	novLogMu.Lock()
	defer novLogMu.Unlock()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintf(f, format, a...)
}

// novObserve is called once per fuzz execution with the tuples runSeq saw.
func novObserve(ids []int) {
	n := novExecs.Add(1)
	now := time.Now().UnixNano()
	pid := os.Getpid()
	for _, id := range ids {
		if novSeen[id].CompareAndSwap(false, true) {
			novLog("T %d %d %d %d\n", now, pid, n, id)
		}
		if novFeed {
			novEdge(id)
		}
	}
	if n%5 == 0 || n == 1 {
		novLog("E %d %d %d\n", now, pid, n)
	}
}

// novPlants are the planted defects of the pre-registered comparison. They
// live in the harness, like the other seqFault plants.
func novPlant(name string) *seqFault {
	switch name {
	case "":
		return nil
	case "rare":
		// REST wrongly denies a custom-role principal that holds the permission
		// at scope A: the probe tuple (custom-role, secrets.read, allow, A), seen
		// in 1 of 100 random sequences in the census (it needs the right
		// custom.perm.toggle first).
		return &seqFault{name: name, probe: func(l layer, p *principal, t tgt, lg *leg, o *legOutcome) *legOutcome {
			if l == layerREST && p.kind == pkCustom && t == tA && o.Outcome == Allowed {
				return &legOutcome{Outcome: Denied, Detail: "planted-rare"}
			}
			return o
		}}
	case "common":
		// the same defect on a tuple the first step reaches often:
		// (global admin, role.grant, allow, A)
		return &seqFault{name: name, step: func(l layer, st seqStep, lg *leg, o *legOutcome) *legOutcome {
			if l == layerREST && st.Kind == skGrant && st.Actor == pkGlobalAdmin && st.T == tA && o.Outcome == Allowed {
				return &legOutcome{Outcome: Other, Detail: "planted-500"}
			}
			return o
		}}
	}
	panic("unknown AUTHZNOV_PLANT " + name)
}

// FuzzAuthzSeqNov is FuzzAuthzSeq with tuple observation, an optional planted
// defect (AUTHZNOV_PLANT=rare|common) and optional tuple feedback
// (AUTHZNOV_FEED=1). Its triage is FuzzAuthzSeq's.
func FuzzAuthzSeqNov(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0})
	f.Add([]byte{2, 0, 1, 0, 0, 3, 0, 1, 0, 0})
	plant := novPlant(os.Getenv("AUTHZNOV_PLANT"))
	f.Fuzz(func(t *testing.T, data []byte) {
		steps := decodeSeq(data)
		st := newSeqStats()
		fs := runSeq(t, steps, plant, st)
		novObserve(st.tuples)
		if len(fs) == 0 {
			return
		}
		v := seqVerdict(t, steps, plant, nil)
		switch v.kind {
		case seqAlwaysFail, seqCandidate:
			privateSink(v.key, v.min, v.class)
			novLog("F %d %d %d %s\n", time.Now().UnixNano(), os.Getpid(), novExecs.Load(), v.key)
			t.Errorf("finding %s after %d steps", v.key, len(v.min))
		}
	})
}

// TestNovCensus (AUTHZNOV_CENSUS=1 [AUTHZNOV_N=120]): runs N random sequences
// from seeds that no comparison uses and prints how many sequences reached each
// decision tuple. It sizes the tuple space and finds which tuples are rare under
// random generation; it is design input, not a result.
func TestNovCensus(t *testing.T) {
	if os.Getenv("AUTHZNOV_CENSUS") != "1" {
		t.Skip("set AUTHZNOV_CENSUS=1")
	}
	n := 120
	if v := os.Getenv("AUTHZNOV_N"); v != "" {
		_, _ = fmt.Sscan(v, &n)
	}
	hits := map[int]int{}
	for i := 0; i < n; i++ {
		st := newSeqStats()
		runSeq(t, genSeq(rand.New(rand.NewSource(int64(9_000_000+i)))), nil, st)
		seen := map[int]bool{}
		for _, id := range st.tuples {
			seen[id] = true
		}
		for id := range seen {
			hits[id]++
		}
	}
	ids := make([]int, 0, len(hits))
	for id := range hits {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	t.Logf("CENSUS sequences=%d distinct-tuples=%d of %d", n, len(ids), novTuples)
	for _, id := range ids {
		t.Logf("CENSUS %4d seq=%d  %s", id, hits[id], novName(id))
	}
}
