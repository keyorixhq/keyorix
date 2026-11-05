package authzdiff

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Drivers.
//
//   - TestAuthzDiffSmoke (default go test): every op, its first target, as the
//     global admin and the no-role principal. Fails if an op's admin positive
//     control is not "allowed" on any layer it claims (a broken op definition
//     must be loud, never a silently empty oracle).
//   - TestAuthzDiffSweep (AUTHZDIFF_SWEEP=1): the exhaustive sweep — every op x
//     target x arg x (named principals + the GENERATED permission sets of
//     genVariations). Records every case to $AUTHZDIFF_OUT and logs every
//     flagged case with its partition bucket. AUTHZDIFF_STRICT=1 fails on any
//     case partition_test.go cannot explain (known findings D1-D4/M1-M3 are
//     listed in REPORT.md and accepted; a new defect lands in "unexplained").
//     AUTHZDIFF_OPS=a,b restricts the op set (used by the plant self-test).
//   - FuzzAuthzDiff: the same case space, chosen by the fuzzer.

// requirementPerms is R for one (op, target, arg): the op's gate permissions
// plus every permission of every role it grants (the ceiling), read from the
// leg's database. The custom role itself is excluded from the ceiling part —
// its permissions ARE the variation, so including them would be circular.
func requirementPerms(lg *leg, spec opSpec, t tgt, a byte) []string {
	req := spec.req(lg.fx, t, a)
	set := map[string]bool{}
	for _, p := range req.perms {
		set[p] = true
	}
	for _, r := range req.ceiling {
		if r.roleID == lg.fx.customRoleID {
			continue
		}
		perms, _ := (model{lg.db}).rolePerms(r.roleID)
		for _, p := range perms {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func maskOf(perms []string) uint16 {
	var m uint16
	for _, p := range perms {
		if i := slices.Index(customPermUniverse, p); i >= 0 {
			m |= 1 << i
		}
	}
	return m
}

func maskNames(m uint16) string {
	var out []string
	for i, p := range customPermUniverse {
		if m&(1<<i) != 0 {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return "{}"
	}
	return "{" + strings.Join(out, ",") + "}"
}

// genMasks derives the permission sets for requirement R over universe U:
//
//	R                      — the positive case
//	R \ {p}                — leave-one-out, for each p in R
//	R \ {p} ∪ {d}          — leave-one-out plus one distractor d in U \ R
//	U \ {p}                — everything but p
//	{q}                    — each single permission q in U
//	{}                     — nothing
//
// Each p in R therefore has many principals that hold "everything relevant
// except p": a gate that stops checking p is visible to all of them, not to
// one hand-picked principal.
func genMasks(R []string) []uint16 {
	r := maskOf(R)
	seen := map[uint16]bool{}
	var out []uint16
	add := func(m uint16) {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	add(r)
	add(0)
	for i := range customPermUniverse {
		bit := uint16(1) << i
		add(bit)
		if r&bit == 0 {
			continue
		}
		loo := r &^ bit
		add(loo)
		add(allPerms &^ bit)
		for j := range customPermUniverse {
			d := uint16(1) << j
			if r&d == 0 {
				add(loo | d)
			}
		}
	}
	return out
}

// genScopes: the op's own scope, the other project, and global.
func genScopes(t tgt) []string {
	switch t {
	case tA:
		return []string{"A", "B", "global"}
	case tB:
		return []string{"B", "A", "global"}
	}
	return []string{"global", "A"}
}

// genVariations crosses genMasks(R) with every grant route and scope.
func genVariations(R []string, t tgt) []struct {
	pk principalKind
	v  variation
} {
	var out []struct {
		pk principalKind
		v  variation
	}
	for _, m := range genMasks(R) {
		for _, s := range genScopes(t) {
			out = append(out,
				struct {
					pk principalKind
					v  variation
				}{pkCustom, variation{m, "user", s}},
				struct {
					pk principalKind
					v  variation
				}{pkCustom, variation{m, "group", s}})
			if s != "global" {
				out = append(out, struct {
					pk principalKind
					v  variation
				}{pkMachine, variation{m, "machine", s}})
			}
		}
	}
	return out
}

func argsFor(spec opSpec) []byte {
	if spec.secretArgs {
		return []byte{0, 1, 2, 3}
	}
	if spec.grantArgs {
		return []byte{0, 1, 2, 3}
	}
	return []byte{0}
}

func TestAuthzDiffSmoke(t *testing.T) {
	specs := withDerived(t, ops())
	for _, spec := range specs {
		t.Run(spec.name, func(t *testing.T) {
			tg := spec.targets[0]
			for _, l := range []layer{layerCore, layerREST, layerGRPC} {
				c := control(t, spec, l, tg, 0)
				if c.NA == "" && c.Outcome != Allowed {
					t.Errorf("admin positive control on %s: %s (%s) — op definition broken for this layer", l, c.Outcome, c.Detail)
				}
			}
			r := runCase(t, spec, caseKey{Op: spec.name, Principal: pkNone, Target: tg.String(), variation: defaultVariation}, tg)
			sink.write(r)
			t.Log(r.line())
		})
	}
}

// TestRequirementsWithinUniverse: every permission an op requires (gate or
// ceiling) must be expressible by the generator, or the leave-one-out sets
// for it silently do not exist.
func TestRequirementsWithinUniverse(t *testing.T) {
	for _, spec := range withDerived(t, ops()) {
		lg := newLeg(t, layerCore)
		defer lg.close()
		for _, tg := range spec.targets {
			for _, a := range argsFor(spec) {
				for _, p := range requirementPerms(lg, spec, tg, a) {
					if !slices.Contains(customPermUniverse, p) {
						t.Errorf("%s target=%s arg=%d requires %q, which is not in customPermUniverse", spec.name, tg, a, p)
					}
				}
			}
		}
	}
}

type sweepTally struct {
	mu                     sync.Mutex
	n, dis                 int
	disBuckets, gapBuckets map[string]int
}

func (s *sweepTally) add(t *testing.T, r *caseResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	switch {
	case r.disagreement():
		s.dis++
		s.disBuckets[r.Bucket]++
		t.Log("DISAGREEMENT [" + r.Bucket + "] " + r.line())
	case r.Bucket != "":
		s.gapBuckets[r.Bucket]++
		if r.Bucket == "unexplained" {
			t.Log("UNEXPLAINED " + r.line())
		}
	}
}

func TestAuthzDiffSweep(t *testing.T) {
	if os.Getenv("AUTHZDIFF_SWEEP") == "" {
		t.Skip("set AUTHZDIFF_SWEEP=1 for the exhaustive sweep (long)")
	}
	only := os.Getenv("AUTHZDIFF_OPS")
	strict := os.Getenv("AUTHZDIFF_STRICT") != ""
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	t.Cleanup(func() {
		t.Logf("sweep: %d cases, %d with an O1/O2 class", tally.n, tally.dis)
		t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
		t.Logf("partition of mapping-gap-only cases: %v", tally.gapBuckets)
		if strict && (tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0) {
			t.Error("unexplained cases present (AUTHZDIFF_STRICT)")
		}
	})
	_, fx := template(t)
	for _, spec := range familyOrder(t, withDerived(t, ops())) {
		if only != "" && !strings.Contains(","+only+",", ","+spec.name+",") {
			continue
		}
		t.Run(spec.name, func(t *testing.T) {
			t.Parallel()
			probe := newLeg(t, layerCore)
			defer probe.close()
			for _, tg := range spec.targets {
				for _, arg := range argsFor(spec) {
					run := func(pk principalKind, v variation) {
						k := caseKey{Op: spec.name, Principal: pk, Target: tg.String(), Arg: arg, variation: v}
						r := runCase(t, spec, k, tg)
						sink.write(r)
						tally.add(t, r)
					}
					for _, pk := range namedPrincipalKinds {
						run(pk, defaultVariation)
					}
					for _, g := range genVariations(requirementPerms(probe, spec, tg, arg), tg) {
						run(g.pk, g.v)
					}
				}
			}
		})
	}
	_ = fx
}

func FuzzAuthzDiff(f *testing.F) {
	f.Add(byte(0), byte(4), byte(0), byte(0), uint16(0xff), byte(0), byte(0))
	f.Add(byte(12), byte(4), byte(1), byte(1), uint16(0x80), byte(1), byte(2))
	f.Fuzz(func(t *testing.T, opSel, pSel, tSel, arg byte, mask uint16, routeSel, scopeSel byte) {
		specs := withDerived(t, ops())
		spec := specs[int(opSel)%len(specs)]
		tg := spec.targets[int(tSel)%len(spec.targets)]
		pk := allPrincipalKinds[int(pSel)%len(allPrincipalKinds)]
		v := defaultVariation
		if pk == pkCustom || pk == pkMachine {
			scopes := genScopes(tg)
			s := scopes[int(scopeSel)%len(scopes)]
			route := []string{"user", "group"}[int(routeSel)%2]
			if pk == pkMachine {
				route = "machine"
				if s == "global" {
					s = "A"
				}
			}
			v = variation{Mask: mask & allPerms, Route: route, Scope: s}
		}
		k := caseKey{Op: spec.name, Principal: pk, Target: tg.String(), Arg: arg % 4, variation: v}
		r := runCase(t, spec, k, tg)
		sink.write(r)
		if r.Bucket != "" {
			t.Log(fmt.Sprintf("FLAGGED [%s] %s", r.Bucket, r.line()))
			if r.Bucket == "unexplained" && os.Getenv("AUTHZDIFF_STRICT") != "" {
				t.Fail()
			}
		}
	})
}
