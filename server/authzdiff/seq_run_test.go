package authzdiff

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/server/http/handlers"
)

// seqFault is the planted-defect hook of the self-test: it can rewrite what a
// mutating step or a probe reports on one layer, or skip a call, to prove the
// oracles fire. It lives in the harness, never in production code.
type seqFault struct {
	name   string
	step   func(l layer, st seqStep, lg *leg, o *legOutcome) *legOutcome
	probe  func(l layer, p *principal, t tgt, lg *leg, o *legOutcome) *legOutcome
	skipDo func(l layer, st seqStep) bool // true: do not run the call on this layer, report Allowed
}

func execMutator(tb testing.TB, lg *leg, l layer, call *seqCall, p *principal) *legOutcome {
	tb.Helper()
	switch l {
	case layerCore:
		if call.coreRecordOnly {
			return &legOutcome{NA: "transport-enforced: core leg is state-synced"}
		}
		r := coreOutcome(call.core(actorCtx(context.Background(), p), lg, p))
		return &legOutcome{Outcome: r.Outcome, Detail: r.Detail}
	case layerREST:
		if call.globalHandler {
			routerMu.Lock()
			if _, _, err := handlers.InitCoreHandlers(lg.c); err != nil {
				routerMu.Unlock()
				tb.Fatalf("re-point handler globals: %v", err)
			}
		}
		r := runREST(lg, p, call.rest(), nil)
		if call.globalHandler {
			routerMu.Unlock()
		}
		return &legOutcome{Outcome: r.Outcome, Detail: r.Detail}
	case layerGRPC:
		if call.grpc == nil {
			return &legOutcome{NA: "no gRPC RPC for this step"}
		}
		err := call.grpc(grpcCtx(p), lg)
		if errors.Is(err, errLayerAbsent) {
			return &legOutcome{NA: "gRPC cannot express this scope"}
		}
		r := grpcOutcome(err)
		return &legOutcome{Outcome: r.Outcome, Detail: r.Detail}
	}
	return &legOutcome{NA: "unknown layer"}
}

func execRead(lg *leg, l layer, spec opSpec, p *principal, t tgt) *legOutcome {
	switch l {
	case layerCore:
		err := spec.core(actorCtx(context.Background(), p), lg, p, t, 0)
		if errors.Is(err, errNotAuthzLayer) {
			return &legOutcome{NA: "core leg is not an authorization layer for a machine"}
		}
		r := coreOutcome(err)
		return &legOutcome{Outcome: r.Outcome, Detail: r.Detail}
	case layerREST:
		r := runREST(lg, p, spec.rest(lg.fx, t, 0), nil)
		if r.Detail == "Too Many Requests" {
			seqRateLimited.Add(1)
			return &legOutcome{NA: "invalid-token rate limiter"}
		}
		return &legOutcome{Outcome: r.Outcome, Detail: r.Detail}
	case layerGRPC:
		r := grpcOutcome(spec.grpc(grpcCtx(p), lg, t, 0))
		if r.Detail == "ResourceExhausted" {
			seqRateLimited.Add(1)
			return &legOutcome{NA: "invalid-token rate limiter"}
		}
		return &legOutcome{Outcome: r.Outcome, Detail: r.Detail}
	}
	return &legOutcome{NA: "unknown layer"}
}

// seqRateLimited counts probes that hit the per-IP invalid-token limiter (a
// process-global token bucket, 1/s refill, keyed by the constant bufconn / test
// peer). Such a probe says nothing about authorisation and is recorded as n/a.
var seqRateLimited atomic.Int64

var (
	invalidProbeMu   sync.Mutex
	invalidProbeLast time.Time
)

// throttleInvalidTokenProbe spaces probes that send a token the server rejects
// (a suspended principal's) so the limiter budget is not what the probe measures.
func throttleInvalidTokenProbe() {
	invalidProbeMu.Lock()
	defer invalidProbeMu.Unlock()
	if d := time.Until(invalidProbeLast.Add(1100 * time.Millisecond)); d > 0 {
		time.Sleep(d)
	}
	invalidProbeLast = time.Now()
}

// dynPrincipal returns p with its suspended flag read from the leg's database
// (the single-step fixtures are static; in a sequence the state moves).
func dynPrincipal(db *gorm.DB, p *principal) *principal {
	q := *p
	if p.userID != 0 {
		var s string
		db.Raw(`SELECT account_state FROM users WHERE id = ?`, p.userID).Scan(&s)
		q.suspended = s != "" && s != "active"
	}
	return &q
}

func readSpecs(tb testing.TB) []opSpec {
	var out []opSpec
	for _, s := range withDerived(tb, ops()) {
		if s.name == "secret.value.byref" || s.name == "secret.value.byid" {
			out = append(out, s)
		}
	}
	if len(out) != 2 {
		tb.Fatalf("value-read ops not found (%d)", len(out))
	}
	return out
}

type seqFinding struct {
	Step  int    // step after which it was seen (-1: before any step)
	Class string // e.g. "O-P:over-denial(...)"
}

type seqStats struct {
	kindAllowed, kindDenied map[seqKind]int
	steps, probes           int
}

func newSeqStats() *seqStats {
	return &seqStats{kindAllowed: map[seqKind]int{}, kindDenied: map[seqKind]int{}}
}

// probeAll runs O-P on the current state of all three legs.
func (w *seqWorld) probeAll(tb testing.TB, specs []opSpec, step int, f *seqFault, stats *seqStats, suspToo bool) []seqFinding {
	var out []seqFinding
	for _, pk := range seqProbes {
		susp := dynPrincipal(w.legs[layerCore].db, w.p(layerCore, pk)).suspended
		if susp && !suspToo {
			continue // its token is rejected: one probe per account-state change, throttled below
		}
		for _, t := range projTargets {
			for _, spec := range specs {
				if susp && (t != tA || spec.name != "secret.value.byref") {
					continue
				}
				if susp {
					throttleInvalidTokenProbe()
				}
				legs := map[layer]*legOutcome{}
				for _, l := range seqLayers {
					if susp && l == layerCore {
						// account state is enforced by the transports (account_state.go);
						// core's read path takes a user id and does not look at it
						legs[l] = &legOutcome{NA: "account state is transport-enforced"}
						continue
					}
					lo := execRead(w.legs[l], l, spec, w.p(l, pk), t)
					if f != nil && f.probe != nil && lo.NA == "" {
						lo = f.probe(l, w.p(l, pk), t, w.legs[l], lo)
					}
					legs[l] = lo
				}
				stats.probes++
				var allow, deny []string
				for _, l := range seqLayers {
					lo := legs[l]
					if lo.NA != "" || (l == layerCore && !spec.coreEnforced) {
						continue
					}
					switch lo.Outcome {
					case Allowed:
						allow = append(allow, string(l))
					case Denied:
						deny = append(deny, string(l))
					}
				}
				tag := fmt.Sprintf("%s@%s/%s", pk, t, spec.name)
				if len(allow) > 0 && len(deny) > 0 {
					out = append(out, seqFinding{step, fmt.Sprintf("O-P:layers-disagree(%s;allow=%s;deny=%s)", tag, strings.Join(allow, "+"), strings.Join(deny, "+"))})
				}
				for _, l := range seqLayers {
					lo := legs[l]
					if lo.NA != "" || (l == layerCore && !spec.coreEnforced) {
						continue
					}
					lg := w.legs[l]
					want := Denied
					if (model{lg.db}).allowed(dynPrincipal(lg.db, w.p(l, pk)), spec.req(lg.fx, t, 0)) {
						want = Allowed
					}
					switch {
					case lo.Outcome == Allowed && want == Denied:
						out = append(out, seqFinding{step, fmt.Sprintf("O-P:allowed-but-model-denies(%s;%s)", tag, l)})
					case lo.Outcome == Denied && want == Allowed:
						out = append(out, seqFinding{step, fmt.Sprintf("O-P:over-denial(%s;%s)", tag, l)})
					case lo.Outcome == Other:
						out = append(out, seqFinding{step, fmt.Sprintf("O-P:other(%s;%s;%s)", tag, l, lo.Detail)})
					}
				}
			}
		}
	}
	return out
}

// runSeq executes steps and returns every finding in order. It stops at the
// first step whose layers disagree (the worlds diverge from there) and does not
// run at all when the baseline (before any step) already has a finding.
func runSeq(tb testing.TB, steps []seqStep, f *seqFault, stats *seqStats) []seqFinding {
	tb.Helper()
	if stats == nil {
		stats = newSeqStats()
	}
	w := newSeqWorld(tb)
	defer w.close()
	specs := readSpecs(tb)
	findings := w.probeAll(tb, specs, -1, f, stats, seqFirstBaseline())
	if len(findings) > 0 {
		return findings
	}
	admin := w.fx.principals[pkGlobalAdmin]
	for i, st := range steps {
		stats.steps++
		if st.Kind == skPermToggle || st.Kind == skExpire {
			w.applyStateStep(tb, st)
			stats.kindAllowed[st.Kind]++ // always applies; counted so coverage lists every kind
			findings = append(findings, w.probeAll(tb, specs, i, f, stats, false)...)
			continue
		}
		call := buildCall(tb, w.fx, st)
		p := w.fx.principals[st.Actor] // userID and kind only; per-layer tokens below
		before := map[layer]string{}
		// The #4020 precondition on the pre-step state of every leg: the step's
		// effect already holds before it runs (a revoke's grant is absent, a
		// grant's is present). A step with no effect check never qualifies.
		preKnown := call.effect != nil
		for _, l := range seqLayers {
			before[l] = authzSnapshot(w.legs[l].db)
			if preKnown {
				if ok, _ := call.effect(w.legs[l].db); !ok {
					preKnown = false
				}
			}
		}
		modelWant := ModelNA
		if call.req != nil {
			lg := w.legs[layerCore]
			modelWant = Denied
			if (model{lg.db}).allowed(dynPrincipal(lg.db, p), *call.req) {
				modelWant = Allowed
			}
		}
		outs := map[layer]*legOutcome{}
		for _, l := range seqLayers {
			lg := w.legs[l]
			if f != nil && f.skipDo != nil && f.skipDo(l, st) {
				outs[l] = &legOutcome{Outcome: Allowed, Detail: "planted-noop"}
				continue
			}
			o := execMutator(tb, lg, l, call, w.p(l, st.Actor))
			if f != nil && f.step != nil && o.NA == "" {
				o = f.step(l, st, lg, o)
			}
			outs[l] = o
		}
		var allow, deny, other []string
		for _, l := range seqLayers {
			if outs[l].NA != "" {
				continue
			}
			switch outs[l].Outcome {
			case Allowed:
				allow = append(allow, string(l))
			case Denied:
				deny = append(deny, string(l))
			default:
				other = append(other, string(l))
			}
		}
		tag := st.String()
		if len(allow) > 0 && len(deny) > 0 {
			findings = append(findings, seqFinding{i, fmt.Sprintf("O-S:layers-disagree(%s;allow=%s;deny=%s)", tag, strings.Join(allow, "+"), strings.Join(deny, "+"))})
			return findings
		}
		consensus := Other
		if len(allow) > 0 {
			consensus = Allowed
			stats.kindAllowed[st.Kind]++
		} else if len(deny) > 0 {
			consensus = Denied
			stats.kindDenied[st.Kind]++
		}
		if modelWant != ModelNA && consensus != Other && consensus != modelWant {
			findings = append(findings, seqFinding{i, fmt.Sprintf("O-S:step-vs-model(%s;got=%s;model=%s)", tag, consensus, modelWant)})
		}
		// Keep the worlds in step: a leg that could not run the call (no gRPC RPC,
		// transport-enforced core) mirrors an allowed consensus through core.
		if consensus == Allowed {
			for _, l := range seqLayers {
				if outs[l].NA != "" {
					_ = call.core(actorCtx(context.Background(), admin), w.legs[l], admin)
				}
			}
		}
		// Suspension revokes the user's sessions (session_eviction.go); a
		// reactivated user logs in again. That is the intended flow, so the
		// harness does it, and a failed login after reactivation is a finding.
		if consensus == Allowed && st.Kind == skReactivate {
			for _, l := range seqLayers {
				if !w.login(l, st.Subject) {
					findings = append(findings, seqFinding{i, fmt.Sprintf("O-E:reactivated-user-cannot-log-in(%s;%s)", tag, l)})
				}
			}
		}
		// A leg that answered Other is a finding of its own. It is O-S:other (always
		// fails) when a transport answered a server error (5xx, gRPC Internal, ...),
		// and O-S:other-client when every transport that answered Other gave a
		// client error (4xx, InvalidArgument, AlreadyExists, ...). When the model
		// denies the step, the other legs denied it, no leg allowed it and no
		// transport answered a server error, or it is a known-open tolerance, it
		// must also have left the state untouched.
		serverErr := false
		for _, l := range other {
			if layer(l) != layerCore && !isClientError(layer(l), outs[layer(l)]) {
				serverErr = true
			}
		}
		known := serverErr && knownSeqOther(st, outs, modelWant, preKnown)
		if len(other) > 0 && !(len(allow) == 0 && len(deny) == 0 && grantAlreadyHeldConflict(st, outs, preKnown)) {
			kind := "O-S:other"
			switch {
			case known:
				kind = seqKnownOtherKind
			case !serverErr:
				kind = "O-S:other-client"
			}
			findings = append(findings, seqFinding{i, fmt.Sprintf("%s(%s;other=%s;got=%s;model=%s)", kind, tag, strings.Join(other, "+"), consensus, modelWant)})
		}
		mustNotChange := consensus == Denied || (len(other) > 0 && consensus == Other && (modelWant == Denied || !serverErr)) || known
		for _, l := range seqLayers {
			lg := w.legs[l]
			switch {
			case mustNotChange && authzSnapshot(lg.db) != before[l]:
				findings = append(findings, seqFinding{i, fmt.Sprintf("O-E:denied-step-changed-state(%s;%s)", tag, l)})
			case consensus == Allowed && call.effect != nil:
				if ok, why := call.effect(lg.db); !ok {
					findings = append(findings, seqFinding{i, fmt.Sprintf("O-E:%s(%s;%s)", why, tag, l)})
				}
			}
		}
		if len(other) > 0 {
			return findings // the legs may have diverged; later steps would compare different worlds
		}
		findings = append(findings, w.probeAll(tb, specs, i, f, stats, st.Kind == skSuspend || st.Kind == skReactivate)...)
	}
	return findings
}

// grantAlreadyHeldConflict reports the by-design answer to a grant the subject
// already holds on every leg (preKnown): every transport refuses it as a conflict
// (REST 409, gRPC AlreadyExists, the same since #4020) and core reports its typed
// refusal. That is not a finding; the step must still leave the state unchanged
// (mustNotChange holds for it). Any other kind, a leg missing, a different detail
// or a grant that was not already held stays O-S:other-client.
func grantAlreadyHeldConflict(st seqStep, outs map[layer]*legOutcome, preKnown bool) bool {
	if st.Kind != skGrant || !preKnown {
		return false
	}
	want := map[layer]string{layerREST: http.StatusText(http.StatusConflict), layerGRPC: codes.AlreadyExists.String()}
	for l, detail := range want {
		if o := outs[l]; o == nil || o.NA != "" || o.Outcome != Other || o.Detail != detail {
			return false
		}
	}
	o := outs[layerCore]
	return o != nil && (o.NA != "" || o.Outcome == Other)
}

// isClientError reports whether a transport's Other answer is the caller's to
// fix (a 4xx, or a gRPC code with that meaning). Anything else a transport
// answers as Other, including an unknown detail, is a server error. Core is not
// classified: it maps errors by identity only, and its untyped bucket mixes
// validation errors with the mapping gaps of the single-step harness.
func isClientError(l layer, o *legOutcome) bool {
	if o == nil || o.Outcome != Other || o.Detail == "" {
		return false
	}
	switch l {
	case layerREST:
		for c := 400; c < 500; c++ {
			if o.Detail == http.StatusText(c) {
				return true
			}
		}
	case layerGRPC:
		switch o.Detail {
		case codes.InvalidArgument.String(), codes.AlreadyExists.String(), codes.FailedPrecondition.String(), codes.OutOfRange.String():
			return true
		}
	}
	return false
}

// seqKnownOtherKind is the class of a step that matches knownSeqOthers.
const seqKnownOtherKind = "O-S:known-other-4020"

// isKnownOpen reports whether a finding class is a known-open tolerance (#4020).
func isKnownOpen(c string) bool { return classKind(c) == seqKnownOtherKind }

// knownSeqOthers are known-open O-S:other signatures: a server error on one leg
// that a filed issue already tracks. A row matches only a step of its kind that
// the model allows, with exactly its outcomes and details on every leg (core nil:
// the core leg did not run), and only when the step's effect was already true
// before it ran on every leg (preKnown). runSeq still requires the state
// unchanged on every leg. Add a row only with its issue; remove it in the PR
// that fixes the issue.
//
// Empty: the #4020 rows (gRPC RemoveRole of a grant not held and AssignRole of
// one held answered Internal, REST 404 / 409) were removed when mapRoleError
// learned storage.ErrRoleNotAssigned / ErrRoleAlreadyAssigned
// (TestSeq4020IsFixedWithoutATolerance).
var knownSeqOthers []struct {
	kind             seqKind
	core, rest, grpc *legOutcome
}

func knownSeqOther(st seqStep, outs map[layer]*legOutcome, modelWant Outcome, preKnown bool) bool {
	if modelWant != Allowed || !preKnown {
		return false
	}
	same := func(got, want *legOutcome) bool {
		if want == nil {
			return got != nil && got.NA != ""
		}
		return got != nil && got.NA == "" && got.Outcome == want.Outcome && got.Detail == want.Detail
	}
	for _, k := range knownSeqOthers {
		if st.Kind == k.kind && same(outs[layerCore], k.core) && same(outs[layerREST], k.rest) && same(outs[layerGRPC], k.grpc) {
			return true
		}
	}
	return false
}

// classKind is a finding's class up to the first "(", e.g. "O-P:over-denial".
func classKind(c string) string {
	if before, _, ok := strings.Cut(c, "("); ok {
		return before
	}
	return c
}

// classKey is the class with the direction kept and the step or probe tag
// dropped: "O-S:step-vs-model(<tag>;got=allowed;model=denied)" becomes
// "O-S:step-vs-model(got=allowed;model=denied)". Two findings with the same
// kind but opposite directions (a transport allowing versus denying) have
// different keys, so one direction's known noise never absorbs the other.
func classKey(c string) string {
	before, rest, ok := strings.Cut(c, "(")
	if !ok {
		return c
	}
	_, dir, _ := strings.Cut(strings.TrimSuffix(rest, ")"), ";")
	return before + "(" + dir + ")"
}

// isOverAllow reports whether a finding class means a transport allowed what the
// model (or another leg, or the state) says must be denied. Such a class is never
// single-step noise: it always fails. Only core allowing alone is not an
// over-allow, because core is not a transport and some of its operations leave
// the check to the transport.
func isOverAllow(c string) bool {
	switch classKind(c) {
	case "O-P:allowed-but-model-denies", "O-E:denied-step-changed-state":
		return true
	case "O-S:step-vs-model":
		return strings.Contains(c, "got=allowed;model=denied")
	case "O-S:layers-disagree", "O-P:layers-disagree":
		_, rest, _ := strings.Cut(c, ";allow=")
		allow, _, _ := strings.Cut(rest, ";")
		return strings.Contains(allow, string(layerREST)) || strings.Contains(allow, string(layerGRPC))
	}
	return false
}

// alwaysFails reports whether a finding class fails the run however it
// reproduces: it is never absorbed as single-step noise. That is every
// over-allow, every O-E intent class (a revocation, suspension or membership
// change that did not take effect: the model reads the same tables, so only O-E
// sees it, and the single-step harness has no effect oracle) and O-S:other (a
// step that ended in a 5xx or an untyped error).
func alwaysFails(c string) bool {
	if isOverAllow(c) {
		return true
	}
	k := classKind(c)
	return strings.HasPrefix(k, "O-E:") || k == "O-S:other"
}

// pickFinding is the finding to report and shrink: the first over-allow one if
// there is any, else the first one that always fails, else the first that is
// not a known-open tolerance, else the first.
func pickFinding(fs []seqFinding) seqFinding {
	for _, f := range fs {
		if isOverAllow(f.Class) {
			return f
		}
	}
	for _, f := range fs {
		if alwaysFails(f.Class) {
			return f
		}
	}
	for _, f := range fs {
		if !isKnownOpen(f.Class) {
			return f
		}
	}
	return fs[0]
}

// hasKey reports whether any finding has the class key.
func hasKey(fs []seqFinding, key string) bool {
	return slices.ContainsFunc(fs, func(f seqFinding) bool { return classKey(f.Class) == key })
}

// isSingleStep reports whether the failing step alone, from a fresh world (with
// the same planted fault, if any), reproduces the same direction-bearing class.
// A class that always fails is never single-step.
func isSingleStep(tb testing.TB, steps []seqStep, f seqFinding, fault *seqFault) bool {
	if alwaysFails(f.Class) {
		return false
	}
	if f.Step < 0 || f.Step >= len(steps) {
		return false
	}
	return hasKey(runSeq(tb, steps[f.Step:f.Step+1], fault, nil), classKey(f.Class))
}

// seqVerdictKind is how one sequence's findings are triaged.
type seqVerdictKind int

const (
	seqClean      seqVerdictKind = iota // no finding
	seqSingleStep                       // the failing step alone reproduces the class: covered by the single-step harness
	seqAlwaysFail                       // a class that always fails (alwaysFails)
	seqCandidate                        // a class only the sequence shows: sequence-dependent candidate
	seqKnown                            // only known-open tolerances (#4020), in any sequence position
)

type seqTriage struct {
	kind  seqVerdictKind
	key   string    // classKey of the reported finding
	class string    // the reported finding's full class (private file only)
	min   []seqStep // the shrunk sequence (nil for a clean or cheap single-step verdict)
}

// fail reports whether the verdict fails a fuzz run or a sweep.
func (v seqTriage) fail() bool { return v.kind == seqAlwaysFail || v.kind == seqCandidate }

// seqShrinkBudget bounds the runs shrink spends on one sequence.
const seqShrinkBudget = 40

// seqVerdict runs steps (with the planted fault, if any) and triages the
// findings. It is the one triage FuzzAuthzSeq, the sweep and the plant tests use.
// Cheap first: if the failing step alone reproduces the class it is single-step
// and needs no shrinking. Otherwise the sequence is shrunk and re-triaged. A class
// that always fails fails even when the shrunk replay comes back clean.
func seqVerdict(tb testing.TB, steps []seqStep, fault *seqFault, stats *seqStats) seqTriage {
	tb.Helper()
	fs := runSeq(tb, steps, fault, stats)
	if len(fs) == 0 {
		return seqTriage{kind: seqClean}
	}
	top := pickFinding(fs)
	if isKnownOpen(top.Class) {
		// pickFinding returns a known-open finding only when every finding is one;
		// it is the step's own outcome signature, whatever the steps before it
		return seqTriage{kind: seqKnown, key: classKey(top.Class), class: top.Class}
	}
	if isSingleStep(tb, steps, top, fault) {
		return seqTriage{kind: seqSingleStep, key: classKey(top.Class), class: top.Class}
	}
	min := shrink(tb, steps, fault, seqShrinkBudget)
	if mfs := runSeq(tb, min, fault, nil); len(mfs) > 0 {
		top = pickFinding(mfs)
	} else if !alwaysFails(top.Class) {
		return seqTriage{kind: seqClean}
	} else {
		min = steps
	}
	v := seqTriage{key: classKey(top.Class), class: top.Class, min: min}
	switch {
	case alwaysFails(top.Class):
		v.kind = seqAlwaysFail
	case isKnownOpen(top.Class):
		v.kind = seqKnown
	case len(min) == 1 || isSingleStep(tb, min, top, fault):
		v.kind = seqSingleStep
	default:
		v.kind = seqCandidate
	}
	return v
}

// shrink removes steps while a finding of the same class survives.
func shrink(tb testing.TB, steps []seqStep, f *seqFault, budget int) []seqStep {
	fs := runSeq(tb, steps, f, nil)
	if len(fs) == 0 {
		return steps
	}
	target := classKey(pickFinding(fs).Class)
	cur := slices.Clone(steps)
	for budget > 0 {
		progressed := false
		for i := range cur {
			cand := slices.Delete(slices.Clone(cur), i, i+1)
			budget--
			got := runSeq(tb, cand, f, nil)
			if hasKey(got, target) {
				cur = cand
				progressed = true
				break
			}
			if budget <= 0 {
				break
			}
		}
		if !progressed {
			break
		}
	}
	return cur
}

func describe(steps []seqStep) string {
	var b strings.Builder
	for i, s := range steps {
		fmt.Fprintf(&b, "  %d. %s\n", i+1, s)
	}
	return b.String()
}

var seqBaselineOnce sync.Once

// seqFirstBaseline is true once per process: the static suspended fixture is
// probed at the first baseline only (throttled), not at every sequence's.
func seqFirstBaseline() bool {
	first := false
	seqBaselineOnce.Do(func() { first = true })
	return first
}
