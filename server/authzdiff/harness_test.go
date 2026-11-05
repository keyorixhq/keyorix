package authzdiff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/metadata"

	"github.com/keyorixhq/keyorix/internal/core"
)

// Case = one (op, principal, target, op-arg, custom-role variation).
type caseKey struct {
	Op        string        `json:"op"`
	Principal principalKind `json:"principal"`
	Target    string        `json:"target"`
	Arg       byte          `json:"arg"`
	variation
}

type legOutcome struct {
	Outcome Outcome `json:"outcome,omitempty"`
	Detail  string  `json:"detail,omitempty"`
	NA      string  `json:"na,omitempty"` // why this layer did not take part
}

type caseResult struct {
	caseKey
	Model Outcome `json:"model"`
	// Counterfactual model decisions, so a partition rule can name the exact
	// missing condition (explain): the model with users.read dropped from the
	// requirement (D1), and with the account active (D5). Empty when Model is
	// ModelNA.
	ModelSansUsersRead Outcome               `json:"model_sans_users_read,omitempty"`
	ModelIfActive      Outcome               `json:"model_if_active,omitempty"`
	Legs               map[layer]*legOutcome `json:"legs"`
	Classes            []string              `json:"classes,omitempty"`
	Bucket             string                `json:"bucket,omitempty"` // partition_test.go explain()
	// PATUngatedWrite: the principal is a restricted PAT and the op's route is
	// in core's restricted-PAT ungated-write table (ADR-042, PAT-GUARD-3).
	PATUngatedWrite bool `json:"pat_ungated_write,omitempty"`
}

// ---------- matrix-derived facts ----------

var (
	matrixOnce sync.Once
	matrixRef  map[string]string // core entry -> core_refusal
)

func coreRefusal(tb testing.TB, row string) string {
	matrixOnce.Do(func() {
		b, err := os.ReadFile("matrix.json")
		if err != nil {
			return
		}
		var m struct {
			Rows []struct {
				Core        string `json:"core"`
				CoreRefusal string `json:"core_refusal"`
			} `json:"rows"`
		}
		if json.Unmarshal(b, &m) == nil {
			matrixRef = map[string]string{}
			for _, r := range m.Rows {
				matrixRef[r.Core] = r.CoreRefusal
			}
		}
	})
	r, ok := matrixRef[row]
	if !ok {
		tb.Fatalf("op row %q not in matrix.json — regenerate MATRIX or fix the op table", row)
	}
	return r
}

func withDerived(tb testing.TB, specs []opSpec) []opSpec {
	for i := range specs {
		specs[i].coreEnforced = coreRefusal(tb, specs[i].row) != "none"
	}
	return specs
}

// ---------- legs ----------

func runREST(lg *leg, p *principal, rr restReq, okIf func([]byte) bool) result {
	var body bytes.Buffer
	if rr.body != nil {
		_ = json.NewEncoder(&body).Encode(rr.body)
	}
	req := httptest.NewRequest(rr.method, rr.path, &body)
	if rr.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	rec := httptest.NewRecorder()
	lg.router.ServeHTTP(rec, req)
	r := restOutcome(rec.Code, rec.Body.String())
	if r.Outcome == Allowed && okIf != nil && !okIf(rec.Body.Bytes()) {
		// a 2xx whose body reports the item itself was refused (bulk ops answer
		// 200 with per-item failures): the effect did not happen.
		return result{Denied, "2xx-item-refused"}
	}
	return r
}

func grpcCtx(p *principal) context.Context {
	return metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+p.token))
}

// runLayer runs one leg of one case on its own fresh world and maps it.
// modelOut, when non-nil, receives the model's decisions (Model and its
// counterfactuals) computed on THIS world after the variation and BEFORE the
// op runs.
func runLayer(tb testing.TB, spec opSpec, l layer, p *principal, k caseKey, t tgt, modelOut *caseResult) *legOutcome {
	tb.Helper()
	lg := newLeg(tb, l)
	defer lg.close()
	lg.applyVariation(tb, k.variation)
	if modelOut != nil {
		decide := func(p *principal, req requirement) Outcome {
			if (model{lg.db}).allowed(p, req) && !patRefusesUngatedWrite(tb, lg.fx, spec, p) {
				return Allowed
			}
			return Denied
		}
		if spec.secretArgs && k.Arg != 0 {
			modelOut.Model = ModelNA // owner/share/ACL fixture: outside the model's domain
		} else {
			req := spec.req(lg.fx, t, k.Arg)
			modelOut.Model = decide(p, req)
			modelOut.ModelSansUsersRead = decide(p, withoutPerm(req, "users.read"))
			active := *p
			active.suspended = false
			modelOut.ModelIfActive = decide(&active, req)
		}
	}
	switch l {
	case layerCore:
		if spec.core == nil {
			return &legOutcome{NA: "no core leg (core method takes no actor)"}
		}
		ctx := actorCtx(context.Background(), p)
		if spec.selfMachineGranter && p.isMachine() {
			ctx = core.WithSelfMachineGranter(ctx, p.machineID)
		}
		err := spec.core(ctx, lg, p, t, k.Arg)
		if errors.Is(err, errNotAuthzLayer) {
			return &legOutcome{NA: "transport calls a non-checking core method for this principal"}
		}
		if errors.Is(err, errItemRefused) {
			return &legOutcome{Outcome: Denied, Detail: "item-refused"}
		}
		r := coreOutcome(err)
		return &legOutcome{Outcome: r.Outcome, Detail: r.Detail}
	case layerREST:
		if p.coreOnly() {
			return &legOutcome{NA: "ID-1: no credential exists for actor 0"}
		}
		var okIf func([]byte) bool
		if spec.restOK != nil {
			okIf = func(b []byte) bool { return spec.restOK(b, lg.fx, t) }
		}
		r := runREST(lg, p, spec.rest(lg.fx, t, k.Arg), okIf)
		return &legOutcome{Outcome: r.Outcome, Detail: r.Detail}
	case layerGRPC:
		if spec.grpc == nil {
			return &legOutcome{NA: "ID-3: no gRPC RPC (ADR-105 partial surface)"}
		}
		if p.coreOnly() {
			return &legOutcome{NA: "ID-1: no credential exists for actor 0"}
		}
		err := spec.grpc(grpcCtx(p), lg, t, k.Arg)
		if errors.Is(err, errLayerAbsent) {
			return &legOutcome{NA: "ID-3: gRPC cannot express this target"}
		}
		r := grpcOutcome(err)
		return &legOutcome{Outcome: r.Outcome, Detail: r.Detail}
	}
	return &legOutcome{NA: "unknown layer"}
}

// ---------- positive control (OUTCOMES.md precondition 2) ----------

var (
	controlMu sync.Mutex
	controls  = map[string]*legOutcome{}
)

// control runs the op as the canonical global admin on a fresh world (custom
// variation irrelevant to the admin) and caches it per (op, target, arg, layer).
func control(tb testing.TB, spec opSpec, l layer, t tgt, arg byte) *legOutcome {
	key := fmt.Sprintf("%s|%s|%d|%s", spec.name, t, arg, l)
	controlMu.Lock()
	defer controlMu.Unlock()
	if c, ok := controls[key]; ok {
		return c
	}
	_, fx := template(tb)
	c := runLayer(tb, spec, l, fx.principals[pkGlobalAdmin], caseKey{Arg: arg, variation: defaultVariation}, t, nil)
	if c.NA == "" && c.Outcome != Allowed && spec.secretArgs && arg == 1 {
		// s1 is owned by the viewer: an owner-only action refuses the non-owner
		// admin, so the owner succeeding equally proves the arguments are valid.
		// (The owner alone often fails too: ownership does not pass the route's
		// RBAC gate.)
		if o := runLayer(tb, spec, l, fx.principals[pkViewer], caseKey{Arg: arg, variation: defaultVariation}, t, nil); o.NA == "" && o.Outcome == Allowed {
			c = o
		}
	}
	for _, pk := range spec.controlAs {
		if c.NA == "" && c.Outcome == Allowed {
			break
		}
		if o := runLayer(tb, spec, l, fx.principals[pk], caseKey{Arg: arg, variation: defaultVariation}, t, nil); o.NA == "" && o.Outcome == Allowed {
			c = o
		}
	}
	controls[key] = c
	return c
}

// ---------- one case ----------

func runCase(tb testing.TB, spec opSpec, k caseKey, t tgt) *caseResult {
	tb.Helper()
	_, fx := template(tb)
	p := fx.principals[k.Principal]
	res := &caseResult{caseKey: k, Legs: map[layer]*legOutcome{}}
	res.Legs[layerCore] = runLayer(tb, spec, layerCore, p, k, t, res)
	res.Legs[layerREST] = runLayer(tb, spec, layerREST, p, k, t, nil)
	res.Legs[layerGRPC] = runLayer(tb, spec, layerGRPC, p, k, t, nil)

	for l, lo := range res.Legs {
		if lo.NA != "" {
			continue
		}
		if c := control(tb, spec, l, t, k.Arg); c.NA == "" && c.Outcome != Allowed {
			lo.NA = fmt.Sprintf("uncalibrated: admin control on %s got %s (%s)", l, c.Outcome, c.Detail)
		}
	}
	res.Classes = classify(spec, p, res)
	res.PATUngatedWrite = patRefusesUngatedWrite(tb, fx, spec, p)
	res.Bucket = explain(res)
	return res
}

// classify applies Oracle 1 (layers agree) and Oracle 2 (each layer = model),
// with the intended differences of OUTCOMES.md filtered out and recorded.
func classify(spec opSpec, p *principal, r *caseResult) []string {
	var out []string
	if p.systemActor {
		return []string{"intended:ID-1(actor-0 core only)"}
	}
	part := map[layer]Outcome{}
	for l, lo := range r.Legs {
		if lo.NA != "" {
			if strings.HasPrefix(lo.NA, "uncalibrated") {
				out = append(out, "uncalibrated:"+string(l))
			}
			continue
		}
		if l == layerCore && !spec.coreEnforced {
			continue // ID-2: transport-enforced op, core leg recorded only
		}
		part[l] = lo.Outcome
	}
	// Oracle 1
	var allow, deny []string
	for l, o := range part {
		switch o {
		case Allowed:
			allow = append(allow, string(l))
		case Denied:
			deny = append(deny, string(l))
		}
	}
	sort.Strings(allow)
	sort.Strings(deny)
	if len(allow) > 0 && len(deny) > 0 {
		out = append(out, fmt.Sprintf("O1:layers-disagree(allow=%s;deny=%s)", strings.Join(allow, "+"), strings.Join(deny, "+")))
	}
	// Oracle 2 + mapping gaps
	for _, l := range []layer{layerCore, layerREST, layerGRPC} {
		o, ok := part[l]
		if !ok {
			continue
		}
		if r.Model == ModelNA {
			if o == Other {
				out = append(out, "other-outside-model:"+string(l))
			}
			continue
		}
		switch {
		case o == Allowed && r.Model == Denied:
			out = append(out, "O2:allowed-but-model-denies:"+string(l))
		case o == Denied && r.Model == Allowed:
			out = append(out, "O2:over-denial:"+string(l))
		case o == Other && r.Model == Denied:
			out = append(out, "mapping-gap:other-where-model-denies:"+string(l))
		case o == Other && r.Model == Allowed:
			out = append(out, "mapping-gap:other-where-model-allows:"+string(l))
		}
	}
	sort.Strings(out)
	return out
}

// ---------- reporting ----------

// resultSink appends results as JSON lines to $AUTHZDIFF_OUT (if set). Only
// op/principal/target/outcome classes and status/code/sentinel names are
// written — never a value, body or request.
type resultSink struct {
	mu sync.Mutex
	f  *os.File
}

var sink = func() *resultSink {
	path := os.Getenv("AUTHZDIFF_OUT")
	if path == "" {
		return &resultSink{}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return &resultSink{}
	}
	return &resultSink{f: f}
}()

func (s *resultSink) write(r *caseResult) {
	if s.f == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(r)
	_, _ = s.f.Write(append(b, '\n'))
}

func (r *caseResult) disagreement() bool {
	for _, c := range r.Classes {
		if strings.HasPrefix(c, "O1:") || strings.HasPrefix(c, "O2:") {
			return true
		}
	}
	return false
}

func (r *caseResult) line() string {
	var legs []string
	for _, l := range []layer{layerCore, layerREST, layerGRPC} {
		lo := r.Legs[l]
		if lo.NA != "" {
			legs = append(legs, fmt.Sprintf("%s=n/a", l))
			continue
		}
		legs = append(legs, fmt.Sprintf("%s=%s(%s)", l, lo.Outcome, lo.Detail))
	}
	return fmt.Sprintf("%s principal=%s target=%s arg=%d perms=%s route=%s scope=%s model=%s %s => %s",
		r.Op, r.Principal, r.Target, r.Arg, maskNames(r.Mask), r.Route, r.Scope, r.Model, strings.Join(legs, " "), strings.Join(r.Classes, ","))
}
