package authzdiff

import (
	"fmt"
	"testing"
)

// runCaseNoGRPC is runCase for an op with no gRPC leg: it drives the core and
// REST legs, records the gRPC leg NA (as runCase would for spec.grpc==nil), and
// runs the identical uncalibration, classification and partition steps. Used by
// the V8 strict sweep; TestV8StrictSweep fails first if an op grows a gRPC leg.
func runCaseNoGRPC(tb testing.TB, spec opSpec, k caseKey, t tgt) *caseResult {
	tb.Helper()
	_, fx := template(tb)
	p := fx.principals[k.Principal]
	res := &caseResult{caseKey: k, Legs: map[layer]*legOutcome{}}
	res.Legs[layerCore] = runLayer(tb, spec, layerCore, p, k, t, res)
	res.Legs[layerREST] = runLayer(tb, spec, layerREST, p, k, t, nil)
	res.Legs[layerGRPC] = &legOutcome{NA: "ID-3: no gRPC RPC (ADR-105 partial surface)"}
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
