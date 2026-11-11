package faultops

// panic_dump_canary_fuzz_test.go -- FuzzPanicDumpCanary.
//
// Panics a storage call in the middle of a real secret operation, through the real
// REST router and gRPC server, and asserts that the panic handling writes no canary
// anywhere: not in the PANIC log line, the stack dump, the response, the gRPC status,
// the metrics, or an audit row.
//
// The storage panic carries a fixed message, so this proves the recovery path itself
// adds nothing; TestPanicDumpCanaryOracle shows the same channels do report a canary
// when one is placed in the panic value. What it does not cover: a panic whose value
// was built from the secret by the code that panicked. FuzzCanaryLeakUnderFault
// sweeps more operations with fixed literals over fewer channels; this target uses a
// fresh high-entropy canary per input and the shared scanner, and it requires that
// the panic really happened.

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/canary"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

const (
	panicChanResponse = "response"
	panicChanMetrics  = "metrics"
	panicChanAudit    = "audit-row"
	panicChanReveal   = "reveal"
)

// panicDumpRules is the whole allowlist, and a secret canary has no entry: the
// control reveal is asserted directly, not judged here. The metadata name can be
// returned by a create that the fault did not interrupt (a fault on a later call can
// land after the row is written), and audit rows name the resource.
func panicDumpRules() *canary.Allowlist {
	return canary.NewAllowlist(
		canary.Rule{ID: "meta-audit", Channel: panicChanAudit, MetadataOnly: true, Why: "audit rows name the resource"},
		canary.Rule{ID: "meta-response", Channel: panicChanResponse, MetadataOnly: true, Why: "the secret's own name, returned to the caller that supplied it"},
	)
}

// panicDumpFixture is per worker: the capture, the metrics control, and the storage
// calls each operation makes, which are found once by a dry run.
type panicDumpFixture struct {
	capture *canary.Capture
	control *prometheus.GaugeVec
	calls   map[string]map[string]int

	captureDir string
	// newWorld builds one execution's world. The PostgreSQL target reuses a schema
	// through resetForReuse instead of migrating per world.
	newWorld func(t *testing.T) *faultWorld
}

func newPanicDumpFixture(tb testing.TB) *panicDumpFixture {
	tb.Helper()
	dir, err := os.MkdirTemp("", "panic-canary-*")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(dir) })
	fx := &panicDumpFixture{capture: canary.NewCapture(), calls: map[string]map[string]int{}, newWorld: func(t *testing.T) *faultWorld { return newFaultWorld(t, nil) }}
	tb.Cleanup(fx.capture.Uninstall)
	fx.captureDir = dir
	fx.control = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "keyorix_panic_canary_control", Help: "Harness control for the metrics capture."}, []string{"v"})
	if err := prometheus.Register(fx.control); err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { prometheus.Unregister(fx.control) })
	return fx
}

// panicDumpOp is one operation the panic interrupts. value carries the secret canary.
type panicDumpOp struct {
	name string
	run  func(ctx context.Context, w *faultWorld, id uint, value, name string) (opResult, error)
}

func panicRESTOp(name, method, path string, body func(value, name string) map[string]any) panicDumpOp {
	return panicDumpOp{name: name, run: func(ctx context.Context, w *faultWorld, id uint, value, secretName string) (opResult, error) {
		target := path
		if strings.Contains(path, "%d") {
			target = fmt.Sprintf(path, id)
		}
		var payload any
		if body != nil {
			payload = body(value, secretName)
		}
		st, data, err := httpJSON(ctx, w, method, target, payload)
		if err != nil {
			return opResult{}, err
		}
		return httpResult(st, data), nil
	}}
}

func panicGRPCResult(err error) (opResult, error) {
	if err != nil {
		return opResult{Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
	}
	return opResult{Success: true, Detail: codes.OK.String()}, nil
}

var panicDumpOps = []panicDumpOp{
	panicRESTOp("rest-create", http.MethodPost, "/api/v1/secrets/", func(v, n string) map[string]any {
		return map[string]any{"name": n, "value": v, "project_id": 1, "environment_id": 1, "type": "generic"}
	}),
	panicRESTOp("rest-update", http.MethodPut, "/api/v1/secrets/%d", func(v, _ string) map[string]any { return map[string]any{"value": v} }),
	panicRESTOp("rest-reveal", http.MethodGet, "/api/v1/secrets/%d?include_value=true", nil),
	panicRESTOp("rest-delete", http.MethodDelete, "/api/v1/secrets/%d", nil),
	panicRESTOp("rest-versions", http.MethodGet, "/api/v1/secrets/%d/versions", nil),
	{name: "grpc-create", run: func(_ context.Context, w *faultWorld, _ uint, value, secretName string) (opResult, error) {
		_, err := pb.NewSecretServiceClient(w.grpcConn).CreateSecret(w.grpcCtx, &pb.CreateSecretRequest{Name: secretName, Value: value, ProjectId: 1, EnvironmentId: 1, Type: "generic"})
		return panicGRPCResult(err)
	}},
	{name: "grpc-update", run: func(_ context.Context, w *faultWorld, id uint, value, _ string) (opResult, error) {
		_, err := pb.NewSecretServiceClient(w.grpcConn).UpdateSecret(w.grpcCtx, &pb.UpdateSecretRequest{Id: uint32(id), Value: &value})
		return panicGRPCResult(err)
	}},
	{name: "grpc-reveal", run: func(_ context.Context, w *faultWorld, id uint, _, _ string) (opResult, error) {
		_, err := pb.NewSecretServiceClient(w.grpcConn).GetSecretValue(w.grpcCtx, &pb.GetSecretRequest{Id: uint32(id), IncludeValue: true})
		return panicGRPCResult(err)
	}},
}

// callsFor returns how many times op calls each storage method on a clean run.
func (fx *panicDumpFixture) callsFor(t *testing.T, op panicDumpOp) map[string]int {
	t.Helper()
	if c, ok := fx.calls[op.name]; ok {
		return c
	}
	w := fx.newWorld(t)
	ctx := context.Background()
	id, err := createCanarySecret(ctx, w, "panic-dry-"+op.name, "panic-dry-value")
	if err != nil {
		t.Fatalf("dry run setup: %v", err)
	}
	drainAllBackgroundGoroutines()
	before := len(w.faulty.Calls())
	res, err := op.run(ctx, w, id, "panic-dry-value-2", "panic-dry-name-2")
	if err != nil || !res.Success {
		t.Fatalf("dry run of %s did not succeed: %v %q", op.name, err, res.Detail)
	}
	drainAllBackgroundGoroutines()
	counts := map[string]int{}
	for _, c := range w.faulty.Calls()[before:] {
		counts[c.Method]++
	}
	fx.calls[op.name] = counts
	return counts
}

// panicDumpInput selects the operation and the storage call to panic.
type panicDumpInput struct {
	op, method, nth uint8
	seed            []byte
}

// panicDumpPlant is the red-proof's planted leak. It receives the world, the panic
// message to use (the harness's fixed one) and the secret canary, and returns the
// panic error to arm, plus any text to add to the observed response.
type panicDumpPlant struct {
	panicErr func(value string) error
	after    func(w *faultWorld, fx *panicDumpFixture, value string)
	response func(value string) string
}

type panicDumpResult struct {
	findings []string
	invalid  string
	fired    bool
	panicked bool
}

var panicLogLine = regexp.MustCompile(`(?i)panic`)

func runPanicDump(t *testing.T, fx *panicDumpFixture, in panicDumpInput, allow *canary.Allowlist, plant *panicDumpPlant) panicDumpResult {
	t.Helper()
	ctx := context.Background()
	op := panicDumpOps[int(in.op)%len(panicDumpOps)]
	if err := fx.capture.InstallOnce(fx.captureDir, os.Create); err != nil {
		t.Fatalf("capture: %v", err)
	}
	counts := fx.callsFor(t, op)
	methods := make([]string, 0, len(counts))
	for m := range counts {
		if m != "WithTransaction" {
			methods = append(methods, m)
		}
	}
	if len(methods) == 0 {
		return panicDumpResult{invalid: "INVALID RUN: " + op.name + " made no storage call, so nothing can panic"}
	}
	slices.Sort(methods)
	method := methods[int(in.method)%len(methods)]
	nth := int(in.nth)%counts[method] + 1

	secretCanary := canary.New("value", canary.Secret, in.seed, in.seed != nil && len(in.seed)%2 == 0)
	controlValue := canary.New("control", canary.Secret, in.seed, false)
	metaName := canary.New("name", canary.Metadata, in.seed, false)
	probe := canary.New("probe", canary.Metadata, in.seed, false)
	scanner := canary.NewScanner(secretCanary, controlValue, metaName, probe)

	w := fx.newWorld(t)
	id, err := createCanarySecret(ctx, w, "control-"+metaName.Core, controlValue.Raw)
	if err != nil {
		return panicDumpResult{invalid: "INVALID RUN: control secret: " + err.Error()}
	}
	st, body, err := httpJSON(ctx, w, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), nil)
	if err != nil || !slices.ContainsFunc(scanner.Scan(panicChanReveal, body), func(h canary.Hit) bool { return h.Label == controlValue.Label }) {
		return panicDumpResult{invalid: fmt.Sprintf("INVALID RUN: the reveal did not return the control canary: HTTP %d %v", st, err)}
	}
	drainAllBackgroundGoroutines()
	fx.capture.Drain()
	beforeAudit := maxAuditEventID(w)

	panicErr := errFuzzInjected
	if plant != nil && plant.panicErr != nil {
		panicErr = plant.panicErr(secretCanary.Raw)
	}
	w.faulty.Arm(&faultstorage.FaultSpec{Method: method, NthCall: nth, Kind: faultstorage.KindPanic, Err: panicErr})
	result := mustExecuteRecoveringPanics(t, func() (opResult, error) { return op.run(ctx, w, id, secretCanary.Raw, metaName.Raw) })
	drainAllBackgroundGoroutines()
	fired := w.faulty.Fired()
	w.faulty.Arm(nil)

	allowed := func(h canary.Hit, origin string) bool { return h.Label == probe.Label || allow.Permit(h, origin) != "" }
	var findings []string
	judge := func(channel string, data []byte) {
		for _, h := range scanner.Scan(channel, data) {
			if !allowed(h, op.name) {
				findings = append(findings, fmt.Sprintf("op=%s method=%s#%d %s", op.name, method, nth, h))
			}
		}
	}
	if plant != nil && plant.response != nil {
		result.Detail += plant.response(secretCanary.Raw)
	}
	judge(panicChanResponse, []byte(result.Detail))
	for _, text := range auditTextSince(w, beforeAudit) {
		judge(panicChanAudit, []byte(text))
	}

	var logText []byte
	outputs := fx.capture.Drain()
	for _, o := range outputs {
		judge(o.Channel, o.Data)
		if o.Channel == canary.ChannelLog {
			logText = append(logText, o.Data...)
		}
	}
	res := panicDumpResult{fired: fired, panicked: panicLogLine.Match(logText)}

	if plant != nil && plant.after != nil {
		plant.after(w, fx, secretCanary.Raw)
	}
	drainAllBackgroundGoroutines()
	for _, text := range auditTextSince(w, beforeAudit) {
		judge(panicChanAudit, []byte(text))
	}

	// Controls: each capture proves it can still show a canary after the panic.
	log.Print(probe.Raw)
	_, _ = fmt.Fprintln(os.Stdout, probe.Raw)
	fmt.Fprintln(os.Stderr, probe.Raw)
	fx.control.WithLabelValues(probe.Raw).Set(1)
	after := fx.capture.Drain()
	for _, ch := range []string{canary.ChannelLog, canary.ChannelStdout, canary.ChannelStderr} {
		found := slices.ContainsFunc(after, func(o canary.Output) bool {
			return o.Channel == ch && slices.ContainsFunc(scanner.Scan(ch, o.Data), func(h canary.Hit) bool { return h.Label == probe.Label })
		})
		if !found {
			res.invalid = "INVALID RUN: the probe did not reach channel " + ch
		}
	}
	for _, o := range after {
		judge(o.Channel, o.Data)
	}
	metrics, err := scrapeMetrics(ctx, w)
	if err != nil {
		res.invalid = "INVALID RUN: metrics: " + err.Error()
	}
	fx.control.Reset()
	if !slices.ContainsFunc(scanner.Scan(panicChanMetrics, []byte(metrics)), func(h canary.Hit) bool { return h.Label == probe.Label }) {
		res.invalid = "INVALID RUN: the probe is not in /metrics"
	}
	judge(panicChanMetrics, []byte(metrics))
	res.findings = findings
	return res
}

// panicDumpCorpus is the seed corpus: every operation, each with a different call panicked.
func panicDumpCorpus() []panicDumpInput {
	out := make([]panicDumpInput, 0, len(panicDumpOps)*2)
	for i := range panicDumpOps {
		out = append(out, panicDumpInput{op: uint8(i), method: uint8(i), seed: []byte(fmt.Sprintf("seed-%d", i))})
		out = append(out, panicDumpInput{op: uint8(i), method: uint8(i + 3), nth: 1, seed: []byte(fmt.Sprintf("seed-b-%d", i))})
	}
	return out
}

// FuzzPanicDumpCanary fails when a panic during a secret operation writes a canary
// anywhere, or when the panic it asked for did not happen.
func FuzzPanicDumpCanary(f *testing.F) {
	if err := i18n.InitializeForTesting(); err != nil {
		f.Fatal(err)
	}
	f.Cleanup(i18n.ResetForTesting)
	fx := newPanicDumpFixture(f)
	for _, in := range panicDumpCorpus() {
		f.Add(in.op, in.method, in.nth, in.seed)
	}
	f.Fuzz(func(t *testing.T, opSel, method, nth uint8, seed []byte) {
		res := runPanicDump(t, fx, panicDumpInput{opSel, method, nth, seed}, panicDumpRules(), nil)
		if res.invalid != "" {
			t.Fatal(res.invalid)
		}
		if !res.fired {
			t.Skip("the armed storage call was not reached on this run")
		}
		if !res.panicked {
			t.Fatalf("INVALID RUN: the fault fired but no panic was logged: the panic path was not exercised")
		}
		if len(res.findings) > 0 {
			t.Fatalf("CANARY LEAK (%d):\n%s", len(res.findings), strings.Join(res.findings, "\n"))
		}
	})
}

// TestPanicDumpCanaryOracle is the red-proof and the effect check: every corpus
// input really panics, each channel reports a canary planted through the mechanism
// that writes it, and a clean run reports nothing. No production code changes.
func TestPanicDumpCanaryOracle(t *testing.T) {
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(i18n.ResetForTesting)
	fx := newPanicDumpFixture(t)
	in := panicDumpInput{op: 0, seed: []byte("red-proof")}

	t.Run("corpus-really-panics", func(t *testing.T) {
		allow := panicDumpRules()
		for i, c := range panicDumpCorpus() {
			// Each input in its own t.Run: worlds stay open until their test ends.
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				res := runPanicDump(t, fx, c, allow, nil)
				if res.invalid != "" {
					t.Fatal(res.invalid)
				}
				if !res.fired || !res.panicked {
					t.Errorf("input %+v: fired=%v panicked=%v", c, res.fired, res.panicked)
				}
				if len(res.findings) != 0 {
					t.Errorf("input %+v: clean run reported: %v", c, res.findings)
				}
			})
		}
	})

	plants := []struct {
		name, want string
		plant      *panicDumpPlant
	}{
		{"panic-value-in-the-log", canary.ChannelLog, &panicDumpPlant{panicErr: func(v string) error { return fmt.Errorf("storage: %s", v) }}},
		{"stdout", canary.ChannelStdout, &panicDumpPlant{after: func(_ *faultWorld, _ *panicDumpFixture, v string) { _, _ = fmt.Fprintln(os.Stdout, v) }}},
		{"stderr", canary.ChannelStderr, &panicDumpPlant{after: func(_ *faultWorld, _ *panicDumpFixture, v string) { fmt.Fprintln(os.Stderr, v) }}},
		{"response", panicChanResponse, &panicDumpPlant{response: func(v string) string { return v }}},
		{"metric-label", panicChanMetrics, &panicDumpPlant{after: func(_ *faultWorld, fx *panicDumpFixture, v string) { fx.control.WithLabelValues(v).Set(1) }}},
		{"audit-row", panicChanAudit, &panicDumpPlant{after: func(w *faultWorld, _ *panicDumpFixture, v string) {
			if err := w.db.Create(&models.AuditEvent{EventType: "redproof", Description: v}).Error; err != nil {
				t.Fatalf("planting audit row: %v", err)
			}
		}}},
	}
	for _, p := range plants {
		t.Run("red-"+p.name, func(t *testing.T) {
			res := runPanicDump(t, fx, in, panicDumpRules(), p.plant)
			if res.invalid != "" {
				t.Fatal(res.invalid)
			}
			want := "channel=" + p.want + " "
			if !slices.ContainsFunc(res.findings, func(s string) bool { return strings.Contains(s, want) }) {
				t.Fatalf("planted leak on %s was not reported; findings: %v", p.want, res.findings)
			}
		})
	}
}
