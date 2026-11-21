package kinhostile

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// marshalStable backs O-LOAD-3/O-LOAD-5 (pure byte comparison), extracted so it
// can be red/green-proven without needing the library to misbehave.
func marshalStable(a, b []byte) bool { return string(a) == string(b) }

// TestLoaderOracles_RedGreen red/green-proves the assertable loader oracles.
func TestLoaderOracles_RedGreen(t *testing.T) {
	// O-LOAD-3 / O-LOAD-5: marshal comparison.
	if !marshalStable([]byte(`{"openapi":"3.0.0"}`), []byte(`{"openapi":"3.0.0"}`)) {
		t.Fatal("O-LOAD-3/5 GREEN failed: identical marshals judged unstable")
	}
	if marshalStable([]byte(`{"openapi":"3.0.0"}`), []byte(`{"openapi":"3.1.0"}`)) {
		t.Fatal("O-LOAD-3/5 RED failed: differing marshals judged stable")
	}

	// O-LOAD-2: resguard budget fires on an over-ceiling cost and passes a benign one.
	b := resguard.Calibrate("kinloader_test", benignLoaderCosts(t), resguard.DefaultFactor)
	delete(b.Meters, "live_heap")
	benign := benignLoaderCosts(t)[0]
	var benignFired bool
	b.Check(func(string, ...any) { benignFired = true }, benign)
	if benignFired {
		t.Fatal("O-LOAD-2 GREEN failed: benign cost tripped the budget")
	}
	red := benign
	red.AllocBytes = benign.AllocBytes*1000 + (1 << 30)
	red.Mallocs = benign.Mallocs*1000 + (1 << 20)
	red.Sampled = true
	var redFired bool
	b.Check(func(string, ...any) { redFired = true }, red)
	if !redFired {
		t.Fatal("O-LOAD-2 RED failed: a 1 GiB alloc spike did not trip the budget")
	}
}

// TestLoaderExternalRef_RedGreen is the load-bearing red/green for O-LOAD-4: the
// SAME document and the SAME detector must report "no external read" when the
// flag is false (GREEN) and "external read happened" when the flag is flipped to
// true (RED). Flipping IsExternalRefsAllowed is the exact regression O-LOAD-4
// guards against.
func TestLoaderExternalRef_RedGreen(t *testing.T) {
	hits := &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(hostileSchemaBody())
	}))
	defer srv.Close()
	dir := t.TempDir()
	fp := filepath.Join(dir, "canary.json")
	if err := os.WriteFile(fp, hostileSchemaBody(), 0o644); err != nil {
		t.Fatal(err)
	}
	doc := []byte(fmt.Sprintf(
		`{"openapi":"3.0.0","info":{"title":"ko3","version":"1"},"paths":{},"components":{"schemas":{"FileRef":{"$ref":%q},"HTTPRef":{"$ref":%q},"Leaf":{"type":"string"}}}}`,
		"file://"+fp, srv.URL+"/x.json"))

	// GREEN: flag false (Keyorix default). No read, refs unresolved.
	hitsBefore := hits.Load()
	lg := openapi3.NewLoader()
	lg.IsExternalRefsAllowed = false
	dg, errg := lg.LoadFromData(doc)
	if hits.Load() != hitsBefore {
		t.Fatalf("O-LOAD-4 GREEN failed: hostile server read with flag=false (err=%v)", errg)
	}
	if ok, detail := externalRefsUnresolved(dg); !ok {
		t.Fatalf("O-LOAD-4 GREEN failed: external ref resolved with flag=false: %s", detail)
	}

	// RED: flag true (the regression). The detector MUST now report a read, or
	// the oracle is vacuous. kin refuses to continue if a ref can't be fetched,
	// so capture whichever signal fires first (server hit OR resolved Value).
	hitsBefore = hits.Load()
	lr := openapi3.NewLoader()
	lr.IsExternalRefsAllowed = true
	dr, errr := lr.LoadFromData(doc)
	readHappened := hits.Load() != hitsBefore
	if ok, _ := externalRefsUnresolved(dr); !ok {
		readHappened = true
	}
	if !readHappened {
		t.Fatalf("O-LOAD-4 RED failed: flag=true neither hit the server nor resolved a ref (err=%v) — detector is vacuous", errr)
	}
}

// TestLoaderNestedExternalRef_RedGreen proves oracle (d) of
// FuzzOpenAPILoaderNoExternalRead sees an external ref nested inside the
// spliced "Fuzz" schema, which the named-ref check (c) does not look at.
func TestLoaderNestedExternalRef_RedGreen(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "canary.json")
	if err := os.WriteFile(fp, hostileSchemaBody(), 0o644); err != nil {
		t.Fatal(err)
	}
	doc := []byte(fmt.Sprintf(
		`{"openapi":"3.0.0","info":{"title":"ko3","version":"1"},"paths":{},"components":{"schemas":{"Leaf":{"type":"string"},"Fuzz":{"type":"object","properties":{"deep":{"type":"array","items":{"$ref":%q}}}}}}}`,
		"file://"+fp))

	// GREEN: flag false (Keyorix default). Nothing in the graph is resolved.
	lg := openapi3.NewLoader()
	lg.IsExternalRefsAllowed = false
	dg, errg := lg.LoadFromData(doc)
	if leaked, detail := externalReadInGraph(dg, doc); leaked {
		t.Fatalf("GREEN failed: nested external ref resolved with flag=false: %s (err=%v)", detail, errg)
	}

	// RED: flag true. The nested file:// ref is read; (d) must report it while
	// the named-ref check (c) stays blind to it.
	lr := openapi3.NewLoader()
	lr.IsExternalRefsAllowed = true
	dr, errr := lr.LoadFromData(doc)
	if errr != nil {
		t.Fatalf("RED setup: flag=true load failed, the nested ref was not read: %v", errr)
	}
	if ok, _ := externalRefsUnresolved(dr); !ok {
		t.Fatal("RED setup: the named-ref check already sees the nested ref; this test no longer shows the gap")
	}
	if leaked, _ := externalReadInGraph(dr, doc); !leaked {
		t.Fatal("RED failed: oracle (d) missed an external ref nested in the Fuzz schema")
	}
}

// benignLoaderCosts measures the full load pipeline over the benign loader seeds
// (the valid, non-pathological documents) for calibration. Excludes the external
// refs (they get refused) and the degenerate shapes.
func benignLoaderCosts(tb testing.TB) []resguard.Cost {
	tb.Helper()
	benign := [][]byte{
		docEnvelope(`{"S":{"type":"object","properties":{"name":{"type":"string"}}}}`, ""),
		recursiveSelfRef(),
		mutualRecursion(),
		deepRefChain(16),
		deepAllOfInComponent(32),
		manyRefsFanout(32),
		extensionFields(),
		pathItemRefs(),
	}
	var costs []resguard.Cost
	for range 4 {
		for _, data := range benign {
			p := resguard.New(tb, resguard.Options{SampleEvery: 1})
			var reads int
			c := p.Measure(len(data), func() { _ = runLoaderPipeline(data, &reads) })
			costs = append(costs, c)
		}
	}
	return costs
}

// TestLoaderCalibrate regenerates the committed loader budget under RESGUARD_CALIBRATE=1.
func TestLoaderCalibrate(t *testing.T) {
	b := resguard.Calibrate("kinloader_pipeline", benignLoaderCosts(t), resguard.DefaultFactor)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes should be calibrated; meters=%v", b.Summary())
	}
	// live_heap is a whole-process post-GC reading dominated by the fuzz engine's
	// own heap for a sub-millisecond load; the input-attributable amplification
	// meters alloc_bytes/mallocs stay fatal (INV-FUZZKIN-liveheap-not-metered).
	delete(b.Meters, "live_heap")
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(loaderBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", loaderBudgetPath, b.Summary())
	}
}

// keep json import used if seeds change.
var _ = json.Valid
var _ = strings.Contains
