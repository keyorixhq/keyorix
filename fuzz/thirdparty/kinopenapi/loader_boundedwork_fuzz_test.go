// Loader full-document bounded-work / round-trip harness (KO3).
//
// This file fuzzes the kin-openapi FULL-DOCUMENT loader —
// openapi3.Loader.LoadFromData (which parses AND resolves $ref), then
// doc.Validate and MarshalJSON — as opposed to the sibling
// schema_boundedwork_fuzz_test.go which decodes STANDALONE schemas and never
// resolves refs. The surfaces exercised here that the schema target cannot
// reach: recursive / circular / mutually-recursive internal $ref graphs, deep
// nesting across refs, large ref fan-out, extension (x-*) fields, and
// duplicate/colliding component names.
//
// REACHABILITY (see INVARIANTS.md / the KO3 report): in every live Keyorix
// caller the loaded document is the trusted committed openapi.yaml, embedded at
// build time — never attacker-controlled. A finding here is a LIBRARY property
// (deep-recursion panic, composition/ref amplification, serialization drift),
// classified HARDENING/CANDIDATE and labelled not-attacker-reachable. The target
// exists to catch a dependency bump that regresses the loader robustness the
// trusted callers assume.
//
// CONFIG B (this file): a custom refusing ReadFromURIFunc is installed, so an
// external $ref in a fuzzed document drives the loader's ref-resolution
// machinery WITHOUT any real file/network IO (the func records the attempt and
// returns an error). Internal (#/components/...) refs still resolve normally.
// The external-ref AIR-GAP property (flag enforcement under the DEFAULT nil
// func) is a different property, tested by FuzzOpenAPILoaderNoExternalRead.
package kinhostile

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const (
	maxDocBytes      = 1 << 14 // 16 KiB: ample for recursive/deep/many-ref graphs; larger
	loaderBudgetPath = "testdata/resguard-kinloader.json"
)

// loaderSuperlinearWall is the O-LOAD-2b fatal ceiling for one
// load+resolve+validate+roundtrip on a <=16 KiB document. Set below Guard's 3 s
// so a near-threshold slow document is attributed here (with size) rather than
// as a bare "hang", and generous (2.5 s) so co-scheduled -parallel load does not
// false-trip it.
const loaderSuperlinearWall = 2500 * time.Millisecond

// newCanaryLoader returns a Config-B loader: a custom ReadFromURIFunc that
// records external-read attempts and refuses them (zero real IO), so a fuzzed
// document's external $refs exercise the resolution path safely. *reads counts
// attempts for diagnostics.
func newCanaryLoader(reads *int) *openapi3.Loader {
	l := openapi3.NewLoader()
	// Flag is irrelevant once a custom func is set (the func owns policy), but
	// we keep it false to mirror Keyorix's default posture.
	l.IsExternalRefsAllowed = false
	l.ReadFromURIFunc = func(_ *openapi3.Loader, _ *url.URL) ([]byte, error) {
		*reads++
		return nil, errCanaryRefused
	}
	return l
}

// loaderOutcome is the heavy, assertion-free half of the pipeline, computed
// inside the watchdog goroutine; assertions run on the test goroutine.
type loaderOutcome struct {
	loaded bool // LoadFromData returned a non-nil doc (refs resolved or cleanly refused)

	// O-LOAD-3 idempotence: marshal1 -> LoadFromData -> marshal2.
	marshal1   []byte
	reloadErr  error
	marshal2   []byte
	idempRan   bool

	// O-LOAD-5 differential: loader-resolved marshal vs plain-json round-trip marshal.
	diffRan      bool
	plainMarshal []byte
}

// runLoaderPipeline loads data, validates, and computes the idempotence and
// differential artifacts. Assertion-free (safe on the watchdog goroutine).
func runLoaderPipeline(data []byte, reads *int) loaderOutcome {
	var o loaderOutcome
	doc, err := newCanaryLoader(reads).LoadFromData(data)
	if err != nil || doc == nil {
		return o // kin rejected the document (or a ref it could not resolve) — nothing to assert.
	}
	o.loaded = true

	// doc.Validate exercises the structural validator over the resolved graph.
	// Its verdict is not an oracle (a hostile doc may be legitimately invalid);
	// it must merely not panic or run away (covered by O-LOAD-1/2).
	_ = doc.Validate(openapi3.NewLoader().Context)

	m1, merr := doc.MarshalJSON()
	if merr != nil {
		return o
	}
	o.marshal1 = m1

	// O-LOAD-3: re-load the marshalled form and re-marshal; expect a byte-stable
	// fixed point. Re-load with a fresh canary loader (same policy).
	var rreads int
	doc2, rerr := newCanaryLoader(&rreads).LoadFromData(m1)
	o.idempRan = true
	if rerr != nil || doc2 == nil {
		o.reloadErr = rerr
		if rerr == nil {
			o.reloadErr = errReloadNil
		}
		return o
	}
	m2, m2err := doc2.MarshalJSON()
	if m2err != nil {
		o.reloadErr = m2err
		return o
	}
	o.marshal2 = m2

	// O-LOAD-5: plain json round trip of the resolved *T (NOT via the loader, so
	// refs are not re-resolved) must marshal identically to the loader-resolved
	// form — ref resolution must be marshal-transparent.
	var t2 openapi3.T
	if json.Unmarshal(m1, &t2) == nil {
		if pm, perr := t2.MarshalJSON(); perr == nil {
			o.diffRan = true
			o.plainMarshal = pm
		}
	}
	return o
}

func assertLoaderOutcome(t *testing.T, data []byte, o loaderOutcome) {
	if !o.loaded {
		return
	}
	if o.idempRan && len(o.marshal1) > 0 {
		if o.reloadErr != nil {
			t.Fatalf("O-LOAD-3: document kin produced via MarshalJSON failed to re-load/re-marshal: %v\n  doc=%s", o.reloadErr, truncate(o.marshal1))
		}
		if string(o.marshal1) != string(o.marshal2) {
			t.Fatalf("O-LOAD-3: load->marshal->load->marshal not idempotent\n  first =%s\n  second=%s", truncate(o.marshal1), truncate(o.marshal2))
		}
	}
	if o.diffRan {
		if string(o.plainMarshal) != string(o.marshal1) {
			t.Fatalf("O-LOAD-5: loader-resolved marshal differs from plain json round-trip marshal\n  loader=%s\n  plain =%s", truncate(o.marshal1), truncate(o.plainMarshal))
		}
	}
	_ = data
}

func FuzzOpenAPIDocumentLoader(f *testing.F) {
	budget, err := resguard.LoadBudget(loaderBudgetPath)
	haveBudget := err == nil
	if !haveBudget {
		f.Logf("no committed budget at %s (run TestLoaderCalibrate with RESGUARD_CALIBRATE=1); metering without a ceiling", loaderBudgetPath)
	}
	p := resguard.New(f, resguard.Options{SampleEvery: 8})

	for _, sd := range loaderSeeds() {
		f.Add(sd)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxDocBytes {
			return
		}
		// O-LOAD-1 + O-LOAD-2: the WHOLE load+resolve+validate+roundtrip runs
		// inside ONE hang/amplification watchdog so a superlinear stage is
		// attributed, not absorbed into a stalled worker. LoadFromData is
		// additionally metered by resguard for the alloc/mallocs ceiling.
		var cost resguard.Cost
		var measured bool
		var reads int
		var o loaderOutcome
		started := time.Now()
		fuzzutil.Guard(t.Fatalf, "kin loader load+resolve+validate+roundtrip", func() {
			cost = p.Measure(len(data), func() {
				o = runLoaderPipeline(data, &reads)
			})
			measured = true
		})
		elapsed := time.Since(started)
		if measured {
			resguard.FeedCoverage(cost)
			if haveBudget {
				budget.Check(t.Fatalf, cost)
			}
			assertLoaderOutcome(t, data, o)
			// O-LOAD-2b (superlinear wall): the whole pipeline on a <=16 KiB
			// document must finish well under the Guard deadline. A multi-second
			// wall on so small an input is strongly superlinear — save it WITH size.
			if elapsed > loaderSuperlinearWall {
				t.Fatalf("O-LOAD-2b: superlinear work: %s on a %d-byte document (>%s)", elapsed, len(data), loaderSuperlinearWall)
			}
		}
	})
}
