// External-ref AIR-GAP harness (KO3, Config A — Keyorix-faithful).
//
// This target drives the DEFAULT loader exactly as Keyorix uses it —
// openapi3.NewLoader() with IsExternalRefsAllowed=false and a NIL ReadFromURIFunc
// (so the flag is ENFORCED by the library, not by a custom policy). It asserts
// the security-relevant property O-LOAD-4: no fuzzed document shape can make the
// loader read an external reference — not a file, not the network — when
// external refs are disallowed.
//
// Three hostile external refs are always present in the document the fuzzer
// mutates around: a loopback httptest server with a hit counter (network read),
// a file:// canary (file read), and a 169.254.169.254 SSRF canary (non-loopback
// read). The harness installs a resguard NetMeter air-gap (non-loopback dials
// fail and are counted; every dial is counted) over http.DefaultTransport, which
// is what the loader's http.DefaultClient uses. Per input it asserts: zero
// hostile-server hits, zero dials, and the injected external SchemaRefs left
// unresolved (.Value == nil) — i.e. the flag held.
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
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// canaryMarker is the unique property name the hostile file/server content
// carries; if it ever appears in a resolved document, an external read happened.
const canaryMarker = "KO3_EXTERNAL_READ_LEAKED"

// airgapFixture holds the per-F hostile endpoints and the air-gap meter.
type airgapFixture struct {
	serverURL  string
	serverHits *atomic.Int64
	filePath   string
	net        *resguard.NetMeter
}

// hostileSchemaBody is a valid standalone schema served by the file/HTTP
// canaries; it carries canaryMarker so a successful external read is observable.
func hostileSchemaBody() []byte {
	return []byte(fmt.Sprintf(`{"type":"object","properties":{%q:{"type":"string"}}}`, canaryMarker))
}

func newAirgapFixture(f *testing.F) *airgapFixture {
	hits := &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(hostileSchemaBody())
	}))
	f.Cleanup(srv.Close)

	dir := f.TempDir()
	fp := filepath.Join(dir, "canary.json")
	if err := os.WriteFile(fp, hostileSchemaBody(), 0o644); err != nil {
		f.Fatalf("write canary file: %v", err)
	}

	nm := resguard.NewNetMeter() // air-gapped: non-loopback dials fail and are counted.
	restore := nm.InstallDefault()
	f.Cleanup(restore)

	return &airgapFixture{serverURL: srv.URL, serverHits: hits, filePath: fp, net: nm}
}

// buildAirgapDoc constructs a document that ALWAYS contains the three hostile
// external refs, and splices the fuzzed bytes in as an extra schema when they
// are valid JSON (so the fuzzer explores structures around the hostile refs).
func (fx *airgapFixture) buildAirgapDoc(fuzz []byte) []byte {
	// The fuzzed fragment, if valid JSON, becomes schema "Fuzz"; else "Fuzz" is a
	// harmless internal ref so the document stays loadable.
	fuzzSchema := `{"$ref":"#/components/schemas/Leaf"}`
	if json.Valid(fuzz) && len(fuzz) > 0 {
		fuzzSchema = string(fuzz)
	}
	return []byte(fmt.Sprintf(
		`{"openapi":"3.0.0","info":{"title":"ko3","version":"1"},"paths":{},"components":{"schemas":{`+
			`"FileRef":{"$ref":%q},`+
			`"HTTPRef":{"$ref":%q},`+
			`"SSRFRef":{"$ref":"http://169.254.169.254/latest/meta-data/x.json"},`+
			`"Leaf":{"type":"string"},`+
			`"Fuzz":%s`+
			`}}}`,
		"file://"+fx.filePath, fx.serverURL+"/x.json", fuzzSchema))
}

// externalRefsUnresolved reports whether every injected external SchemaRef is
// unresolved (.Value == nil) and no canary content leaked. doc may be nil.
func externalRefsUnresolved(doc *openapi3.T) (ok bool, detail string) {
	if doc == nil || doc.Components == nil {
		return true, ""
	}
	for _, name := range []string{"FileRef", "HTTPRef", "SSRFRef"} {
		ref := doc.Components.Schemas[name]
		if ref == nil {
			continue
		}
		if ref.Value != nil {
			// A resolved external ref: content was read.
			if m, err := ref.Value.MarshalJSON(); err == nil && strings.Contains(string(m), canaryMarker) {
				return false, fmt.Sprintf("%s resolved to canary content: %s", name, truncate(m))
			}
			return false, fmt.Sprintf("%s.Value is non-nil (external ref resolved)", name)
		}
	}
	return true, ""
}

func FuzzOpenAPILoaderNoExternalRead(f *testing.F) {
	fx := newAirgapFixture(f)
	p := resguard.New(f, resguard.Options{SampleEvery: 8, Net: fx.net})

	// Seed with the loader seeds (reused as the "Fuzz" fragment) plus a few bare
	// shapes aimed at the external-ref gate.
	for _, sd := range loaderSeeds() {
		f.Add(sd)
	}
	f.Add([]byte(`{"type":"object","properties":{"deep":{"$ref":"#/components/schemas/FileRef"}}}`))
	f.Add([]byte(`{"allOf":[{"$ref":"#/components/schemas/HTTPRef"},{"$ref":"#/components/schemas/SSRFRef"}]}`))

	f.Fuzz(func(t *testing.T, fuzz []byte) {
		if len(fuzz) > maxDocBytes {
			return
		}
		data := fx.buildAirgapDoc(fuzz)

		hitsBefore := fx.serverHits.Load()
		var doc *openapi3.T
		var loadErr error
		var cost resguard.Cost
		started := time.Now()
		// O-LOAD-1 + O-LOAD-2: no panic, bounded work for the whole load under the
		// Keyorix-faithful default config.
		fuzzutil.Guard(t.Fatalf, "kin loader air-gap load", func() {
			cost = p.Measure(len(data), func() {
				l := openapi3.NewLoader()
				l.IsExternalRefsAllowed = false // nil ReadFromURIFunc => flag ENFORCED by library.
				doc, loadErr = l.LoadFromData(data)
			})
		})
		elapsed := time.Since(started)
		resguard.FeedCoverage(cost)
		hitsAfter := fx.serverHits.Load()

		// O-LOAD-4 (zero external reads when disallowed):
		// (a) the hostile HTTP server was never contacted by this input.
		if hitsAfter != hitsBefore {
			t.Fatalf("O-LOAD-4: loader READ the hostile HTTP server under IsExternalRefsAllowed=false (hits %d->%d)\n  err=%v", hitsBefore, hitsAfter, loadErr)
		}
		// (b) no dial of ANY kind happened (loopback or not) — the flag should
		// stop resolution before the transport is reached. cost.Dials/NonLoopback
		// are this input's deltas (the Net seam is reset per Measure).
		if cost.Dials != 0 || cost.NonLoopbackDials != 0 {
			t.Fatalf("O-LOAD-4: loader DIALED under IsExternalRefsAllowed=false (dials=%d nonLoopback=%d)\n  err=%v", cost.Dials, cost.NonLoopbackDials, loadErr)
		}
		// (c) the injected external refs were left unresolved / no canary content leaked.
		if ok, detail := externalRefsUnresolved(doc); !ok {
			t.Fatalf("O-LOAD-4: external ref resolved under IsExternalRefsAllowed=false: %s\n  err=%v", detail, loadErr)
		}
		// O-LOAD-2b superlinear wall.
		if elapsed > loaderSuperlinearWall {
			t.Fatalf("O-LOAD-2b: superlinear work: %s on a %d-byte document (>%s)", elapsed, len(data), loaderSuperlinearWall)
		}
	})
}
