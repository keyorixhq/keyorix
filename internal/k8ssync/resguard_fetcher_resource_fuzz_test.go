package k8ssync

// resguard_fetcher_resource_fuzz_test.go wires the shared resguard resource layer
// (internal/fuzzutil/resguard) around the k8ssync Keyorix fetcher, closing the one
// oracle the existing FuzzKeyorixFetcherHostileServer does NOT cover: that a hostile or
// broken server cannot make a single secret resolution LOOP or ALLOCATE without bound.
//
// Why this target and not the existing hostile one: FuzzKeyorixFetcherHostileServer
// checks CORRECTNESS (fail-closed, right value, right scope, canary) and caps the server
// at RequestCeiling:64, which turns an over-long pagination walk into an *error* it then
// classifies — so it never measures the walk as a RESOURCE cost. resolveID
// (keyorix_fetcher.go) paginates `for page := 1; ; page++` and only stops at
// `page >= body.TotalPages`, with TotalPages supplied by the SERVER and NO client-side
// page/request ceiling. This target meters the HTTP round-trips (NetMeter) and allocation
// (resguard sampled alloc) of each FetchWithExpiry, so the unbounded-pagination surface is
// visible as a resource finding (see TestResguardK8sSyncPaginationRedGreen and the OP1
// report §6 — classified HARDENING).
//
// Meters enabled and why:
//   - NetMeter (air-gap + dials + net_bytes_in): the fetcher must only ever dial its
//     configured loopback server (never a redirect-chosen host). Note HTTP keep-alive
//     reuses ONE TCP connection across the whole resolution, so the dial COUNT stays ~1
//     even during a long pagination walk — the meter that actually catches the walk is
//     net_bytes_in (cumulative response volume; each page body is capped at
//     maxResponseBodyBytes, but the NUMBER of pages is not, so the sum is unbounded).
//   - alloc_bytes (sampled): a response shape that makes the JSON decode allocate
//     super-linearly would show here even though each body is LimitReader-capped.
//   - goroutines / open fds (local, like the connect pilot): a per-request leak across the
//     fuzz run.
// Disk/sleep/DB meters are NOT enabled: the fetcher writes no temp files, performs no
// virtual sleep, and touches no database on this path.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const resguardK8sSyncBudgetPath = "testdata/resguard-k8ssync-fetcher.json"

// resReader is a tiny deterministic consumer of fuzz bytes.
type resReader struct {
	b []byte
	i int
}

func (r *resReader) u8() byte {
	if r.i >= len(r.b) {
		return 0
	}
	v := r.b[r.i]
	r.i++
	return v
}

// resCtx bounds a FetchWithExpiry call so a server that advertises a huge total_pages
// cannot run the pagination loop (or the test) unboundedly — the context deadline is the
// backstop the fetcher itself lacks.
func resCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

// fetcherResourceServer builds an httptest server whose responses are shaped by the
// parameters a fuzz input (or a red/green test) chose: how many pages the list claims,
// whether the target secret is ever present, the served value, and a forced status.
type fetcherResourceShape struct {
	totalPages  int    // list total_pages the server advertises (>=1)
	targetOnETP bool   // target appears only on the last page (forces a full walk)
	value       string // value the value route returns
	listStatus  int    // 0 => 200
}

func fetcherResourceServer(shape fetcherResourceShape) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/7/environments", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"environments":[{"ID":3,"Name":"prod"}]}}`))
	})
	mux.HandleFunc("/api/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		if shape.listStatus != 0 {
			w.WriteHeader(shape.listStatus)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		tp := max(shape.totalPages, 1)
		secrets := `[{"ID":41,"Name":"other","project_id":7,"environment_id":3}]`
		// Target appears only on the final page, so a resolution must walk every page.
		if shape.targetOnETP && page >= tp {
			secrets = `[{"ID":41,"Name":"other","project_id":7,"environment_id":3},{"ID":42,"Name":"db-pass","project_id":7,"environment_id":3}]`
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"secrets":%s,"total_pages":%d,"page":%d}}`, secrets, tp, page)
	})
	mux.HandleFunc("/api/v1/secrets/42", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(shape.value)
		_, _ = fmt.Fprintf(w, `{"data":{"value":%s,"secret":{"id":42,"project_id":7,"environment_id":3,"expiration":null}}}`, b)
	})
	return httptest.NewServer(mux)
}

// meteredFetcher builds a fetcher whose HTTP transport is routed through the NetMeter, so
// every dial is counted and air-gapped (a non-loopback dial fails).
func meteredFetcher(baseURL string, nm *resguard.NetMeter) *KeyorixFetcher {
	fe := NewKeyorixFetcher(baseURL, hostileFetchToken, 7)
	fe.hc.Transport = nm.Transport()
	return fe
}

// FuzzK8sSyncFetcherResource meters FetchWithExpiry against a server whose response shape
// is fuzz-controlled (bounded page count to keep throughput high — the UNBOUNDED case is
// proven by the dedicated red/green test). Oracles: air-gap (no non-loopback dial), the
// calibrated resguard budget (dials / net_bytes_in / alloc stay bounded), and no
// goroutine/fd leak across inputs.
func FuzzK8sSyncFetcherResource(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 1, 8})   // 1 page, target present, small value
	f.Add([]byte{3, 1, 200}) // up to 4 pages, target present
	f.Add([]byte{2, 0, 0})   // target absent -> walk then ErrUpstreamGone
	f.Add([]byte{0, 1, 255}) // 1 page, bigger value

	nm := resguard.NewNetMeter()
	probe := resguard.New(f, resguard.Options{SampleEvery: 32, Net: nm})

	budget, err := resguard.LoadBudget(resguardK8sSyncBudgetPath)
	haveBudget := err == nil
	if !haveBudget {
		f.Logf("no committed budget at %s (run TestResguardK8sSyncCalibrate with RESGUARD_CALIBRATE=1); metering without a ceiling", resguardK8sSyncBudgetPath)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		b := &resReader{b: data}
		// Keep the fuzz body fast: at most 4 pages. The unbounded loop is exercised by
		// the red/green test, not by every fuzz input (which would flap and starve
		// throughput on a loopback round-trip per page).
		shape := fetcherResourceShape{
			totalPages:  int(b.u8()%4) + 1,
			targetOnETP: b.u8()%2 == 0,
			value:       string(bytes.Repeat([]byte{'v'}, int(b.u8()))),
		}
		srv := fetcherResourceServer(shape)
		defer srv.Close()

		fe := meteredFetcher(srv.URL, nm)

		ctx, cancel := resCtx()
		cost := probe.Measure(len(data), func() {
			_, _, _ = fe.FetchWithExpiry(ctx, "prod/db-pass")
		})
		cancel()
		resguard.FeedCoverage(cost)

		if cost.NonLoopbackDials > 0 {
			t.Fatalf("AIR-GAP: fetcher made %d non-loopback dial(s) — it must only reach its configured loopback server", cost.NonLoopbackDials)
		}
		if haveBudget {
			budget.Check(t.Fatalf, cost)
		}
	})
}

// measureShape runs one FetchWithExpiry against a server of the given shape and returns
// its metered Cost. Used by calibration and the red/green proof.
func measureShape(tb testing.TB, probe *resguard.Probe, nm *resguard.NetMeter, shape fetcherResourceShape) resguard.Cost {
	tb.Helper()
	srv := fetcherResourceServer(shape)
	defer srv.Close()
	fe := meteredFetcher(srv.URL, nm)
	ctx, cancel := resCtx()
	defer cancel()
	return probe.Measure(0, func() { _, _, _ = fe.FetchWithExpiry(ctx, "prod/db-pass") })
}

// TestResguardK8sSyncCalibrate (RESGUARD_CALIBRATE=1) derives the committed budget from a
// benign corpus (1-page resolutions, small values). dials and net_bytes_in are put in
// ModeAbsolute: the per-request response is size-bounded (maxResponseBodyBytes) and the
// benign dial count is small and input-size-independent, so an absolute ceiling is the
// right model (a padded fuzz input must not buy a larger dial budget).
func TestResguardK8sSyncCalibrate(t *testing.T) {
	if os.Getenv("RESGUARD_CALIBRATE") == "" {
		t.Skip("set RESGUARD_CALIBRATE=1 to (re)write " + resguardK8sSyncBudgetPath)
	}
	nm := resguard.NewNetMeter()
	probe := resguard.New(t, resguard.Options{SampleEvery: 1, Net: nm})
	var samples []resguard.Cost
	for range 32 {
		samples = append(samples,
			measureShape(t, probe, nm, fetcherResourceShape{totalPages: 1, targetOnETP: true, value: "small-secret-value"}),
			measureShape(t, probe, nm, fetcherResourceShape{totalPages: 2, targetOnETP: true, value: "v"}),
		)
	}
	budget := resguard.Calibrate("k8ssync-fetcher-resource", samples, 8)
	budget.KeepOnly("dials", "net_bytes_in", "alloc_bytes")
	budget.UseAbsolute("dials", "net_bytes_in")
	if err := budget.WriteJSON(resguardK8sSyncBudgetPath); err != nil {
		t.Fatalf("write budget: %v", err)
	}
	t.Logf("wrote %s: %+v", resguardK8sSyncBudgetPath, budget.Meters)
}

// TestResguardK8sSyncPaginationRedGreen is the red/green proof for the dials oracle AND
// the committed reproducer of the HARDENING finding: resolveID has no client-side page
// ceiling, so a server advertising a large total_pages (with the target never present)
// drives one HTTP round-trip per page — bounded only by the caller's context deadline.
//
//	GREEN: total_pages=1 -> a handful of dials, under the absolute ceiling.
//	RED:   total_pages=3000, target absent -> the walk issues ~3000 dials, far over the
//	       ceiling, and the dials meter fires.
func TestResguardK8sSyncPaginationRedGreen(t *testing.T) {
	budget, err := resguard.LoadBudget(resguardK8sSyncBudgetPath)
	if err != nil {
		t.Skipf("no committed budget at %s yet (run TestResguardK8sSyncCalibrate with RESGUARD_CALIBRATE=1): %v", resguardK8sSyncBudgetPath, err)
	}
	nm := resguard.NewNetMeter()
	probe := resguard.New(t, resguard.Options{SampleEvery: 1, Net: nm})

	fire := func(shape fetcherResourceShape) (bool, resguard.Cost) {
		cost := measureShape(t, probe, nm, shape)
		fired := false
		budget.Check(func(string, ...any) { fired = true }, cost)
		return fired, cost
	}

	if fired, cost := fire(fetcherResourceShape{totalPages: 1, targetOnETP: true, value: "ok"}); fired {
		t.Fatalf("GREEN FAILED: a benign 1-page resolution (%d dials) tripped the budget", cost.Dials)
	}
	fired, cost := fire(fetcherResourceShape{totalPages: 3000, targetOnETP: false})
	if !fired {
		t.Fatalf("RED FAILED: a 3000-page walk (%d dials, %d net bytes in) did NOT trip the budget — the oracle proves nothing", cost.Dials, cost.NetBytesIn)
	}
	// Note: HTTP keep-alive reuses one TCP connection, so the dial COUNT stays ~1; the
	// meter that catches the unbounded walk is net_bytes_in (cumulative response volume),
	// which here is far over the absolute ceiling.
	t.Logf("HARDENING reproduced: unbounded pagination read %d response bytes (dials=%d, keep-alive) for ONE resolution — no client-side page ceiling, bounded only by the context deadline", cost.NetBytesIn, cost.Dials)
}
