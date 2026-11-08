package http

import (
	"log"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

const fuzzWorldExecs = 2000

var (
	fuzzSweep      *sweep
	fuzzRoutes     []sweepRoute
	fuzzExecs      int
	fuzzReported   = map[string]bool{}
	fuzzSelfTested bool
)

func fuzzWorld(t *testing.T) {
	if !fuzzSelfTested {
		runPlantedLeakSelfTest(t)
		fuzzSelfTested = true
	}
	if fuzzSweep != nil && fuzzExecs < fuzzWorldExecs {
		return
	}
	if fuzzSweep != nil {
		fuzzSweep.close()
	}
	fuzzSweep = newSweep(t, sweepSeed())
	fuzzRoutes = listSweepRoutes(t, fuzzSweep.w.router)
	fuzzExecs = 0
	fuzzReported = map[string]bool{}
}

// FuzzCanaryRouteSweep drives one (route, principal, request shape) per
// execution, with the fuzzer's bytes mutating the body or an extra header, and
// fails on any Secret-class canary on any surface that sweepWaivers does not
// name. Persistent stores (metrics, DB, temp files) are scanned every 200
// executions.
func FuzzCanaryRouteSweep(f *testing.F) {
	prevLog := log.Writer()
	f.Cleanup(func() { log.SetOutput(prevLog) })
	f.Cleanup(i18n.ResetForTesting)
	// The world outlives every callback, so the last one is released here: the
	// seed-only path of a plain go test never reaches the rebuild in fuzzWorld.
	f.Cleanup(func() {
		if fuzzSweep != nil {
			fuzzSweep.close()
			fuzzSweep = nil
		}
	})
	f.Add(uint16(0), uint8(0), uint8(0), []byte(nil))
	f.Add(uint16(5), uint8(1), uint8(3), []byte{1, 2, 3})
	f.Add(uint16(120), uint8(0), uint8(5), []byte("\x00\xff{\"a\":"))
	f.Fuzz(func(t *testing.T, rsel uint16, psel, ssel uint8, mut []byte) {
		fuzzWorld(t)
		fuzzExecs++
		s := fuzzSweep
		rt := fuzzRoutes[int(rsel)%len(fuzzRoutes)]
		if rt.Method == "CONNECT" || rt.Method == "TRACE" {
			return
		}
		principals := []string{"admin", "outsider", "anon", "garbage"}
		p := principals[int(psel)%len(principals)]
		disposable := (p == "admin" || p == "outsider") && sweepDestructive.MatchString(rt.Pattern)
		shapes := s.shapesFor(rt, p)
		if len(shapes) == 0 {
			return
		}
		r := shapes[int(ssel)%len(shapes)]
		if disposable && !s.useDisposable(&r) {
			t.Fatalf("INVALID RUN: %s", strings.Join(s.scanFailures, "; "))
		}
		if len(mut) > 0 {
			if len(r.Body) > 0 {
				b := append([]byte(nil), r.Body...)
				for i, m := range mut {
					b[(int(m)*31+i*7)%len(b)] ^= mut[(i+1)%len(mut)] | 1
				}
				r.Body = b
			} else if r.Header != nil {
				v := strings.Map(func(c rune) rune {
					if c < 0x20 || c > 0x7e {
						return '_'
					}
					return c
				}, string(mut))
				r.Header.Set("X-Fuzz-Mut", v)
			}
		}
		s.run(r)
		if fuzzExecs%200 == 0 {
			s.scanPersistentDeep(rt.String(), false)
			if len(s.scanFailures) > 0 {
				t.Fatalf("INVALID RUN: %s", strings.Join(s.scanFailures, "; "))
			}
			// A session the input managed to end is a harness state, not a leak:
			// rebuild instead of sweeping on unauthenticated.
			if !s.sessionLive(s.w.adminTok) || !s.sessionLive(s.outsiderTok) {
				t.Logf("a long-lived session died at exec %d; rebuilding the world", fuzzExecs)
				fuzzExecs = fuzzWorldExecs
			}
		}
		for k, h := range s.hits {
			if fuzzReported[k] || h.Class != "S" {
				continue
			}
			fuzzReported[k] = true
			if h.Waiver != "" {
				continue
			}
			t.Fatalf("LEAK candidate: %s repro=%v", k, h.Repro)
		}
	})
}
