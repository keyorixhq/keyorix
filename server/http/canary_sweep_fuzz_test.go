package http

import (
	"os"
	"strings"
	"testing"
)

// ownedTB lets one canary world outlive a single fuzz callback: the world is
// rebuilt every fuzzWorldExecs executions, not once per *testing.T.
type ownedTB struct {
	testing.TB
	dirs     []string
	cleanups []func()
}

func (o *ownedTB) TempDir() string {
	d, err := os.MkdirTemp("", "kx-fuzz-*")
	if err != nil {
		panic(err)
	}
	o.dirs = append(o.dirs, d)
	return d
}
func (o *ownedTB) Cleanup(fn func())         { o.cleanups = append(o.cleanups, fn) }
func (o *ownedTB) Helper()                   {}
func (o *ownedTB) Logf(string, ...any)       {}
func (o *ownedTB) Log(...any)                {}
func (o *ownedTB) Fatalf(f string, a ...any) { panic("canary fuzz world: " + f) }
func (o *ownedTB) Fatal(a ...any)            { panic("canary fuzz world fatal") }
func (o *ownedTB) Errorf(string, ...any)     {}
func (o *ownedTB) Error(...any)              {}
func (o *ownedTB) Skipf(string, ...any)      {}
func (o *ownedTB) release() {
	for i := len(o.cleanups) - 1; i >= 0; i-- {
		o.cleanups[i]()
	}
	for _, d := range o.dirs {
		_ = os.RemoveAll(d)
	}
}

const fuzzWorldExecs = 2000

var (
	fuzzSweep    *sweep
	fuzzOwner    *ownedTB
	fuzzRoutes   []sweepRoute
	fuzzExecs    int
	fuzzReported = map[string]bool{}
)

func fuzzWorld(t *testing.T) {
	if fuzzSweep != nil && fuzzExecs < fuzzWorldExecs {
		return
	}
	if fuzzSweep != nil {
		fuzzSweep.close()
		fuzzOwner.release()
	}
	fuzzOwner = &ownedTB{TB: t}
	fuzzSweep = newSweep(fuzzOwner, sweepSeed())
	fuzzRoutes = listSweepRoutes(fuzzOwner, fuzzSweep.w.router)
	fuzzExecs = 0
	fuzzReported = map[string]bool{}
}

// FuzzCanaryRouteSweep drives one (route, principal, request shape) per
// execution, with the fuzzer's bytes mutating the body or an extra header, and
// fails on any Secret-class canary on any surface other than known finding F1.
// Persistent stores (metrics, DB, temp files) are scanned every 200 executions.
func FuzzCanaryRouteSweep(f *testing.F) {
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
		if p == "admin" && sweepDestructive.MatchString(rt.Pattern) {
			p = "outsider"
		}
		shapes := s.shapesFor(rt, p)
		if len(shapes) == 0 {
			return
		}
		r := shapes[int(ssel)%len(shapes)]
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
		}
		for k, h := range s.hits {
			if fuzzReported[k] || h.Class != "S" {
				continue
			}
			fuzzReported[k] = true
			if strings.HasSuffix(k, "|url-echo") {
				continue // known finding F1, tracked privately
			}
			t.Fatalf("LEAK candidate: %s repro=%v", k, h.Repro)
		}
	})
}
