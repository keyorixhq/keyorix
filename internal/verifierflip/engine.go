// Package verifierflip is a mutation harness for integrity/authenticity
// verifiers: it takes one valid artifact, derives a deterministic set of
// mutations (every single-bit flip, truncations, extensions, reorders, byte
// deletes/inserts, duplications), feeds each to the verifier under test and
// classifies the outcome. See PREREG.md for the rules this code implements.
//
// The package has no production importers; it is imported only by its own
// tests (the per-verifier targets live in *_test.go).
package verifierflip

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"slices"
	"time"
)

// Target describes one verifier and one valid artifact for it.
type Target struct {
	Name string
	// Artifact is a valid artifact: Verify(Artifact) must return true.
	Artifact []byte
	// Verify reports whether the verifier accepts b. It may panic; the
	// engine recovers and records a PANIC candidate.
	Verify func(b []byte) bool
	// Canon maps an ACCEPTED artifact to its semantic meaning. A mutated
	// artifact that is accepted with Canon equal to the original's is
	// ACCEPT-EQUIVALENT; otherwise ACCEPT-DIFFERENT. nil means the raw bytes
	// are the meaning (any accepted mutation is ACCEPT-DIFFERENT).
	// Canon MUST include the decoded signature/MAC/tag bytes, not only the
	// signed message: a verifier that accepts a different tag for the same
	// message is exactly the defect class this harness exists to find. Only
	// encoding freedom the format documents (hex case, base64 padding bits,
	// JSON whitespace, integer leading zeros) may be normalised away.
	Canon func(b []byte) string
	// Region optionally names the artifact field a byte offset belongs to,
	// so reports group by field rather than by offset.
	Region func(offset int) string
	// MACStart/MACEnd delimit the MAC/signature bytes for the position
	// timing check (both zero disables it).
	MACStart, MACEnd int
	// Seps are delimiters used by the field-swap/drop/duplicate reorders.
	Seps [][]byte
}

// Options bound the work per target.
type Options struct {
	Seed         uint64
	MaxBitFlips  int // sample cap; PREREG: 65536
	TimingReps   int // reps per timed reject; PREREG: 5
	SkipTiming   bool
	TimingFactor float64 // outlier factor; PREREG: 20
}

// DefaultOptions are the PREREG values.
func DefaultOptions(seed uint64) Options {
	return Options{Seed: seed, MaxBitFlips: 65536, TimingReps: 5, TimingFactor: 20}
}

// Verdict classes.
const (
	Reject           = "REJECT"
	AcceptEquivalent = "ACCEPT-EQUIVALENT"
	AcceptDifferent  = "ACCEPT-DIFFERENT"
	Panic            = "PANIC"
	Timing           = "TIMING"
)

// Candidate is one non-REJECT observation.
type Candidate struct {
	Kind     string
	Mutation string // e.g. "bitflip@17.3", "truncate@40"
	Region   string
	Hex      string // mutated artifact (first 2 KiB)
	Detail   string
}

// Report is the outcome for one target.
type Report struct {
	Target      string
	Mutations   int
	Rejects     int
	Equivalent  int
	Different   int
	Panics      int
	TimingFlags int
	MedianNS    int64
	// PosRatio is trimmed-mean(first quarter of MAC) / trimmed-mean(last
	// quarter); 0 when not measured.
	PosRatio float64
	// PosSkew is set when PosRatio is outside [1/1.5, 1.5] (PREREG timing
	// rule (b)); informational unless it reproduces across processes.
	PosSkew    bool
	Candidates []Candidate
	// ByRegion counts non-reject candidates by kind and region.
	ByRegion map[string]int
}

type mutation struct {
	name string
	data []byte
	off  int // byte offset for flips, -1 otherwise
}

// Run executes the mutation set against t. It returns an error only if the
// baseline artifact itself is not accepted (the target is then INVALID).
func Run(t Target, o Options) (*Report, error) {
	if o.MaxBitFlips == 0 {
		o.MaxBitFlips = 65536
	}
	if o.TimingReps == 0 {
		o.TimingReps = 5
	}
	if o.TimingFactor == 0 {
		o.TimingFactor = 20
	}
	ok, pan := safeVerify(t.Verify, t.Artifact)
	if pan != "" || !ok {
		return nil, fmt.Errorf("verifierflip: target %q baseline not accepted (panic=%q)", t.Name, pan)
	}
	canon := func(b []byte) string {
		if t.Canon == nil {
			return string(b)
		}
		return t.Canon(b)
	}
	baseCanon := canon(t.Artifact)
	rep := &Report{Target: t.Name, ByRegion: map[string]int{}}
	rng := rand.New(rand.NewPCG(o.Seed, 0x9e3779b97f4a7c15)) // #nosec G404 -- deterministic, seed-reproducible mutation schedule for a test harness, not security-sensitive

	var rejectTimes []int64
	var pos []PosSample
	type slow struct {
		m  mutation
		ns int64
	}
	var slowCands []slow

	emit := func(m mutation) {
		rep.Mutations++
		if bytes.Equal(m.data, t.Artifact) {
			rep.Mutations--
			return
		}
		acc, pn := safeVerify(t.Verify, m.data)
		region := ""
		if t.Region != nil && m.off >= 0 {
			region = t.Region(m.off)
		}
		switch {
		case pn != "":
			rep.Panics++
			rep.add(Candidate{Kind: Panic, Mutation: m.name, Region: region, Hex: hx(m.data), Detail: pn})
		case acc:
			c, pc := safeCanon(canon, m.data)
			switch {
			case pc != "":
				rep.Panics++
				rep.add(Candidate{Kind: Panic, Mutation: m.name, Region: region, Hex: hx(m.data), Detail: "canon: " + pc})
			case c == baseCanon:
				rep.Equivalent++
				rep.add(Candidate{Kind: AcceptEquivalent, Mutation: m.name, Region: region, Hex: hx(m.data)})
			default:
				rep.Different++
				rep.add(Candidate{Kind: AcceptDifferent, Mutation: m.name, Region: region, Hex: hx(m.data)})
			}
		default:
			rep.Rejects++
			if !o.SkipTiming {
				ns := minTime(t.Verify, m.data, o.TimingReps)
				rejectTimes = append(rejectTimes, ns)
				if m.off >= t.MACStart && m.off < t.MACEnd && t.MACEnd > t.MACStart && len(m.name) > 7 && m.name[:7] == "bitflip" {
					pos = append(pos, PosSample{m.off, ns})
				}
				slowCands = append(slowCands, slow{m, ns})
			}
		}
	}
	generate(t, o, rng, emit)

	if !o.SkipTiming && len(rejectTimes) > 0 {
		sorted := append([]int64(nil), rejectTimes...)
		slices.Sort(sorted)
		med := sorted[len(sorted)/2]
		rep.MedianNS = med
		thr := int64(float64(med) * o.TimingFactor)
		for _, s := range slowCands {
			if s.ns > thr && s.ns-med > timingFloorNS {
				// Re-time before believing it: GC pauses and scheduler noise
				// are single events, a real slow path is repeatable.
				a := minTime(t.Verify, s.m.data, 20)
				b := minTime(t.Verify, s.m.data, 20)
				if a > thr && b > thr && a-med > timingFloorNS && b-med > timingFloorNS {
					rep.TimingFlags++
					rep.add(Candidate{Kind: Timing, Mutation: s.m.name, Hex: hx(s.m.data),
						Detail: fmt.Sprintf("min %dns,%dns vs median %dns", a, b, med)})
				}
			}
		}
		if len(pos) >= 16 {
			rep.PosRatio = posRatio(pos, t.MACStart, t.MACEnd)
			rep.PosSkew = rep.PosRatio > 1.5 || (rep.PosRatio > 0 && rep.PosRatio < 1/1.5)
		}
	}
	return rep, nil
}

func (r *Report) add(c Candidate) {
	key := c.Kind + "/" + c.Region
	r.ByRegion[key]++
	// Keep the report bounded: first 8 examples per (kind, region), but all
	// PANIC / ACCEPT-DIFFERENT / TIMING are never the dropped class by
	// count alone because ByRegion keeps the totals.
	n := 0
	for _, e := range r.Candidates {
		if e.Kind == c.Kind && e.Region == c.Region {
			n++
		}
	}
	if n < 8 {
		r.Candidates = append(r.Candidates, c)
	}
}

func hx(b []byte) string {
	if len(b) > 2048 {
		b = b[:2048]
	}
	return hex.EncodeToString(b)
}

func safeVerify(f func([]byte) bool, b []byte) (ok bool, panicMsg string) {
	defer func() {
		if r := recover(); r != nil {
			ok, panicMsg = false, fmt.Sprint(r)
		}
	}()
	// Verify must not retain or mutate its input; hand it a copy so a
	// verifier that does cannot corrupt later mutations.
	return f(append([]byte(nil), b...)), ""
}

func safeCanon(f func([]byte) string, b []byte) (s string, panicMsg string) {
	defer func() {
		if r := recover(); r != nil {
			panicMsg = fmt.Sprint(r)
		}
	}()
	return f(append([]byte(nil), b...)), ""
}

func minTime(f func([]byte) bool, b []byte, reps int) int64 {
	best := int64(1<<62 - 1)
	for range reps {
		cp := append([]byte(nil), b...)
		t0 := time.Now()
		func() {
			defer func() { _ = recover() }()
			f(cp)
		}()
		if d := time.Since(t0).Nanoseconds(); d < best {
			best = d
		}
	}
	return best
}

// timingFloorNS: see PREREG amendment 1. A reject must exceed the median by
// this absolute amount as well as by Options.TimingFactor, so the legitimate
// two-population shape (cheap structural reject vs a public-key verification
// or KEM decapsulation) is not reported; pathological work still is.
const timingFloorNS = 2_000_000

// PosSample is one timed single-bit-flip reject inside the MAC field.
type PosSample struct {
	Off int
	NS  int64
}

// posRatio: see Report.PosRatio. Trimmed (top 10% dropped) mean of the
// first quarter of the MAC field divided by that of the last quarter.
func posRatio(s []PosSample, start, end int) float64 {
	q := (end - start) / 4
	if q == 0 {
		return 0
	}
	var a, b []int64
	for _, p := range s {
		switch {
		case p.Off < start+q:
			a = append(a, p.NS)
		case p.Off >= end-q:
			b = append(b, p.NS)
		}
	}
	ma, mb := trimmedMean(a), trimmedMean(b)
	if ma == 0 || mb == 0 {
		return 0
	}
	return ma / mb
}

func trimmedMean(v []int64) float64 {
	if len(v) == 0 {
		return 0
	}
	slices.Sort(v)
	v = v[:len(v)-len(v)/10]
	var sum float64
	for _, x := range v {
		sum += float64(x)
	}
	return sum / float64(len(v))
}
