// Command pkcs7-driver is a single-version time-travel driver for
// github.com/digitorus/pkcs7. It is compiled once per historical library
// version by scripts/fuzzing/time-travel/run.sh (each build lives in its own
// scratch module that pins one version via a require directive, so two versions
// of the same import path never coexist in one binary — the fundamental reason
// the differential must cross a process boundary).
//
// Protocol (stable across versions, this is the contract the comparer relies on):
//
//	stdin : one corpus item per line, "<id>\t<hex>", hex = lowercase hex of the
//	        raw DER/BER input bytes (empty hex = empty input, a legal item).
//	stdout: one JSON object per line, in input order, with the canonical verdict.
//
// The canonical result deliberately records only version-stable facts:
//   - verdict  : "accept" (Parse returned nil error) or "reject".
//   - errclass : a coarse, wording-independent bucket of the error (see classify),
//     because upstream reworded several errors between versions and a raw-string
//     diff would drown real behaviour changes in cosmetic ones. The raw error is
//     also carried (errraw) so the comparer can separate wording-only changes.
//   - ncerts/ncontent: shape of the accepted structure, so an "accept whose parse
//     result changed" is visible even when the verdict did not.
//   - allocbucket: floor(log2(TotalAlloc delta)) during Parse — the bounded-work
//     signal. The disclosed GHSA-3xqc-rpq8-wgp9 amplification turned ~130 input
//     bytes into ~1.8 GB, i.e. allocbucket ~30 vs a normal parse's ~15, so a
//     coarse log2 bucket separates amplification from GC noise without being
//     flaky. A hard RLIMIT (set by the caller) turns a true amplification into a
//     process death the runner records as "oom", so this binary never eats the
//     host's memory.
//
// It never prints the library's raw error text unescaped and never panics out:
// a panic inside Parse is caught and reported as verdict "panic" with the
// recovered value's class, because a panic IS a behaviour (crewjam/saml taught us
// a bare third-party panic is a finding, not noise).
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
	"runtime"
	"strings"

	"github.com/digitorus/pkcs7"
)

type result struct {
	ID          string `json:"id"`
	Verdict     string `json:"verdict"` // accept | reject | panic
	ErrClass    string `json:"errclass"`
	ErrRaw      string `json:"errraw,omitempty"`
	NCerts      int    `json:"ncerts"`
	NContent    int    `json:"ncontent"`
	AllocBucket int    `json:"allocbucket"`
	InLen       int    `json:"inlen"`
}

// classify buckets an error (or recovered panic) message into a wording-stable
// token. The buckets are derived from the error surface digitorus/pkcs7 actually
// produces (ber2der conversion, asn1 unmarshal, unsupported content type,
// trailing data) — NOT guessed; new unmatched messages fall to "other" and the
// comparer surfaces "other" explicitly rather than hiding it.
func classify(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case msg == "":
		return "none"
	case strings.Contains(m, "ber2der") || strings.Contains(m, "indefinite") || strings.Contains(m, "ber "):
		return "ber"
	case strings.Contains(m, "invalid length") || strings.Contains(m, "length") || strings.Contains(m, "truncat") || strings.Contains(m, "out of bound") || strings.Contains(m, "index out of range"):
		return "length"
	case strings.Contains(m, "trailing"):
		return "trailing"
	case strings.Contains(m, "asn1") || strings.Contains(m, "unmarshal") || strings.Contains(m, "sequence") || strings.Contains(m, "tag") || strings.Contains(m, "integer"):
		return "asn1"
	case strings.Contains(m, "unsupported") || strings.Contains(m, "not supported") || strings.Contains(m, "unknown"):
		return "unsupported"
	case strings.Contains(m, "nil") || strings.Contains(m, "pointer"):
		return "nil"
	default:
		return "other"
	}
}

func allocBucket(d uint64) int {
	if d == 0 {
		return 0
	}
	return bits.Len64(d) // floor(log2)+1; monotone, coarse, stable.
}

func run(id string, data []byte) (res result) {
	res.ID = id
	res.InLen = len(data)
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	defer func() {
		runtime.ReadMemStats(&m1)
		res.AllocBucket = allocBucket(m1.TotalAlloc - m0.TotalAlloc)
		if r := recover(); r != nil {
			res.Verdict = "panic"
			res.ErrRaw = fmt.Sprint(r)
			res.ErrClass = classify(res.ErrRaw)
		}
	}()
	p7, err := pkcs7.Parse(data)
	if err != nil {
		res.Verdict = "reject"
		res.ErrRaw = err.Error()
		res.ErrClass = classify(res.ErrRaw)
		return res
	}
	res.Verdict = "accept"
	res.ErrClass = "none"
	if p7 != nil {
		res.NCerts = len(p7.Certificates)
		res.NContent = len(p7.Content)
	}
	return res
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 64<<20) // allow long hex lines
	// Encode straight to os.Stdout (one syscall per line, unbuffered from Go's
	// side) so each result reaches the pipe immediately. This is required by the
	// interactive oracle mode (FuzzPKCS7TimeTravelOracle writes one input and
	// blocks reading one result): a bufio.Writer that only flushes on exit would
	// deadlock that round-trip. The per-line syscall cost is negligible for the
	// batch runner too.
	enc := json.NewEncoder(os.Stdout)
	for in.Scan() {
		line := in.Text()
		if line == "" {
			continue
		}
		id, hx, ok := strings.Cut(line, "\t")
		if !ok {
			// tolerate "<hex>" only, id = line number is not available; use hex prefix
			hx = line
			id = ""
		}
		data, err := hex.DecodeString(strings.TrimSpace(hx))
		if err != nil {
			_ = enc.Encode(result{ID: id, Verdict: "badinput", ErrClass: "other", ErrRaw: "driver: bad hex"})
			continue
		}
		_ = enc.Encode(run(id, data))
	}
	if err := in.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "driver: scan error:", err)
		os.Exit(2)
	}
}
