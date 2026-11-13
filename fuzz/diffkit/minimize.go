package diffkit

// Minimize shrinks a diverging input while the divergence persists.
//
// It is a generic, greedy delta-minimiser: given the current input it asks
// candidates for a list of strictly-smaller candidates, adopts the first one
// that still satisfies stillDiverges, and repeats until no candidate reduces
// further. The result is a local minimum (not guaranteed global), which is the
// standard, cheap guarantee a fuzzer minimiser gives.
//
// stillDiverges MUST be deterministic for a stable result; for a flaky
// divergence, wrap it to require the divergence to reproduce N times (see
// ByteShrink's use in the instances, which replays 3x before trusting a shrink).
func Minimize[In any](in In, candidates func(In) []In, stillDiverges func(In) bool) In {
	cur := in
	for {
		progressed := false
		for _, cand := range candidates(cur) {
			if stillDiverges(cand) {
				cur = cand
				progressed = true
				break
			}
		}
		if !progressed {
			return cur
		}
	}
}

// ByteCandidates is a ready-made candidate generator for []byte inputs: it
// proposes removing chunks (halves, then quarters, … down to single bytes).
// It is the usual building block for Minimize over byte slices.
func ByteCandidates(b []byte) [][]byte {
	if len(b) <= 1 {
		return nil
	}
	var out [][]byte
	// Remove contiguous chunks of decreasing size.
	for chunk := len(b) / 2; chunk >= 1; chunk /= 2 {
		for i := 0; i+chunk <= len(b); i += chunk {
			cand := make([]byte, 0, len(b)-chunk)
			cand = append(cand, b[:i]...)
			cand = append(cand, b[i+chunk:]...)
			out = append(out, cand)
		}
	}
	return out
}
