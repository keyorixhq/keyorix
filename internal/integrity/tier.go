package integrity

import "fmt"

// MaxTier is the highest detected tier.
const MaxTier = 6

// rung is one step of the tier ladder. A tier is the number of consecutive
// rungs, from the first, whose condition holds; the first rung that does not
// hold stops the climb (its state, unknown included, is what TierWhy names).
type rung struct {
	name string
	// ids: the rung holds when ANY of these lines is StateOK.
	ids []string
}

// ladder defines tiers 1..6; tier 0 means rung 1 does not hold. The table in
// docs/security/integrity-posture.md is this slice, and TestTierTableMatchesDocs
// keeps the two equal.
var ladder = []rung{
	{"Secure Boot enabled", []string{CheckSecureBoot}},
	{"kernel lockdown integrity or confidentiality", []string{CheckLockdown}},
	// The release manifest is deliberately not a rung: its signature is never
	// verified in-process, so a match is not binary identity.
	{"running binary identity (fs-verity enabled)", []string{CheckFSVerity}},
	{"IMA appraise policy loaded", []string{CheckIMA}},
	{"KEK sealed to a TPM (no weaker fallback configured)", []string{CheckTPMSealing}},
	{"Keylime agent present", []string{CheckKeylime}},
}

// DetectTier derives the tier from the lines. It is a pure function of them:
// no I/O, no clock, and nothing reads the tier to decide anything.
func DetectTier(lines []Line) (int, string) {
	state := make(map[string]State, len(lines))
	for _, l := range lines {
		state[l.ID] = l.State
	}
	for i, r := range ladder {
		held := false
		for _, id := range r.ids {
			if state[id] == StateOK {
				held = true
				break
			}
		}
		if !held {
			return i, fmt.Sprintf("next rung not reached: %s (%s)", r.name, describeStates(r.ids, state))
		}
	}
	return MaxTier, "all rungs reached"
}

func describeStates(ids []string, state map[string]State) string {
	s := ""
	for i, id := range ids {
		if i > 0 {
			s += ", "
		}
		st := state[id]
		if st == "" {
			st = StateUnknown
		}
		s += id + " " + string(st)
	}
	return s
}

// LadderNames returns the rung names in order (tier n is reached by rungs 1..n).
func LadderNames() []string {
	out := make([]string, len(ladder))
	for i, r := range ladder {
		out[i] = r.name
	}
	return out
}
