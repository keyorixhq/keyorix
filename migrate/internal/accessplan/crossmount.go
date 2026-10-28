package accessplan

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// CrossMountDrift re-checks the reviewed plan's Vault tree listing at apply time (ask
// rd-smt-fix-cross-mount-convention, Andrei's condition): for every policy stanza that resolved
// by the default convention or a --path-map entry in either plan, the reviewed plan's CrossMountEvidence must equal
// the fresh re-derivation's. It returns one line per stanza that differs: other-mount paths that
// appeared, disappeared or became unlistable, or a reviewed plan written before the evidence
// existed. apply-access refuses to write anything when this is non-empty: the reviewer approved
// a plan built on a Vault tree that is no longer the one being migrated.
//
// Stanzas present in only one of the two plans are not compared here; SelectForApply never
// executes an item the operator did not review.
func CrossMountDrift(reviewed, fresh []Item) []string {
	before, after := crossMountEvidenceByStanza(reviewed), crossMountEvidenceByStanza(fresh)
	var drift []string
	for ref, now := range after {
		was, ok := before[ref]
		if !ok || slices.Equal(was, now) {
			continue
		}
		switch {
		case was == nil:
			drift = append(drift, fmt.Sprintf("%s: the reviewed plan has no record of the other KV mounts at its scope (written before this check) — re-run plan-access; Vault now: %s", ref, strings.Join(now, "; ")))
		case now == nil:
			drift = append(drift, fmt.Sprintf("%s: no longer resolves to a scope checked against the other KV mounts (reviewed: %s) — re-run plan-access", ref, strings.Join(was, "; ")))
		default:
			drift = append(drift, fmt.Sprintf("%s: reviewed %s; Vault now: %s", ref, strings.Join(was, "; "), strings.Join(now, "; ")))
		}
	}
	sort.Strings(drift)
	return drift
}

// crossMountEvidenceByStanza maps each KindRole stanza (SourceRef) to its evidence. The same
// stanza appears once per role/user it is attached to, always with the same evidence; a nil
// value means the stanza is there without evidence (not a default-convention or --path-map resolution, or a
// plan file that predates the evidence).
func crossMountEvidenceByStanza(items []Item) map[string][]string {
	out := map[string][]string{}
	for _, it := range items {
		if it.Kind != KindRole || !strings.HasPrefix(it.SourceRef, "policy:") {
			continue
		}
		if _, seen := out[it.SourceRef]; !seen || it.CrossMountEvidence != nil {
			out[it.SourceRef] = it.CrossMountEvidence
		}
	}
	return out
}
