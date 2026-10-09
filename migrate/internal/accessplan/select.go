package accessplan

import "fmt"

// SelectForApply picks, from a freshly re-derived plan (in its own order), the items
// apply-access hands to Apply:
//
//   - every item the operator reviewed (its Key is in reviewed) that STILL resolves to Create;
//   - every Skip-outcome Role/MachineIdentity item, reviewed or not. These are never written
//     (Apply only reads their ExistingID); they are what lets a resumed run attach a grant or
//     OIDC binding to a parent an earlier, interrupted run already created. Without them a
//     resumed run fails every such grant with "parent ... was not created in this run".
//
// warnings lists reviewed items that are no longer Create, or no longer in the live state.
func SelectForApply(fresh []Item, reviewed map[string]bool) (selected []Item, warnings []string) {
	seen := map[string]bool{}
	for _, it := range fresh {
		key := Key(it)
		if it.Outcome == Skip && (it.Kind == KindRole || it.Kind == KindMachineIdentity) {
			selected = append(selected, it) // read-only seed for Apply, never executed.
			seen[key] = true
			continue
		}
		if !reviewed[key] {
			continue // never execute something the operator did not review.
		}
		seen[key] = true
		if it.Outcome != Create {
			warnings = append(warnings, fmt.Sprintf("%s %s no longer resolves to \"create\" (now %q) — not applied; re-run plan-access and review", it.Kind, it.SourceRef, it.Outcome))
			continue
		}
		selected = append(selected, it)
	}
	for key := range reviewed {
		if !seen[key] {
			warnings = append(warnings, fmt.Sprintf("reviewed item %q is no longer part of the live Vault/Keyorix state — not applied; re-run plan-access and review", key))
		}
	}
	return selected, warnings
}
