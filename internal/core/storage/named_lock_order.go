package storage

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
)

// NamedLockOrder is the single declared acquisition order for every
// WithNamedLock key family, outermost first. A call chain may only acquire a
// key whose family comes strictly LATER than every key it already holds, or —
// within one family — a key whose numeric id is strictly GREATER (the
// ascending-id discipline withOrderedUserSoDLocks and
// lockProjectAdminGuardsInOrder already follow). Re-acquiring a key the chain
// already holds is reentrant and always allowed (INV-STORE-02).
//
// Why this exists: the 2026-10-03 race fixes (#2664-#2678) made named locks
// nest in new ways (membership -> sod-grant, last-admin -> project-admin, ...).
// Two chains nesting the same two families in opposite orders deadlock under
// Postgres advisory locks — across replicas, where no Go deadlock detector
// sees it. The order was derived from the nestings the internal/core suite
// actually performs (observed by tracing every nested acquisition), not
// chosen to make them pass: if a new nesting contradicts this table, that
// is a lock-order inversion to fix in the code, NOT a reason to reorder the
// table.
//
// Every key passed to WithNamedLock must belong to a family declared here;
// with the check enabled an undeclared family is itself a violation, so a
// new key family cannot be introduced without placing it in the order.
//
// Not covered: in-process sync.Mutex fields on KeyorixCore (accountStateMu,
// globalAdminGuardMu, ...), which some named-lock holders take inside their
// critical section. Those are not routed through WithNamedLock, so this
// check never sees them (#2694).
var NamedLockOrder = []string{
	"dual-control-approval:request:", // dualControlLockKey (internal/core/invitations.go)
	"last-admin-guard",               // lastAdminGuardLockKey (internal/core/account_state.go)
	"project-membership:",            // membershipLockKey (internal/core/membership_lifecycle.go)
	"project-admin-guard:",           // projectAdminGuardLockKey (internal/core/project_members.go)
	"sod-grant:group:",               // sodGrantLockKey("group", id)
	"sod-grant:machine:",             // sodGrantLockKey("machine", id)
	"sod-grant:user:",                // sodGrantLockKey("user", id)
	"secret-dependency-graph:",       // secretDependencyGraphLockKey (internal/core/secret_dependencies.go)
	"environment-secret-guard:",      // EnvironmentSecretGuardLockKey (this package)
}

// namedLockFamily returns the family's rank in NamedLockOrder and the key's
// suffix after the family prefix, or rank -1 if no family matches. Families
// are matched longest-prefix-first so one prefix can never shadow another.
func namedLockFamily(key string) (int, string) {
	best, bestLen := -1, -1
	for i, p := range NamedLockOrder {
		if (key == p || strings.HasPrefix(key, p)) && len(p) > bestLen {
			best, bestLen = i, len(p)
		}
	}
	if best < 0 {
		return -1, ""
	}
	return best, key[bestLen:]
}

// namedLockIDLess compares two same-family suffixes as ':'-separated unsigned
// integers, lexicographically by component. ok is false when either suffix is
// not of that shape (then no within-family order is defined).
func namedLockIDLess(a, b string) (less, ok bool) {
	pa, pb := strings.Split(a, ":"), strings.Split(b, ":")
	if len(pa) != len(pb) {
		return false, false
	}
	for i := range pa {
		x, err1 := strconv.ParseUint(pa[i], 10, 64)
		y, err2 := strconv.ParseUint(pb[i], 10, 64)
		if err1 != nil || err2 != nil {
			return false, false
		}
		if x != y {
			return x < y, true
		}
	}
	return false, true
}

// CheckNamedLockOrder reports whether acquiring key while holding every key in
// held respects NamedLockOrder. held must not contain key (the reentrant case
// never reaches this check).
func CheckNamedLockOrder(held map[string]bool, key string) error {
	rank, id := namedLockFamily(key)
	if rank < 0 {
		return fmt.Errorf("named lock %q belongs to no family declared in storage.NamedLockOrder — declare its place in the order", key)
	}
	for h := range held {
		if h == key {
			continue
		}
		hr, hid := namedLockFamily(h)
		switch {
		case hr < 0:
			return fmt.Errorf("named lock %q is held but belongs to no declared family", h)
		case hr > rank:
			return fmt.Errorf("lock-order inversion: acquiring %q (family %q) while holding %q (family %q), which NamedLockOrder places after it", key, NamedLockOrder[rank], h, NamedLockOrder[hr])
		case hr == rank:
			less, ok := namedLockIDLess(hid, id)
			if !ok {
				return fmt.Errorf("lock-order inversion: acquiring %q while holding %q from the same family, whose ids have no defined order", key, h)
			}
			if !less {
				return fmt.Errorf("lock-order inversion: acquiring %q while holding %q — same family, ids must be acquired in ascending order", key, h)
			}
		}
	}
	return nil
}

var namedLockOrderCheck atomic.Bool

// EnableNamedLockOrderCheck turns on CheckNamedLockOrder enforcement inside
// WithNamedLock for the rest of the process: an out-of-order acquisition then
// panics. It is meant to be called from test binaries only (an init() in a
// _test.go file); production binaries never call it, so there the check costs
// one atomic load per acquisition.
func EnableNamedLockOrderCheck() { namedLockOrderCheck.Store(true) }

// NamedLockOrderCheckEnabled reports whether EnableNamedLockOrderCheck was called.
func NamedLockOrderCheckEnabled() bool { return namedLockOrderCheck.Load() }
