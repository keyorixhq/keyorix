package main

import (
	"fmt"
	"slices"
	"strings"
)

// fix1Entries are the core entry points FIX-1 moved from the removed
// name-based requireAuthorityForRole onto requireGranterHoldsRolePermissions
// (internal/core/invitations.go's FIX-1 note). InviteToProject and InviteGlobal
// are one guard; together these are the 8 calibration guards.
var fix1Entries = []string{
	"AssignRoleToGroup", "AssignGroupRoleWithExpiry", "AssignMachineRole", "AddUserToGroup",
	"CreateUserWithAssignments", "InviteToProject", "InviteGlobal",
	"InviteToProjectWithLink", "InviteGlobalWithLink",
	"ApproveAccessRequestWithExpiry", "TransitionMembership",
}

// expectedDead are FIX-1-listed entries with no production caller at
// bd16d6921 (grep `\b<name>\(` over internal/ and server/ non-test finds only
// the declaration). Their live twins are the *WithLink methods, which share
// buildProjectInvite / the global-invite builder. A dead entry passes
// calibration only if the SSA walk ALSO finds zero ops reaching it; if a caller
// appears, the row fails so the oracle is re-derived.
var expectedDead = map[string]bool{"InviteToProject": true, "InviteGlobal": true}

func calibrationNames() []string { return append(slices.Clone(fix1Entries), guardFuncs...) }

// grepOracle is the INDEPENDENT expectation: derived by a plain text search for
// `\.<Entry>\(` call sites under server/ (non-test) and the enclosing func of
// each hit, done by hand on 2026-11-04 at origin/main bd16d6921 — a different
// method from the SSA walk, so agreement is evidence and disagreement is an error
// in one of them. Handler suffixes are matched against Op.Handler.
// InviteToProject/InviteGlobal have no direct server/ call site (reached only
// through core wrappers), so the oracle only requires that SOME op reaches them.
var grepOracle = map[string][]string{
	"AssignRoleToGroup":              {"REST:AssignRoleToGroup"},
	"AssignGroupRoleWithExpiry":      {"REST:AssignRoleToGroup"},
	"AddUserToGroup":                 {"REST:AddGroupMember", "GRPC:AddGroupMember"},
	"CreateUserWithAssignments":      {"REST:CreateUser", "GRPC:CreateUser"},
	"AssignMachineRole":              {"REST:GrantMachineRole", "REST:RemoveMachineRole"},
	"ApproveAccessRequestWithExpiry": {"REST:ResolveAccessRequest"},
	"TransitionMembership":           {"REST:TransitionMembership"},
	"InviteToProject":                {},
	"InviteGlobal":                   {},
	"InviteToProjectWithLink":        {"REST:CreateInvitation"},
	"InviteGlobalWithLink":           {"REST:CreateGlobalInvitation"},
}

// calibrateSelfTest proves calibrate can go red: each planted wrong
// expectation (a gRPC twin that does not exist; a dead entry marked live; a
// guard dropped from every op's reach) must make it fail. Returns the cases
// that wrongly stayed green.
func calibrateSelfTest(ops []*Op) []string {
	var stayedGreen []string
	try := func(name string, mutate func() func()) {
		restore := mutate()
		if _, ok := calibrate(ops); ok {
			stayedGreen = append(stayedGreen, name)
		}
		restore()
	}
	try("nonexistent gRPC twin", func() func() {
		old := grepOracle["AssignMachineRole"]
		grepOracle["AssignMachineRole"] = append(slices.Clone(old), "GRPC:GrantMachineRole")
		return func() { grepOracle["AssignMachineRole"] = old }
	})
	try("live entry marked dead", func() func() {
		expectedDead["TransitionMembership"] = true
		return func() { delete(expectedDead, "TransitionMembership") }
	})
	try("guard removed from reach", func() func() {
		saved := map[*Op][]string{}
		for _, op := range ops {
			if slices.Contains(op.GuardReach, "requireGranterHoldsRolePermissions") && slices.Contains(op.GuardReach, "AddUserToGroup") {
				saved[op] = op.GuardReach
				op.GuardReach = slices.DeleteFunc(slices.Clone(op.GuardReach), func(s string) bool { return s == "requireGranterHoldsRolePermissions" })
			}
		}
		return func() {
			for op, g := range saved {
				op.GuardReach = g
			}
		}
	})
	return stayedGreen
}

// calibrate returns a report and whether every expectation held.
func calibrate(ops []*Op) (string, bool) {
	var b strings.Builder
	ok := true
	fmt.Fprintf(&b, "| FIX-1 entry | expected (grep oracle) | found by SSA walk (ops reaching it) | reaches requireGranterHoldsRolePermissions | result |\n|---|---|---|---|---|\n")
	for _, e := range fix1Entries {
		var found []string
		guarded := false
		for _, op := range ops {
			if !slices.Contains(op.GuardReach, e) {
				continue
			}
			found = append(found, op.Key)
			if slices.Contains(op.GuardReach, "requireGranterHoldsRolePermissions") {
				guarded = true
			}
		}
		var missing []string
		for _, want := range grepOracle[e] {
			layer, name, _ := strings.Cut(want, ":")
			hit := false
			for _, op := range ops {
				if strings.EqualFold(op.Layer, layer) && strings.HasSuffix(op.Handler, "."+name) && slices.Contains(op.GuardReach, e) {
					hit = true
				}
			}
			if !hit {
				missing = append(missing, want)
			}
		}
		res := "PASS"
		if expectedDead[e] {
			if len(found) == 0 {
				res = "PASS (dead: no production caller, as expected)"
			} else {
				res = "FAIL expected dead but reached — re-derive the oracle"
				ok = false
			}
		} else if len(missing) > 0 || len(found) == 0 || !guarded {
			res = fmt.Sprintf("FAIL missing=%v found=%d guarded=%v", missing, len(found), guarded)
			ok = false
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", e, strings.Join(grepOracle[e], ", "), cell(found), yn(guarded), res)
	}
	return b.String(), ok
}
