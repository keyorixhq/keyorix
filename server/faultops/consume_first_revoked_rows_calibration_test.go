// consume_first_revoked_rows_calibration_test.go — INVITE-ACCEPT-NOV-1 item 4: red
// AND green for consumeFirstExemption.revokedRowsAdded on synthetic snapshots of the
// invitation_accept op (the real op's behaviour is the TestOpFaultSweep run in the PR
// body). The rule may accept the undone accept's residue (the spent link, one kept
// LoginAttempt slot, one revoked membership row) and nothing that looks like it.
package faultops

import (
	"strings"
	"testing"
)

func TestConsumeFirstRevokedRows_Calibration(t *testing.T) {
	const (
		tokLive    = `{"ID":1,"Purpose":"invitation_accept","State":"active"}`
		tokSpent   = `{"ID":1,"Purpose":"invitation_accept","State":"consumed"}`
		tokOther   = `{"ID":1,"Purpose":"account_setup","State":"consumed"}`
		memberOld  = `{"ID":1,"ProjectID":1,"Role":"project_admin","State":"active","UserID":1}`
		memberGone = `{"ID":1,"ProjectID":1,"Role":"project_admin","State":"revoked","UserID":1}`
		revoked    = `{"ID":2,"ProjectID":1,"Role":"project_viewer","State":"revoked","UserID":2}`
		revoked2   = `{"ID":3,"ProjectID":2,"Role":"project_viewer","State":"revoked","UserID":2}`
		live       = `{"ID":2,"ProjectID":1,"Role":"project_viewer","State":"active","UserID":2}`
		slot       = `{"ID":1,"IP":"203.0.113.1"}`
		admin      = `{"ID":1,"Username":"faultadmin"}`
		invitee    = `{"ID":2,"Username":"fuzzinvitee"}`
	)
	snap := func(tok string, members, slots, users []string) dbSnapshot {
		tbl := func(name string, rows []string) tableSnapshot {
			return tableSnapshot{Table: name, Hash: strings.Join(rows, "|"), Rows: rows}
		}
		return dbSnapshot{Tables: map[string]tableSnapshot{
			"SetupToken":        tbl("SetupToken", []string{tok}),
			"ProjectMembership": tbl("ProjectMembership", members),
			"LoginAttempt":      tbl("LoginAttempt", slots),
			"User":              tbl("User", users),
			"AuditEvent":        tbl("AuditEvent", []string{"audit-anything"}),
		}}
	}
	before := snap(tokLive, []string{memberOld}, nil, []string{admin})
	check := func(t *testing.T, after dbSnapshot, want bool, why string) {
		t.Helper()
		_, ok := consumeFirstAccountsForDiff(oracleInput{op: setupInvitationOpKey, before: before, after: after})
		if ok != want {
			t.Fatalf("predicate returned %v, want %v: %s", ok, want, why)
		}
	}

	t.Run("green: spent link, one slot, one revoked membership", func(t *testing.T) {
		check(t, snap(tokSpent, []string{memberOld, revoked}, []string{slot}, []string{admin}), true,
			"the undone accept's whole residue must be accepted, or the sweep stays red on the decided design")
	})
	t.Run("green: spent link and slot, the grant never reached the membership", func(t *testing.T) {
		check(t, snap(tokSpent, []string{memberOld}, []string{slot}, []string{admin}), true,
			"no membership row is a subset of the residue")
	})
	t.Run("red: the added membership is live", func(t *testing.T) {
		check(t, snap(tokSpent, []string{memberOld, live}, []string{slot}, []string{admin}), false,
			"a live membership is a grant the undo did not revert")
	})
	t.Run("red: two revoked rows, cap is one", func(t *testing.T) {
		check(t, snap(tokSpent, []string{memberOld, revoked, revoked2}, []string{slot}, []string{admin}), false,
			"more rows than the one membership a project invite makes")
	})
	t.Run("red: an existing membership was revoked", func(t *testing.T) {
		check(t, snap(tokSpent, []string{memberGone, revoked}, []string{slot}, []string{admin}), false,
			"an edit to a row that existed before is not this op's residue")
	})
	t.Run("red: the account stayed live", func(t *testing.T) {
		check(t, snap(tokSpent, []string{memberOld, revoked}, []string{slot}, []string{admin, invitee}), false,
			"the orphan account #4409 is about")
	})
	t.Run("red: the token changed in a column other than State", func(t *testing.T) {
		check(t, snap(tokOther, []string{memberOld, revoked}, []string{slot}, []string{admin}), false,
			"only the consumption column may move")
	})
}
