package faultops

// MFA-RESET-TESTS-1 item 3. RequestMFAReset and ApproveMFAReset authorise with
// requireReauth (docs/atomicity-exempt.tsv class B, consume-first by design) BEFORE
// their transaction: the matched TOTP time-step (MFASecret.LastUsedStep) is burned
// first and must stay burned when the action fails, so a code that was accepted
// once cannot be replayed within its window. Same shape, same exemption, as
// REST POST /api/v1/auth/mfa/disable above.
//
// consumedColumns, not a whole-table MFASecret exemption: a genuine partial commit
// of the reset (DeleteMFAForUser committing while another step rolled back) shows
// as the MFASecret ROW vanishing or User.MFAEnabled flipping, which the
// LastUsedStep column exclusion does not hide. Oracle (g)
// (mfa_reset_oracle_test.go) additionally checks the half-reset directly.
//
// The cancel op needs no step-up (cancelling narrows), so it has no entry.
func init() {
	consumeFirstExemptions = append(consumeFirstExemptions,
		consumeFirstExemption{
			op:              "REST POST /api/v1/mfa-reset-requests",
			fn:              "(*KeyorixCore).requireReauth",
			consumedColumns: map[string][]string{"MFASecret": {"LastUsedStep"}},
			why:             "requireReauth burned the requester's TOTP time-step (MFASecret.LastUsedStep) before the request was written; it must stay burned so the same code cannot be replayed",
		},
		consumeFirstExemption{
			op:              "REST POST /api/v1/mfa-reset-requests/{id}/approve",
			fn:              "(*KeyorixCore).requireReauth",
			consumedColumns: map[string][]string{"MFASecret": {"LastUsedStep"}},
			why:             "requireReauth burned the approver's TOTP time-step (MFASecret.LastUsedStep) before the reset transaction; it must stay burned so the same code cannot be replayed",
		},
	)
}
