# NOTE (not a bug): bulk-reject/bulk-approve access-request ops' unconditional summary audit event legitimately differs in content when the single requested item fails — the oracle's error-branch has no exemption mechanism for this yet

**Date:** 2026-10-02
**Component:** `server/faultops/fuzz_storage_fault_operations_test.go` (the
oracle (a) error-path `default:` branch), surfaced by
`internal/core/bulk_access_requests.go`'s `BulkRejectAccessRequests`/
`BulkApproveAccessRequests`.
**Status:** Not a bug — documenting a harness scoping limitation found
while fixing the opCatalog per-item/envelope result-detection gap (see the
`SESSION-FI (AT5)` comments on the `bulk-delete`/`bulk-reject`/
`bulk-approve`/`bulk-rename`/`bulk-rotate` ops in `opcatalog_test.go`).

## Summary

After fixing `bulk-reject`'s opCatalog `Execute` to correctly report
`Success: false` when the one requested item lands in the response's
`failed` array (rather than trusting the HTTP envelope's unconditional
200), the fuzzer's reproduction of `fault=GetAccessRequest#1/error`
(`server/faultops/testdata/fuzz/FuzzStorageFaultOperations/641bee1094876d56`)
narrows from a 3-table diff to exactly `[AuditEvent]`.

This is the SAME shape `onlyOutcomeLogTables` (this file, line ~740)
already generalizes and accepts UNCONDITIONALLY — but only inside the
`case in.result.Success:` branch, specifically because (per that check's
own comment) "oracle (c) above already ran first and would have caught
the dangerous case... before execution ever reaches this branch." The
`default:` branch (oracle (a)'s error-reporting case, `in.after.Hash !=
in.before.Hash`) has no equivalent exemption — any state change at all
after a reported error is flagged, unconditionally.

`BulkRejectAccessRequests`/`BulkApproveAccessRequests` always write one
unconditional summary audit event ("bulk-reject attempted for N access
request(s): X rejected, Y failed") regardless of outcome — its CONTENT
(the X/Y counts) honestly differs between the reference run (item
succeeds) and the faulted run (item fails), same as `isGlobalAdminRoleName`'s
sibling cases already established elsewhere in this campaign as benign
audit-content variation, not a business-state inconsistency: the actual
`AccessRequest` row and any `Notification` are correctly NOT created in the
faulted run (confirmed by this exact fix — those two tables no longer
appear in the diff once `Success` correctly reflects the per-item outcome).

## Why this is not being silently exempted

Extending `onlyOutcomeLogTables`/`acceptableByDesign` to the `default:`
branch would very likely be correct, but that branch's existing design
deliberately scoped the blanket exemption to the success case only, with
an explicit safety argument (oracle (c) already ran) that has not been
independently re-validated for the error-reporting path. Making that
change without the same care (a red/green check against a case where it
SHOULD still catch a real bug in the error path) risks weakening a
safety-critical oracle on the strength of one observation. Left as a
`knownOpenTolerance` instead — narrowly scoped to this exact
(op, method, kind) triple — so the corpus entry can be committed without
either failing CI or silently broadening the oracle's own exemption logic.

## Suggested follow-up (not done here)

If this same AuditEvent-only-diff-on-error shape recurs on other ops
(worth checking `BulkApproveAccessRequests` independently — same
unconditional summary-audit pattern, not yet fuzzer-confirmed), consider
generalizing `onlyOutcomeLogTables` to the `default:` branch with its own
explicit safety argument and a dedicated red/green validation (a planted
bug that SHOULD still be caught there), rather than accumulating
per-triple `knownOpenTolerances` entries for what is structurally the same
benign pattern each time.
