// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// #3508 (MERGE-FIX-3504B). Surfaced by CI's fuzz shard 2 + fuzz-changed on release
	// PR #3504 (input 032e733231), a PR that touches nothing in the secret-delete path.
	// Confirmed pre-existing by native replay by op key + storage method (the hex input
	// decodes to a different fault on main, whose method catalog differs): it fails on
	// the release base ac638181 without #3504's commits AND on origin/main f8bc35322.
	//
	// Real bug, low impact: SecretHandler.DeleteSecret commits the delete and its
	// secret.deleted audit row in one transaction (correct), then reads the purge date
	// back with DeletedSecretPurgeAt -> GetSecretIncludingDeleted. The handler already
	// tolerates an ERROR from that read-back ("a failed read-back must not turn a
	// completed delete into an error"), but a PANIC there is not recovered, so the
	// client sees an aborted request although the secret is deleted and audited.
	// AUDIT-MUTATION-TX-1 (v0.97.0) does not cover it: it is the read-back after the
	// transaction, not the transaction.
	//
	// Scoped to ONE op + ONE storage method + the panic kind + nth 1 + the three tables
	// the committed delete touches. The error kind on the same pair is not tolerated
	// (it passes). Remove this row in the PR that makes the read-back panic-safe (#3508).
	registerKnownOpenTolerance("delete_secrets_id_getsecretincludingdeleted_1_panic", knownOpenTolerance{
		op: "REST DELETE /api/v1/secrets/{id}", method: "GetSecretIncludingDeleted", kind: faultstorage.KindPanic,
		nth: 1, oracle: "a", issue: "#3508", expires: "2026-11-20",
		tables:     []string{"SecretNode", "AuditEvent", "SecretAccessLog"},
		findingDoc: "#3508",
	})
}
