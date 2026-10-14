// local_folded_credential.go — the live machine-credential re-check, widened
// to read one secret's node in the same statement (PERF-LEVER2).
//
// On a machine-token cache hit for a secret read, the auth middleware asks for
// the fold by putting a ReadPathPrefetch with a fold target on the request
// (storage.NewReadPathPrefetchFolding). GetMachineIdentityCredentialWithIdentityStateByHash
// then runs ONE statement:
//
//   - the credential and identity-state columns, exactly credentialLookupRawQuery's
//     select list, FROM/JOIN and WHERE, scanned into the same fields in the same order;
//   - LEFT JOIN secret_nodes n on the fold target, plus the node read's select
//     list and joins (readPathPrefetchParts: stamp, trigger proof, roles at the
//     warm entry's scope, generation, and schedule/versions when asked).
//
// The credential comes back to the caller exactly as the plain statement would
// return it, and the caller judges it with the same code at the same point; a
// missing or deleted secret only makes the node columns NULL. Nothing here
// decides anything about the credential.
//
// The node answers are parked on the carrier (ParkNodeStamp) for the machine
// whose credential was read, and only when the node row was found. GetSecret
// takes them for that secret only, once, and serves the warm entry only when
// the parked stamp equals the cached generation, the trigger was proven in this
// statement, and the entry is the one whose scope the roles were read for
// (getCachedSecret). Any other outcome is today's path.
//
// When the fold cannot run (a transaction-scoped store, the node cache off or
// cold for that secret) or the statement fails or finds no credential row, the
// plain credential statement runs instead and its answer is returned. So the
// fold can never turn an error into a cached-snapshot answer: the caller only
// ever sees the plain statement's error.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// foldedNodeState is the parked node read (PrefetchedNodeStamp.State).
type foldedNodeState struct {
	stamp nodeStampRead
	// entryGeneration is the generation of the warm entry whose scope the
	// roles were read at.
	entryGeneration nodeGeneration
	perm            *storage.PrefetchedPermission
	sched           *storage.PrefetchedScheduleVersion
}

const foldedCredentialCols = `SELECT c.id, c.machine_identity_id, c.name, c.token_hash, c.token_prefix,
       c.allowed_c_id_rs, c.last_used_at, c.expires_at, c.revoked, c.created_at,
       c.classification, m.state AS identity_state, `

// getMachineCredentialFolded runs the folded statement. ok is false when it
// cannot or did not answer (the caller then runs the plain statement); the
// returned node state is nil when the secret's row was not found.
func (ls *LocalStorage) getMachineCredentialFolded(ctx context.Context, hash string, pf *storage.ReadPathPrefetch, secretID uint) (*models.MachineIdentityCredential, string, *foldedNodeState, bool) {
	if ls.rawStmts == nil || !ls.cacheEnabled {
		return nil, "", nil, false
	}
	cached, ok := ls.secretMetaCache.getNode(secretID)
	if !ok || cached.node == nil {
		return nil, "", nil, false
	}
	parts := ls.readPathPrefetchParts(pf, secretID, cached.node)
	q := foldedCredentialCols + parts.cols +
		"\nFROM machine_identity_credentials c\nJOIN machine_identities m ON m.id = c.machine_identity_id" +
		"\nLEFT JOIN secret_nodes n ON n.id = ? AND n.deleted_at IS NULL\n" + parts.joins +
		"\nWHERE c.token_hash = ?"
	args := make([]any, 0, len(parts.colArgs)+len(parts.joinArgs)+2)
	args = append(append(append(append(args, parts.colArgs...), secretID), parts.joinArgs...), hash)

	rows, err := ls.db.WithContext(ctx).Raw(q, args...).Rows()
	if err != nil {
		return nil, "", nil, false
	}
	defer func() { _ = rows.Close() }()
	var (
		c             models.MachineIdentityCredential
		identityState string
		nodeRows      []readPathPrefetchRow
		nodeFound     bool
		n             int
	)
	for rows.Next() {
		var r readPathPrefetchRow
		var cacheEpoch *int64
		var trigger *bool
		dest := []any{
			&c.ID, &c.MachineIdentityID, &c.Name, &c.TokenHash, &c.TokenPrefix,
			&c.AllowedCIDRs, &c.LastUsedAt, &c.ExpiresAt, &c.Revoked, &c.CreatedAt,
			&c.Classification, &identityState,
			&cacheEpoch, &trigger, &r.RoleID, &r.Generation,
		}
		if pf.WantScheduleVersion {
			dest = append(dest, &r.Cnt, &r.MaxVer, &r.SumRc,
				&r.SchedID, &r.SchedSecretNodeID, &r.SchedAllowedDays,
				&r.SchedStartHour, &r.SchedEndHour, &r.SchedTimezone,
				&r.SchedCreatedAt, &r.SchedUpdatedAt)
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, "", nil, false
		}
		n++
		if cacheEpoch != nil {
			nodeFound = true
			r.CacheEpoch = *cacheEpoch
			r.TriggerPresent = trigger != nil && *trigger
			nodeRows = append(nodeRows, r)
		}
	}
	if rows.Err() != nil || n == 0 {
		// No credential row (or a failure): the plain statement answers, with
		// its own error.
		return nil, "", nil, false
	}
	if !nodeFound {
		return &c, identityState, nil, true
	}
	stamp, perm, sched := readPathPrefetchFromRows(pf, secretID, cached.node, nodeRows)
	return &c, identityState, &foldedNodeState{stamp: stamp, entryGeneration: cached.generation, perm: perm, sched: sched}, true
}

// foldedCredentialLookup runs the fold the request asked for, if any. handled
// is false when the plain statement must answer.
func (ls *LocalStorage) foldedCredentialLookup(ctx context.Context, hash string) (*models.MachineIdentityCredential, string, bool) {
	pf := storage.ReadPathPrefetchFrom(ctx)
	if pf == nil {
		return nil, "", false
	}
	secretID := pf.TakeFoldTarget()
	if secretID == 0 {
		return nil, "", false
	}
	cred, state, node, ok := ls.getMachineCredentialFolded(ctx, hash, pf, secretID)
	if !ok {
		return nil, "", false
	}
	// Parked only for the machine the carrier was built for, and only if it is
	// the machine this credential belongs to.
	if node != nil && cred.MachineIdentityID == pf.MachineID {
		pf.ParkNodeStamp(&storage.PrefetchedNodeStamp{SecretID: secretID, MachineID: pf.MachineID, State: node})
	}
	return cred, state, true
}

// takeFoldedNodeHit serves the warm entry from the parked node read when it
// confirms the entry (see the file header). Called by getCachedSecret.
func takeFoldedNodeHit(pf *storage.ReadPathPrefetch, id uint, cached secretNodeCacheEntry) bool {
	ns := pf.TakeNodeStamp(id, pf.MachineID)
	if ns == nil {
		return false
	}
	st, ok := ns.State.(*foldedNodeState)
	if !ok || !st.stamp.found || !st.stamp.trusted ||
		st.stamp.generation != cached.generation || st.entryGeneration != cached.generation {
		return false
	}
	pf.Park(st.perm, st.sched)
	return true
}
