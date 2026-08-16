// audit_retention_anchor.go — chain re-anchor for retention-purge compatibility
// (ADR-029).
//
// The audit hash chain (local_audit_chain.go) always starts at auditGenesisHash
// — the true first-ever row. Once a retention purge (PurgeAuditLogs) hard-
// deletes the earliest rows, the new earliest surviving row still carries a
// real prev_hash pointing at its now-deleted predecessor, so a bare re-walk
// from genesis reports a broken chain forever — indistinguishable from real
// tampering, and permanently disabling both VerifyAuditChain and
// WriteAuditCheckpoint (which refuses to sign over a broken chain).
//
// A retention anchor closes that gap: it records that a purge was sanctioned by
// persisting the new earliest surviving row's id/prev_hash/entry_hash, HMAC-
// signed with the same checkpoint signing key (KEK-derived, held in memory by
// this process only — the database/DBA does not have it, mirroring
// audit_checkpoint.go's own signing key). A DB-level actor cannot forge an
// anchor claiming an arbitrary gap is fine: without the key, any forged value
// fails signature verification and is ignored, and the walk then requires
// genesis again — the existing, safe (if inconvenient) failure mode.
//
// Persisted as a SINGLE overwritten system_metadata row (like the high-water
// mark, auditHighWaterKey) — it always reflects the earliest surviving row as
// of the MOST RECENT purge that reached into the chained (post-ADR-029)
// region, so an older anchor can never be replayed to claim a LARGER surviving
// prefix than what a subsequent purge actually left: any mismatch between the
// anchor's claimed row and the live earliest row is reported as a broken
// chain (see local_audit_chain.go's VerifyAuditChain), never silently trusted.
package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// auditRetentionAnchorKey is the system_metadata key holding the signed
// retention re-anchor.
const auditRetentionAnchorKey = "audit_retention_anchor" // #nosec G101 -- metadata key name, not a credential

// auditRetentionAnchorSep separates fields in the persisted value. Must not be
// "\x00": PostgreSQL text/varchar columns reject an embedded NUL byte outright
// (see auditHighWaterSep's doc comment for the same constraint on the
// high-water mark, which this mirrors).
const auditRetentionAnchorSep = "\x1f"

// auditRetentionAnchorCanonical is the exact byte string signed/verified for a
// retention anchor. The "retanchor-v1" prefix domain-separates it from
// checkpointCanonical and auditHighWaterValue's own layouts — an HMAC valid for
// one of those must never also verify as a valid retention anchor, or vice
// versa, even though all three share the same underlying signing key.
func auditRetentionAnchorCanonical(rowID uint, prevHash, entryHash, keyVersion string) string {
	return fmt.Sprintf("retanchor-v1\x00%d\x00%s\x00%s\x00%s", rowID, prevHash, entryHash, keyVersion)
}

// signRetentionAnchorWithVersion computes the HMAC over the anchor fields under
// the given key_version label (not necessarily the current one — see
// loadAuditRetentionAnchor, which recomputes under a STORED key_version purely
// to tell an actual tamper apart from a stale anchor left by a signing-key
// rotation; either way c.auditCkptKey is the only key bytes this process has).
func (c *KeyorixCore) signRetentionAnchorWithVersion(rowID uint, prevHash, entryHash, keyVersion string) string {
	mac := hmac.New(sha256.New, c.auditCkptKey)
	mac.Write([]byte(auditRetentionAnchorCanonical(rowID, prevHash, entryHash, keyVersion)))
	return hex.EncodeToString(mac.Sum(nil))
}

// signRetentionAnchor signs a fresh anchor under the CURRENT signing key/version.
func (c *KeyorixCore) signRetentionAnchor(rowID uint, prevHash, entryHash string) string {
	return c.signRetentionAnchorWithVersion(rowID, prevHash, entryHash, c.auditCkptKeyVersion)
}

// auditRetentionAnchorValue serializes a retention anchor for persistence via
// SetSystemMetadata.
func auditRetentionAnchorValue(rowID uint, prevHash, entryHash, keyVersion, sig string) string {
	return strings.Join([]string{
		"v1",
		strconv.FormatUint(uint64(rowID), 10),
		prevHash,
		entryHash,
		keyVersion,
		sig,
	}, auditRetentionAnchorSep)
}

// parseAuditRetentionAnchor parses a stored value back into its fields. ok is
// false on any malformed value (treated as "no anchor").
func parseAuditRetentionAnchor(val string) (rowID uint, prevHash, entryHash, keyVersion, sig string, ok bool) {
	parts := strings.Split(val, auditRetentionAnchorSep)
	if len(parts) != 6 || parts[0] != "v1" {
		return 0, "", "", "", "", false
	}
	id, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil || id == 0 {
		return 0, "", "", "", "", false
	}
	return uint(id), parts[2], parts[3], parts[4], parts[5], true
}

// persistAuditRetentionAnchor signs and stores a fresh retention anchor for the
// given new-earliest-surviving row. Called by PurgeAuditLogs INSIDE the same
// transaction as the delete (via tx, the transaction-scoped storage.Storage)
// whenever DeleteAuditLogsBefore reports the purge reached into the chained
// (post-ADR-029) region — see its doc comment. A no-op (logged, not fatal) when
// no signing key is configured: without a key, no marker could be authenticated
// anyway (see AuditCheckpointsAvailable), so writing an unsigned one would only
// create a plain, DB-forgeable marker — worse than no marker at all.
func (c *KeyorixCore) persistAuditRetentionAnchor(ctx context.Context, tx storage.Storage, rowID uint, prevHash, entryHash string) error {
	if !c.AuditCheckpointsAvailable() {
		log.Printf("audit retention: purge reached into the chained region but no checkpoint signing key is configured — the audit chain will not verify past this purge until encryption is enabled and a subsequent purge re-anchors it")
		return nil
	}
	sig := c.signRetentionAnchor(rowID, prevHash, entryHash)
	val := auditRetentionAnchorValue(rowID, prevHash, entryHash, c.auditCkptKeyVersion, sig)
	return tx.SetSystemMetadata(ctx, auditRetentionAnchorKey, val)
}

// loadAuditRetentionAnchor reads and authenticates the current retention
// anchor, returning nil when none exists, it fails to parse, or its signature
// does not verify — either genuine tampering, or a stale anchor left by a
// signing-key rotation (a KEK-provider migration; we hold only the CURRENT key,
// so an anchor signed under a superseded one can never be re-verified here).
// Either way it is safest to ignore an unverifiable anchor rather than trust
// it: the walk then requires genesis and correctly reports the trail broken
// until a fresh purge re-anchors it under the current key — never silently
// treats an unauthenticated value as a valid seed point. Only a genuine storage
// failure reading it is returned as an error.
func (c *KeyorixCore) loadAuditRetentionAnchor(ctx context.Context) (*storage.AuditChainAnchor, error) {
	if !c.AuditCheckpointsAvailable() {
		return nil, nil
	}
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditRetentionAnchorKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	rowID, prevHash, entryHash, keyVersion, sig, parsed := parseAuditRetentionAnchor(val)
	if !parsed {
		log.Printf("audit retention anchor is malformed — ignoring it")
		return nil, nil
	}
	computed := c.signRetentionAnchorWithVersion(rowID, prevHash, entryHash, keyVersion)
	if !hmac.Equal([]byte(computed), []byte(sig)) {
		if keyVersion == c.auditCkptKeyVersion {
			log.Printf("audit retention anchor fails its signature under the current key version %q — ignoring it (the marker was tampered with; chain verification requires genesis and will report broken until a fresh purge re-anchors it)", keyVersion)
		} else {
			log.Printf("audit retention anchor is signed under a superseded key version %q — ignoring it (a KEK-provider migration likely occurred; a fresh retention purge re-anchors it under the current key)", keyVersion)
		}
		return nil, nil
	}
	return &storage.AuditChainAnchor{RowID: rowID, PrevHash: prevHash, EntryHash: entryHash}, nil
}
