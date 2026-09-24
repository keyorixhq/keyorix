package auditverify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// RetentionAnchor is this package's own representation of an authenticated
// retention re-anchor point (ADR-029 / audit_retention_anchor.go): the new
// earliest surviving row's id/prev_hash/entry_hash after a purge reached
// into the chained region. Deliberately not
// internal/core/storage.AuditChainAnchor.
type RetentionAnchor struct {
	RowID     uint64
	PrevHash  string
	EntryHash string
}

// auditRetentionAnchorSep matches internal/core.auditRetentionAnchorSep —
// \x1f, not \x00, for the same PostgreSQL text-column reason as the
// high-water mark.
const auditRetentionAnchorSep = "\x1f"

// retentionAnchorCanonical is the exact byte string signed/verified for a
// retention anchor. The "retanchor-v1" prefix domain-separates it from
// checkpointCanonical/the high-water layout — byte-identical
// reimplementation of internal/core.auditRetentionAnchorCanonical.
func retentionAnchorCanonical(rowID uint64, prevHash, entryHash, keyVersion string) string {
	return fmt.Sprintf("retanchor-v1\x00%d\x00%s\x00%s\x00%s", rowID, prevHash, entryHash, keyVersion)
}

// SignRetentionAnchor computes the hex HMAC-SHA256 over the anchor fields
// under the given key/keyVersion — mirrors
// internal/core.signRetentionAnchorWithVersion.
func SignRetentionAnchor(rowID uint64, prevHash, entryHash, keyVersion string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(retentionAnchorCanonical(rowID, prevHash, entryHash, keyVersion)))
	return hex.EncodeToString(mac.Sum(nil))
}

// ParseRetentionAnchor parses a stored system_metadata
// "audit_retention_anchor" value into its fields. ok is false on any
// malformed value (treated as "no anchor") — byte-identical contract to
// internal/core.parseAuditRetentionAnchor.
func ParseRetentionAnchor(val string) (rowID uint64, prevHash, entryHash, keyVersion, sig string, ok bool) {
	parts := strings.Split(val, auditRetentionAnchorSep)
	if len(parts) != 6 || parts[0] != "v1" {
		return 0, "", "", "", "", false
	}
	id, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || id == 0 {
		return 0, "", "", "", "", false
	}
	return id, parts[2], parts[3], parts[4], parts[5], true
}

// RetentionAnchorSigMatches reports whether sig is the valid HMAC over the
// anchor fields under key/keyVersion.
func RetentionAnchorSigMatches(rowID uint64, prevHash, entryHash, keyVersion, sig string, key []byte) bool {
	computed := SignRetentionAnchor(rowID, prevHash, entryHash, keyVersion, key)
	return hmac.Equal([]byte(computed), []byte(sig))
}
