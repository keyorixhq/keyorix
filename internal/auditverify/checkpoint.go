package auditverify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Checkpoint is this package's own representation of an audit_checkpoints
// row (ADR-029) — deliberately not internal/storage/models.AuditCheckpoint,
// same reasoning as AuditEventRow.
type Checkpoint struct {
	ID             uint64
	ChainedEvents  int64
	HeadID         uint64
	HeadHash       string
	KeyVersion     string
	Signature      string
	AnchorToken    []byte
	AnchoredAt     *time.Time
	AnchorProvider string
}

// checkpointCanonical is the exact byte string signed/verified for a
// checkpoint. Byte-identical reimplementation of
// internal/core.checkpointCanonical — a differential test asserts that.
func checkpointCanonical(cp *Checkpoint) string {
	return fmt.Sprintf("v1\x00%d\x00%d\x00%s\x00%s", cp.ChainedEvents, cp.HeadID, cp.HeadHash, cp.KeyVersion)
}

// SignCheckpoint computes the hex HMAC-SHA256 over cp's canonical bytes
// under key — the same derivation internal/core.signCheckpoint performs
// with the KEK-derived checkpoint signing key.
func SignCheckpoint(cp *Checkpoint, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(checkpointCanonical(cp)))
	return hex.EncodeToString(mac.Sum(nil))
}

// CheckpointSignatureValid reports whether cp.Signature is the valid HMAC
// over cp's canonical bytes under key.
func CheckpointSignatureValid(cp *Checkpoint, key []byte) bool {
	return hmac.Equal([]byte(SignCheckpoint(cp, key)), []byte(cp.Signature))
}

// auditHighWaterSep matches internal/core.auditHighWaterSep — \x1f (ASCII
// unit separator), never \x00, because PostgreSQL text/varchar columns
// reject an embedded NUL byte outright and this value is persisted as a
// plain string via SetSystemMetadata.
const auditHighWaterSep = "\x1f"

// ParseHighWater parses a system_metadata "audit_checkpoint_highwater"
// value into the checkpoint snapshot and signature it encodes. ok is false
// on any malformed value (treated as "no mark") — byte-identical contract
// to internal/core.parseAuditHighWater.
func ParseHighWater(val string) (cp *Checkpoint, sig string, ok bool) {
	parts := strings.Split(val, auditHighWaterSep)
	if len(parts) != 6 || parts[0] != "v1" {
		return nil, "", false
	}
	chained, err1 := strconv.ParseInt(parts[1], 10, 64)
	headID, err2 := strconv.ParseUint(parts[2], 10, 64)
	if err1 != nil || err2 != nil {
		return nil, "", false
	}
	return &Checkpoint{
		ChainedEvents: chained,
		HeadID:        headID,
		HeadHash:      parts[3],
		KeyVersion:    parts[4],
	}, parts[5], true
}

// HighWaterSigMatches reports whether sig is the valid HMAC over cp's
// canonical bytes under key — used for the high-water mark, whose signature
// is carried alongside the parsed fields rather than on a Signature field.
func HighWaterSigMatches(cp *Checkpoint, sig string, key []byte) bool {
	return hmac.Equal([]byte(SignCheckpoint(cp, key)), []byte(sig))
}
