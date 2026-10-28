package auditverify

import (
	"cmp"
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
	// Seals/SealDigest bind a checkpoint written after an accepted audit loss
	// (seal.go): the number of seals and the newest seal's digest. Not stored
	// on a checkpoint row: the verifier sets them from the authenticated seal
	// record before checking a signature. A sealed high-water mark carries
	// them (the v2 layout).
	Seals      int
	SealDigest string
}

// checkpointCanonical is the exact byte string signed/verified for a
// checkpoint. Byte-identical reimplementation of
// internal/core.checkpointCanonicalSealed — a differential test asserts that:
// the v1 form without seals, "v2" with the seal count and newest seal digest
// ahead of the v1 fields otherwise.
func checkpointCanonical(cp *Checkpoint) string {
	if cp.Seals != 0 {
		return fmt.Sprintf("v2\x00%d\x00%s\x00%d\x00%d\x00%s\x00%s", cp.Seals, cp.SealDigest, cp.ChainedEvents, cp.HeadID, cp.HeadHash, cp.KeyVersion)
	}
	return fmt.Sprintf("v1\x00%d\x00%d\x00%s\x00%s", cp.ChainedEvents, cp.HeadID, cp.HeadHash, cp.KeyVersion)
}

// bound returns a copy of cp bound to seal binding b.
func (cp *Checkpoint) bound(b sealBinding) *Checkpoint {
	c := *cp
	c.Seals, c.SealDigest = b.N, b.Digest
	return &c
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

// EncodeHighWater serializes cp and sig into the same
// "audit_checkpoint_highwater" string format ParseHighWater decodes —
// byte-identical contract to internal/core.auditHighWaterValue. Exported for
// symmetry with ParseHighWater: any caller (this package's own tests,
// server/admin's backup/restore tests) that needs to construct a
// syntactically valid high-water value should use this rather than
// hand-rolling the separator-joined layout.
func EncodeHighWater(cp *Checkpoint, sig string) string {
	if cp.Seals > 0 {
		return strings.Join([]string{
			"v2",
			strconv.Itoa(cp.Seals),
			cp.SealDigest,
			strconv.FormatInt(cp.ChainedEvents, 10),
			strconv.FormatUint(cp.HeadID, 10),
			cp.HeadHash,
			cp.KeyVersion,
			sig,
		}, auditHighWaterSep)
	}
	return strings.Join([]string{
		"v1",
		strconv.FormatInt(cp.ChainedEvents, 10),
		strconv.FormatUint(cp.HeadID, 10),
		cp.HeadHash,
		cp.KeyVersion,
		sig,
	}, auditHighWaterSep)
}

// ParseHighWater parses a system_metadata "audit_checkpoint_highwater"
// value into the checkpoint snapshot and signature it encodes. ok is false
// on any malformed value (treated as "no mark") — byte-identical contract
// to internal/core.parseAuditHighWater.
//
// A v2 (sealed) mark sets Seals and SealDigest, which its signature covers.
func ParseHighWater(val string) (cp *Checkpoint, sig string, ok bool) {
	parts := strings.Split(val, auditHighWaterSep)
	seals, digest := 0, ""
	if len(parts) == 8 && parts[0] == "v2" {
		n, err := strconv.Atoi(parts[1])
		if err != nil || n < 1 || parts[2] == "" {
			return nil, "", false
		}
		seals, digest = n, parts[2]
		parts = append([]string{"v1"}, parts[3:]...)
	}
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
		Seals:         seals,
		SealDigest:    digest,
	}, parts[5], true
}

// HighWaterOrder orders two high-water marks for rollback protection: a mark
// written under more seals is newer whatever its count (an accepted loss
// lowers the count), and between marks under the same number of seals the
// higher count is newer. It returns -1, 0 or +1.
func HighWaterOrder(a, b *Checkpoint) int {
	switch {
	case a.Seals != b.Seals:
		return cmp.Compare(a.Seals, b.Seals)
	default:
		return cmp.Compare(a.ChainedEvents, b.ChainedEvents)
	}
}

// HighWaterSigMatches reports whether sig is the valid HMAC over cp's
// canonical bytes under key — used for the high-water mark, whose signature
// is carried alongside the parsed fields rather than on a Signature field.
func HighWaterSigMatches(cp *Checkpoint, sig string, key []byte) bool {
	return hmac.Equal([]byte(SignCheckpoint(cp, key)), []byte(sig))
}
