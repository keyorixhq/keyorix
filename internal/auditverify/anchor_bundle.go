package auditverify

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/notary"
)

// ExternalAnchorBundle is a JSON-serializable snapshot of a signed
// checkpoint, held externally by the operator/auditor (design §3's
// `--anchor` flag) — e.g. archived off-box from a prior verification run, or
// from `keyorix audit export`. Cross-checking the DB's own chain length
// against a copy the host cannot have altered after the fact is the
// strongest leg of this package's trust model (design §2): unlike the in-DB
// checkpoint alone, a genuinely externally-held copy constrains even a host
// admin who holds the checkpoint signing key — from the moment the anchor
// was taken onward.
type ExternalAnchorBundle struct {
	ChainedEvents  int64  `json:"chained_events"`
	HeadID         uint64 `json:"head_id"`
	HeadHash       string `json:"head_hash"`
	KeyVersion     string `json:"key_version"`
	Signature      string `json:"signature"`
	AnchorToken    []byte `json:"anchor_token,omitempty"`
	AnchorProvider string `json:"anchor_provider,omitempty"`
}

// ParseExternalAnchorBundle parses the JSON bundle design §3's `--anchor`
// flag takes. All interpretation of this file lives here and in
// crossCheckExternalAnchor below — the caller (the cobra command) only
// reads the bytes off disk and hands them to this function.
func ParseExternalAnchorBundle(data []byte) (*ExternalAnchorBundle, error) {
	var b ExternalAnchorBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse anchor bundle: %w", err)
	}
	if b.HeadHash == "" || b.Signature == "" {
		return nil, fmt.Errorf("anchor bundle is missing required fields (head_hash, signature)")
	}
	return &b, nil
}

func (b *ExternalAnchorBundle) asCheckpoint() *Checkpoint {
	return &Checkpoint{
		ChainedEvents: b.ChainedEvents,
		HeadID:        b.HeadID,
		HeadHash:      b.HeadHash,
		KeyVersion:    b.KeyVersion,
		Signature:     b.Signature,
	}
}

// crossCheckExternalAnchor authenticates opts.ExternalAnchor by whatever
// means are available — the supplied checkpoint key (its HMAC signature), an
// RFC 3161 token against opts.TSARoots, or both — and, if authenticated by
// EITHER method, compares its certified chain length and head against the
// LIVE walk. This catches a truncation or genesis re-seed even if the
// database's own local checkpoint/high-water rows were ALSO deleted or
// forged, since this anchor's ground truth came from outside the host
// (design §2's strongest leg — RFC 3161 in particular needs no shared secret
// at all). An unauthenticated bundle (no key, no roots, or both fail) is
// reported as present-but-unauthenticated and never trusted for the
// chain-length comparison — see buildNotProven.
func crossCheckExternalAnchor(ctx context.Context, db *DB, opts Options, result *Result) error {
	b := opts.ExternalAnchor
	cp := b.asCheckpoint()

	result.ExternalAnchor.Supplied = true

	keyAuthenticated := len(opts.CheckpointKey) > 0 && CheckpointSignatureValid(cp, opts.CheckpointKey)

	tokenVerified := false
	if len(b.AnchorToken) > 0 && opts.TSARoots != nil {
		if _, err := notary.VerifyReceipt(opts.TSARoots, []byte(checkpointCanonical(cp)), b.AnchorToken); err == nil {
			tokenVerified = true
		} else {
			result.escalate(VerdictBroken, fmt.Sprintf(
				"the externally-supplied anchor's RFC 3161 token failed verification against the configured "+
					"trust root: %v — it does not authenticate what it claims", err))
			return nil
		}
	}

	if !keyAuthenticated && !tokenVerified {
		return nil // unauthenticated bundle — advisory only, see buildNotProven
	}
	result.ExternalAnchor.Authenticated = true

	if result.ChainedEvents < b.ChainedEvents {
		result.escalate(VerdictBroken, fmt.Sprintf(
			"audit trail truncated below an externally-held anchor: it certified %d chained events (a copy this "+
				"host does not control), only %d remain — caught even if this database's own local "+
				"checkpoint/high-water rows were also deleted or forged", b.ChainedEvents, result.ChainedEvents))
		return nil
	}
	if b.HeadID != 0 {
		hash, found, err := db.AuditEntryHashByID(ctx, b.HeadID)
		if err != nil {
			return err
		}
		if !found {
			result.escalate(VerdictBroken, fmt.Sprintf(
				"audit event #%d certified by the externally-held anchor is missing from this database", b.HeadID))
			return nil
		}
		if hash != b.HeadHash {
			result.escalate(VerdictBroken, fmt.Sprintf(
				"audit event #%d hash differs from the externally-held anchor (certified head was rewritten)", b.HeadID))
			return nil
		}
	}
	return nil
}
