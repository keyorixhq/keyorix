package anchorbundle

import (
	"encoding/json"
	"fmt"
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
// crossCheckExternalAnchor (internal/auditverify/anchor_bundle.go) — the
// caller (the cobra command) only reads the bytes off disk and hands them to
// this function.
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
