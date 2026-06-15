// evidence_signing.go — authenticity signatures for exported compliance-evidence
// packs (ISO 27001 / SOC 2). The scheduled export HMAC-signs the exact bytes it
// writes with a DEK-derived key the database/DBA does not hold (see
// encryption.Service.EvidenceSignKey), so an archived pack's integrity is provable
// on the server off-box. A signature is "<keyVersion>:<hmac-hex>"; a signature made
// under a DEK version superseded by a rotation is reported as unverifiable rather
// than a generic mismatch (mirrors the audit-checkpoint key-version handling).
package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// SetEvidenceSignKey wires the DEK-derived HMAC key (and its DEK key version) used to
// sign and verify evidence packs. Called at startup when encryption is enabled; with
// no key set, packs are exported unsigned and verification is unavailable.
func (c *KeyorixCore) SetEvidenceSignKey(key []byte, keyVersion string) {
	c.evidenceSignKey = key
	c.evidenceSignKeyVersion = keyVersion
}

// EvidenceSigningAvailable reports whether a signing key is configured (encryption on).
func (c *KeyorixCore) EvidenceSigningAvailable() bool {
	return len(c.evidenceSignKey) > 0
}

// signEvidence returns "<keyVersion>:<hmac-hex>" over data, or ("", false) when
// signing is unavailable.
func (c *KeyorixCore) signEvidence(data []byte) (string, bool) {
	if !c.EvidenceSigningAvailable() {
		return "", false
	}
	mac := hmac.New(sha256.New, c.evidenceSignKey)
	mac.Write(data)
	return c.evidenceSignKeyVersion + ":" + hex.EncodeToString(mac.Sum(nil)), true
}

// EvidenceVerifyResult reports the outcome of verifying a pack's signature.
type EvidenceVerifyResult struct {
	Valid          bool   `json:"valid"`
	KeyVersion     string `json:"key_version,omitempty"`     // DEK version the signature was made under
	CurrentVersion string `json:"current_version,omitempty"` // current signing-key (DEK) version
	Reason         string `json:"reason,omitempty"`
}

// VerifyEvidenceSignature recomputes the HMAC over data and compares it to signature
// in constant time. A signature made under a superseded DEK version is reported
// unverifiable (not just invalid), so a post-rotation false alarm is distinguishable
// from real tampering.
func (c *KeyorixCore) VerifyEvidenceSignature(data []byte, signature string) *EvidenceVerifyResult {
	if !c.EvidenceSigningAvailable() {
		return &EvidenceVerifyResult{Reason: "evidence signing is unavailable (encryption disabled)"}
	}
	version, sigHex, ok := splitEvidenceSignature(signature)
	if !ok {
		return &EvidenceVerifyResult{Reason: "malformed signature"}
	}
	res := &EvidenceVerifyResult{KeyVersion: version, CurrentVersion: c.evidenceSignKeyVersion}
	if version != c.evidenceSignKeyVersion {
		res.Reason = "signature was made under a superseded key version (the DEK has rotated since); cannot verify"
		return res
	}
	want, err := hex.DecodeString(sigHex)
	if err != nil {
		res.Reason = "malformed signature"
		return res
	}
	mac := hmac.New(sha256.New, c.evidenceSignKey)
	mac.Write(data)
	if hmac.Equal(mac.Sum(nil), want) {
		res.Valid = true
		return res
	}
	res.Reason = "signature does not match — the pack was modified or signed by a different deployment"
	return res
}

// splitEvidenceSignature parses "<version>:<hex>" on the first colon.
func splitEvidenceSignature(s string) (version, hexSig string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}
