// evidence_signing.go — authenticity signatures for exported compliance-evidence
// packs (ISO 27001 / SOC 2). The scheduled export HMAC-signs the exact bytes it
// writes with a KEK-derived key the database/DBA does not hold (see
// encryption.Service.EvidenceSignKey), so an archived pack's integrity is provable
// on the server off-box. Deriving from the KEK rather than the DEK means a routine
// DEK rotation does NOT invalidate previously-signed packs — the KEK is unaffected
// by it, only by a KEK-provider migration (#268). A signature is
// "<keyVersion>:<hmac-hex>"; a signature made under a key version superseded by a
// KEK change is reported as unverifiable rather than a generic mismatch (mirrors
// the audit-checkpoint key-version handling).
package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// SetEvidenceSignKey wires the KEK-derived HMAC key (and its key-version fingerprint)
// used to sign and verify evidence packs. Called at startup when encryption is
// enabled; with no key set, packs are exported unsigned and verification is
// unavailable.
func (c *KeyorixCore) SetEvidenceSignKey(key []byte, keyVersion string) {
	c.evidenceSignKey = key
	c.evidenceSignKeyVersion = keyVersion
}

// EvidenceSigningAvailable reports whether a signing key is configured (encryption on).
func (c *KeyorixCore) EvidenceSigningAvailable() bool {
	return len(c.evidenceSignKey) > 0
}

// signEvidence returns "<keyVersion>:<hmac-hex>" over filename+data, or ("", false)
// when signing is unavailable. Including the filename in the HMAC binds the signature
// to a specific pack identity, so a valid signature for one pack cannot be presented
// as authenticating a differently-named pack (AUD-009).
func (c *KeyorixCore) signEvidence(filename string, data []byte) (string, bool) {
	if !c.EvidenceSigningAvailable() {
		return "", false
	}
	mac := hmac.New(sha256.New, c.evidenceSignKey)
	mac.Write([]byte(filename))
	mac.Write([]byte{0}) // null separator prevents length-extension across fields
	mac.Write(data)
	return c.evidenceSignKeyVersion + ":" + hex.EncodeToString(mac.Sum(nil)), true
}

// EvidenceVerifyResult reports the outcome of verifying a pack's signature.
type EvidenceVerifyResult struct {
	Valid          bool   `json:"valid"`
	KeyVersion     string `json:"key_version,omitempty"`     // key version the signature was made under
	CurrentVersion string `json:"current_version,omitempty"` // current signing-key (KEK) fingerprint
	Reason         string `json:"reason,omitempty"`
}

// VerifyEvidenceSignature recomputes the HMAC over filename+data and compares it to
// signature in constant time. filename must match what was supplied to signEvidence at
// export time (i.e. the pack's canonical filename). A signature made under a superseded
// key version is reported unverifiable rather than invalid.
func (c *KeyorixCore) VerifyEvidenceSignature(filename string, data []byte, signature string) *EvidenceVerifyResult {
	if !c.EvidenceSigningAvailable() {
		return &EvidenceVerifyResult{Reason: "evidence signing is unavailable (encryption disabled)"}
	}
	version, sigHex, ok := splitEvidenceSignature(signature)
	if !ok {
		return &EvidenceVerifyResult{Reason: "malformed signature"}
	}
	res := &EvidenceVerifyResult{KeyVersion: version, CurrentVersion: c.evidenceSignKeyVersion}
	if version != c.evidenceSignKeyVersion {
		res.Reason = "signature was made under a superseded key version (the signing key has changed since); cannot verify"
		return res
	}
	want, err := hex.DecodeString(sigHex)
	if err != nil {
		res.Reason = "malformed signature"
		return res
	}
	mac := hmac.New(sha256.New, c.evidenceSignKey)
	mac.Write([]byte(filename))
	mac.Write([]byte{0})
	mac.Write(data)
	if hmac.Equal(mac.Sum(nil), want) {
		res.Valid = true
		return res
	}
	res.Reason = "signature does not match — the pack was modified, signed by a different deployment, or presented under the wrong filename"
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
