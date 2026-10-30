package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// The untrusted binding (N < 0) signs nothing and authenticates nothing: not
// an empty signature (parseAuditHighWaterBound blanks a mismatched one), and
// not a MAC over the "v2\x00-1\x00..." form an older binary could have written.
func TestCheckpointSign_UntrustedBindingSignsAndAuthenticatesNothing(t *testing.T) {
	t.Parallel()
	c := &KeyorixCore{}
	c.SetAuditCheckpointKey(bytes.Repeat([]byte{0x2}, 32), "v1")
	cp := &models.AuditCheckpoint{ChainedEvents: 7, HeadID: 7, HeadHash: "abc", KeyVersion: "v1"}

	_, err := c.signCheckpointUnder(cp, auditSealBindingUntrusted)
	require.ErrorIs(t, err, ErrAuditSealsUntrusted)

	h := hmac.New(sha256.New, c.auditCkptKey)
	h.Write([]byte(checkpointCanonicalSealed(cp.ChainedEvents, cp.HeadID, cp.HeadHash, cp.KeyVersion, auditSealBindingUntrusted)))
	legacy := hex.EncodeToString(h.Sum(nil))
	assert.False(t, c.checkpointSigMatchesUnder(cp, auditSealBindingUntrusted, legacy), "a MAC over the N<0 form never authenticates")
	assert.False(t, c.checkpointSigMatchesUnder(cp, auditSealBindingUntrusted, ""), "an empty signature never authenticates")

	c.auditSealBind = auditSealBindingUntrusted
	_, err = c.signCheckpoint(cp)
	require.ErrorIs(t, err, ErrAuditSealsUntrusted)
	cp.Signature = legacy
	assert.False(t, c.checkpointSignatureValid(cp))

	c.auditSealBind = auditSealBinding{}
	sig, err := c.signCheckpoint(cp)
	require.NoError(t, err)
	cp.Signature = sig
	assert.True(t, c.checkpointSignatureValid(cp), "a trusted binding still signs and verifies")
}
