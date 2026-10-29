package auditverify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// The server's signed audit verification state row (AUDIT-VERIFY-STATE-1,
// internal/core/audit_verify_state.go). Online, a row that is deleted while the
// chain says one exists, fails its signature, claims rows past the chain head,
// certified a head row that is now missing or rewritten, or carries a
// discontinuity is a sticky BROKEN. This is an independent reimplementation of
// those five rules over the fields they read; the rest of the row (failure,
// seal count, cycle bookkeeping) is not checked here.
const (
	auditVerifyStateKey                = "audit_verification_state"
	auditVerifyStateMarkerEvent        = "system.audit_verification_state_initialized"
	auditVerifyStateDiscontinuityEvent = "system.audit_verification_state_discontinuity"
	auditVerifyStateDomain             = "auditverify-state-v1\x00"
)

// verifyStateRow is the part of the row's JSON payload checked offline.
type verifyStateRow struct {
	AuditHead uint64 `json:"audit_head"`
	Pin       *struct {
		HeadID   uint64 `json:"head_id"`
		HeadHash string `json:"head_hash"`
	} `json:"pin"`
	LastCheck *struct {
		ThroughID uint64 `json:"through_id"`
		Valid     bool   `json:"valid"`
		HeadHash  string `json:"head_hash"`
	} `json:"last_check"`
	LastFull *struct {
		ThroughID uint64 `json:"through_id"`
	} `json:"last_full"`
	Cycle *struct {
		TargetID uint64 `json:"target_id"`
		SeedID   uint64 `json:"seed_id"`
	} `json:"cycle"`
	Discontinuity *struct {
		Kind   string `json:"kind"`
		Reason string `json:"reason"`
	} `json:"discontinuity"`
}

// claimedThrough is the highest audit event id the row says existed, as
// internal/core's auditVerifyState.claimedThrough.
func (s *verifyStateRow) claimedThrough() uint64 {
	n := s.AuditHead
	if s.Pin != nil {
		n = max(n, s.Pin.HeadID)
	}
	if s.LastCheck != nil {
		n = max(n, s.LastCheck.ThroughID)
	}
	if s.LastFull != nil {
		n = max(n, s.LastFull.ThroughID)
	}
	if s.Cycle != nil {
		n = max(n, s.Cycle.TargetID, s.Cycle.SeedID)
	}
	return n
}

// decodeVerifyState splits an "avs-v1" row. ok is false on any other shape.
func decodeVerifyState(val string) (payload []byte, sig string, ok bool) {
	parts := strings.Split(val, "\x1f")
	if len(parts) != 3 || parts[0] != "avs-v1" {
		return nil, "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", false
	}
	return payload, parts[2], true
}

func verifyStateMACValid(payload []byte, sig string, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(auditVerifyStateDomain))
	mac.Write(payload)
	return hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(sig))
}

// checkVerifyState applies the state-row rules after a clean walk. Without a
// key only the "deleted" rule runs (it reads the chain, not the row).
func checkVerifyState(ctx context.Context, db *DB, opts Options, result *Result) error {
	if result.Verdict == VerdictBroken {
		return nil
	}
	val, found, err := db.GetSystemMetadata(ctx, auditVerifyStateKey)
	if err != nil {
		return err
	}
	if !found {
		if result.stateEventID != 0 {
			result.escalate(VerdictBroken, fmt.Sprintf(
				"the server's audit verification state row is missing although audit event #%d records that one exists: "+
					"it was deleted, and with it the record of what earlier verifications certified", result.stateEventID))
		}
		return nil
	}
	if len(opts.CheckpointKey) == 0 {
		return nil
	}
	payload, sig, ok := decodeVerifyState(val)
	authentic := ok && verifyStateMACValid(payload, sig, opts.CheckpointKey)
	if !authentic && ok && carriedByKeyTransition(result, val) {
		// Signed under the previous key and named by the authenticated record
		// of a transition whose completion has not appended its event yet: the
		// server accepts it the same way.
		authentic = true
	}
	var row verifyStateRow
	if !authentic || json.Unmarshal(payload, &row) != nil {
		result.escalate(VerdictBroken,
			"the server's audit verification state row does not verify under the supplied checkpoint key "+
				"(garbled, replaced, or signed under another key epoch)")
		return nil
	}
	if d := row.Discontinuity; d != nil {
		result.escalate(VerdictBroken, fmt.Sprintf(
			"the server recorded an audit verification state discontinuity (%s): %s", d.Kind, d.Reason))
		return nil
	}
	// The head is read after the row, as the server does: ids only grow, so a
	// row a live server saved during this run cannot look past it.
	_, head, _, _, _, err := db.EventRange(ctx)
	if err != nil {
		return err
	}
	if claimed := row.claimedThrough(); claimed > head {
		result.escalate(VerdictBroken, fmt.Sprintf(
			"the server's authentic audit verification state covers audit event #%d, but the chain ends at #%d: "+
				"rows it verified were removed", claimed, head))
		return nil
	}
	return checkVerifyStateHead(ctx, db, &row, result)
}

// checkVerifyStateHead is internal/core's auditVerifyStateHeadGone: the head
// row the authentic row certified (its pin, or for a row saved before pins its
// last valid tail check) must still exist with that hash, unless the
// authenticated retention anchor is past it (a sanctioned purge removed it).
// Ids are never reused, so after the tail was cut and regrown past the claimed
// head, or rows below it were rewritten and re-chained, this is what still
// shows the gap.
func checkVerifyStateHead(ctx context.Context, db *DB, row *verifyStateRow, result *Result) error {
	var id uint64
	var hash string
	switch {
	case row.Pin != nil && row.Pin.HeadID != 0:
		id, hash = row.Pin.HeadID, row.Pin.HeadHash
	case row.LastCheck != nil && row.LastCheck.Valid && row.LastCheck.ThroughID != 0:
		id, hash = row.LastCheck.ThroughID, row.LastCheck.HeadHash
	default:
		return nil
	}
	got, found, err := db.AuditEntryHashByID(ctx, id)
	switch {
	case err != nil:
		return err
	case found && got == hash:
		return nil
	case found:
		result.escalate(VerdictBroken, fmt.Sprintf(
			"audit event #%d, the head the server's authentic audit verification state certified, was rewritten", id))
		return nil
	case id < result.retentionAnchorRowID:
		return nil // removed by a sanctioned (authenticated) retention purge
	}
	result.escalate(VerdictBroken, fmt.Sprintf(
		"audit event #%d, the head the server's authentic audit verification state certified, is missing: "+
			"rows it verified were removed", id))
	return nil
}

// carriedByKeyTransition reports whether val is the state row the active key
// transition record names and no in-chain event for that record exists yet.
func carriedByKeyTransition(result *Result, val string) bool {
	t := result.activeTransition
	if t == nil || t.State == "" {
		return false
	}
	sum := sha256.Sum256([]byte(val))
	if hex.EncodeToString(sum[:]) != t.State {
		return false
	}
	for _, e := range result.keyTransitionEvents {
		if strings.Contains(e.description, t.Digest()) {
			return false
		}
	}
	return true
}
