package auditverify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Key transition records (docs/design-audit-key-transition.md): written by
// rotate-kek and migrate-provider, MACed by the old checkpoint key and, over
// that, by the new one. Byte-identical reimplementation of
// internal/core/audit_key_transition.go; a differential test asserts it.
const (
	auditKeyTransitionsKey   = "audit_key_transitions"
	auditKeyTransitionEvent  = "system.audit_key_transition"
	auditKeyTransitionDomain = "auditkeytrans-v1\x00"
)

// KeyTransition is one parsed, not yet authenticated record.
type KeyTransition struct {
	V            int    `json:"v"`
	Seq          int    `json:"seq"`
	OldKID       string `json:"old_kid"`
	NewKID       string `json:"new_kid"`
	HeadID       uint64 `json:"head_id"`
	HeadHash     string `json:"head_hash"`
	CheckpointID uint64 `json:"checkpoint_id"`
	Checkpoint   string `json:"checkpoint"`
	Prev         string `json:"prev"`

	payload        []byte
	macOld, macNew string
}

// KeyTransitionStatus reports what this run found for the key transition
// records.
type KeyTransitionStatus struct {
	Present bool `json:"present"`
	Records int  `json:"records"`
	// Authenticated: the record for the current key epoch verified under the
	// supplied checkpoint key.
	Authenticated bool `json:"authenticated"`
	// OldKeyVerified counts records whose old-key MAC verified under a
	// supplied previous checkpoint key.
	OldKeyVerified int `json:"old_key_verified"`
}

// keyTransitionEvent is an in-chain system.audit_key_transition row.
type keyTransitionEvent struct {
	id          uint64
	description string
}

// Digest is the hex SHA-256 of the record's payload.
func (k *KeyTransition) Digest() string {
	sum := sha256.Sum256(k.payload)
	return hex.EncodeToString(sum[:])
}

func keyTransitionMAC(key []byte, dir string, payload []byte, macOld string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(auditKeyTransitionDomain + dir + "\x00"))
	mac.Write(payload)
	if dir == "new" {
		mac.Write([]byte("\x00" + macOld))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// NewMACValid reports whether the new-key MAC verifies under key.
func (k *KeyTransition) NewMACValid(key []byte) bool {
	return hmac.Equal([]byte(keyTransitionMAC(key, "new", k.payload, k.macOld)), []byte(k.macNew))
}

// OldMACValid reports whether the old-key MAC verifies under key.
func (k *KeyTransition) OldMACValid(key []byte) bool {
	return hmac.Equal([]byte(keyTransitionMAC(key, "old", k.payload, "")), []byte(k.macOld))
}

var errKeyTransitionMalformed = errors.New("the audit_key_transitions record is malformed")

// ParseKeyTransitions decodes the stored row and checks the records link up
// (consecutive seq from 1, prev digests, old key version = previous new one),
// as internal/core.parseAuditKeyTransitions does. MACs are not checked.
func ParseKeyTransitions(val string) ([]*KeyTransition, error) {
	var recs []*KeyTransition
	for line := range strings.SplitSeq(val, "\n") {
		parts := strings.Split(line, "\x1f")
		if len(parts) != 4 || parts[0] != "akt-v1" {
			return nil, errKeyTransitionMalformed
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, errKeyTransitionMalformed
		}
		r := &KeyTransition{}
		if err := json.Unmarshal(payload, r); err != nil || r.V != 1 || r.OldKID == "" || r.NewKID == "" || r.OldKID == r.NewKID {
			return nil, errKeyTransitionMalformed
		}
		r.payload, r.macOld, r.macNew = payload, parts[2], parts[3]
		if n := len(recs); r.Seq != n+1 || (n == 0 && r.Prev != "") ||
			(n > 0 && (r.Prev != recs[n-1].Digest() || r.OldKID != recs[n-1].NewKID)) {
			return nil, fmt.Errorf("%w: record #%d does not follow the record before it (seq, prev digest or key version)", errKeyTransitionMalformed, r.Seq)
		}
		recs = append(recs, r)
	}
	return recs, nil
}

// checkKeyTransitions applies the verification rules of
// docs/design-audit-key-transition.md to an authenticated latest checkpoint
// (its key version is the current epoch). The caller ran enforceCheckpoint.
func checkKeyTransitions(ctx context.Context, db *DB, opts Options, result *Result) error {
	if len(opts.CheckpointKey) == 0 || !result.Checkpoint.Authenticated || result.Verdict == VerdictBroken {
		return nil
	}
	epoch := result.Checkpoint.KeyVersion
	val, found, err := db.GetSystemMetadata(ctx, auditKeyTransitionsKey)
	if err != nil {
		return err
	}
	if !found {
		if len(result.keyTransitionEvents) > 0 {
			result.escalate(VerdictBroken, fmt.Sprintf("audit event #%d records a key transition, but the audit_key_transitions record is missing",
				result.keyTransitionEvents[0].id))
		}
		return nil
	}
	recs, err := ParseKeyTransitions(val)
	if err != nil {
		result.escalate(VerdictBroken, err.Error())
		return nil
	}
	result.KeyTransition = KeyTransitionStatus{Present: true, Records: len(recs)}
	last := recs[len(recs)-1]
	switch {
	case last.NewKID == epoch:
		if !last.NewMACValid(opts.CheckpointKey) {
			result.escalate(VerdictBroken, fmt.Sprintf("key transition #%d to the current key version %q fails its new-key signature under the supplied checkpoint key (forged or altered)", last.Seq, epoch))
			return nil
		}
		if broken, err := keyTransitionHeadGone(ctx, db, result, last); err != nil || broken {
			return err
		}
	case last.OldKID == epoch:
		if !last.OldMACValid(opts.CheckpointKey) {
			result.escalate(VerdictBroken, fmt.Sprintf("pending key transition #%d from the current key version %q fails its old-key signature (forged or altered)", last.Seq, epoch))
			return nil
		}
		if n := len(recs); n > 1 && !recs[n-2].NewMACValid(opts.CheckpointKey) {
			result.escalate(VerdictBroken, fmt.Sprintf("key transition #%d to the current key version %q fails its new-key signature under the supplied checkpoint key (forged or altered)", recs[n-2].Seq, epoch))
			return nil
		}
	default:
		result.escalate(VerdictBroken, fmt.Sprintf("the latest key transition (#%d, %q to %q) is for another key epoch than the authenticated checkpoint's key version %q",
			last.Seq, last.OldKID, last.NewKID, epoch))
		return nil
	}
	result.KeyTransition.Authenticated = true
	for _, e := range result.keyTransitionEvents {
		if !keyTransitionNamed(recs, e.description) {
			result.escalate(VerdictBroken, fmt.Sprintf("audit event #%d names a key transition record that audit_key_transitions does not hold", e.id))
			return nil
		}
	}
	return checkKeyTransitionsOldKeys(ctx, db, opts, result, recs)
}

func keyTransitionNamed(recs []*KeyTransition, description string) bool {
	for _, r := range recs {
		if strings.Contains(description, r.Digest()) {
			return true
		}
	}
	return false
}

// keyTransitionHeadGone: the head the active record certified must still be in
// the chain with its hash, unless an authenticated retention purge removed it.
func keyTransitionHeadGone(ctx context.Context, db *DB, result *Result, r *KeyTransition) (bool, error) {
	if r.HeadID == 0 {
		return false, nil
	}
	hash, found, err := db.AuditEntryHashByID(ctx, r.HeadID)
	switch {
	case err != nil:
		return false, err
	case found && hash == r.HeadHash:
		return false, nil
	case !found && result.RetentionGap.Sanctioned && r.HeadID < result.RetentionGap.RowID:
		return false, nil
	}
	result.escalate(VerdictBroken, fmt.Sprintf("audit event #%d, the head key transition #%d certified, is missing or was rewritten", r.HeadID, r.Seq))
	return true, nil
}

// checkKeyTransitionsOldKeys checks each record's old-key MAC under the
// supplied previous keys. A previous key is matched to a record by the
// record's own checkpoint (it must verify under that key and claim the
// record's old key version); once matched, a failing old-key MAC or a
// checkpoint that differs from the recorded digest is BROKEN.
func checkKeyTransitionsOldKeys(ctx context.Context, db *DB, opts Options, result *Result, recs []*KeyTransition) error {
	for _, r := range recs {
		var cp *Checkpoint
		if r.CheckpointID != 0 {
			var err error
			if cp, err = db.CheckpointByID(ctx, r.CheckpointID); err != nil {
				return err
			}
		}
		for _, pk := range opts.PreviousCheckpointKeys {
			switch {
			case cp != nil && cp.KeyVersion == r.OldKID && CheckpointSignatureValid(cp, pk):
				if !r.OldMACValid(pk) {
					result.escalate(VerdictBroken, fmt.Sprintf("key transition #%d fails its old-key signature under the previous checkpoint key that signs checkpoint #%d (forged with the new key only)", r.Seq, cp.ID))
					return nil
				}
				sum := sha256.Sum256([]byte(checkpointCanonical(cp) + "\x00" + cp.Signature))
				if hex.EncodeToString(sum[:]) != r.Checkpoint {
					result.escalate(VerdictBroken, fmt.Sprintf("audit checkpoint #%d differs from the one key transition #%d recorded", cp.ID, r.Seq))
					return nil
				}
			case r.OldMACValid(pk):
			default:
				continue
			}
			result.KeyTransition.OldKeyVerified++
			break
		}
	}
	return nil
}
