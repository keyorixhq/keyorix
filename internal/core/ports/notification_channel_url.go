// notification_channel_url.go — the self-describing on-disk format for
// NotificationChannel.URLEnc (#2433/#2468).
//
// Why a format tag at all. A notification channel's destination URL IS the
// bearer credential, so it is encrypted at rest — but encryption is optional
// in this product (`storage.encryption.enabled`), and encryptAuthSecret's
// long-standing convention when it is off is to pass the plaintext through
// unchanged. For every OTHER auth-secret column that convention is harmless,
// because those columns' write paths refuse outright when encryption is off
// (BeginMFAEnrollment fails closed on AuthEncryptionActive). Notification
// channels have no such refusal: they predate encryption here and must keep
// working on an install that never enabled it.
//
// That left url_enc holding either an envelope or raw plaintext with nothing
// to tell them apart, and three readers that each had to GUESS:
//
//   - the core read path fed plaintext bytes to DecryptSecretWithAAD, which
//     fails — and since the list is (correctly) fail-closed, one such row broke
//     the WHOLE list;
//   - the startup backfill could not tell a migrated row from one still
//     awaiting migration, so enabling encryption later stranded every row
//     written while it was off;
//   - the DEK-rotation sweep fed plaintext to DeserializeEncryptedData and
//     returned an error, hard-failing the sweep for EVERY table, not just this
//     one.
//
// One leading byte removes the guess. The tag is checked, never inferred: an
// unrecognised byte is an error (fail closed), not a best-effort fallback —
// silently treating an unknown format as plaintext is exactly how a corrupted
// or attacker-written row would get dialled as a URL.
package ports

import (
	"encoding/json"
	"fmt"
)

// Format tags for the first byte of NotificationChannel.URLEnc.
//
// NotificationChannelURLTagAbsent is not stored; it is what
// UnwrapNotificationChannelURL reports for an empty/NULL column, which is a
// legitimate state (an `email` channel has no URL, and so does any row an
// upgrading install has not backfilled yet). Callers must map it to the empty
// URL, never to a decrypt attempt.
const (
	NotificationChannelURLTagAbsent    byte = 0x00
	NotificationChannelURLTagPlaintext byte = 0x01
	NotificationChannelURLTagEncrypted byte = 0x02
)

// WrapNotificationChannelURL prefixes payload with tag, producing the value
// stored in notification_channels.url_enc. tag must be Plaintext or Encrypted;
// Absent is never written (an absent URL is an empty column, so that an
// upgrading install's NULL and a deliberately-empty value read back
// identically).
// Written as a single append onto a one-byte literal rather than
// make([]byte, 0, len(payload)+1): the explicit capacity arithmetic tripped
// CodeQL's go/allocation-size-overflow (high) on this PR. The overflow is not
// actually reachable — len() of a real slice cannot be within one of MaxInt —
// but the arithmetic bought nothing, so removing it is simpler code AND a
// genuinely closed finding rather than a dismissed one.
func WrapNotificationChannelURL(tag byte, payload []byte) []byte {
	return append([]byte{tag}, payload...)
}

// NotificationChannelURLEnvelopeIsAADBound reports whether an
// encrypted-tagged payload carries a non-empty `aad_version`, i.e. whether its
// AAD will actually be checked on decryption.
//
// This exists because the metadata that decides whether AAD is enforced is
// written by whoever wrote the row. Service.DecryptSecretWithAAD falls back to
// a no-AAD decrypt when `aad_version` is empty, so that rows predating #94
// still read — and that fallback turned the AAD binding into a suggestion for
// THIS column. url_enc is new as of #2468, so it has no legitimate pre-AAD
// rows at all; a DB-write attacker could paste any old non-AAD ciphertext from
// anywhere in the database into url_enc and read its plaintext back out of
// GET /notification-channels. A decryption oracle, built entirely out of the
// compatibility shim.
//
// Decoded here rather than in internal/encryption so internal/core can refuse
// the shape without importing that package (ADR-109); this reads one field of
// the envelope's own JSON and needs nothing but encoding/json. A payload that
// does not decode at all is reported as an error, not as "not bound" — a
// caller must not be able to confuse "malformed" with "merely legacy".
func NotificationChannelURLEnvelopeIsAADBound(payload []byte) (bool, error) {
	var envelope struct {
		Metadata struct {
			AADVersion string `json:"aad_version"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return false, fmt.Errorf("notification channel URL: stored envelope is not decodable: %w", err)
	}
	return envelope.Metadata.AADVersion != "", nil
}

// UnwrapNotificationChannelURL splits a stored url_enc value into its format
// tag and payload. An empty value reports NotificationChannelURLTagAbsent with
// no error — the row simply has no URL. Any byte that is not a known tag is an
// error: this function never guesses a format.
func UnwrapNotificationChannelURL(stored []byte) (tag byte, payload []byte, err error) {
	if len(stored) == 0 {
		return NotificationChannelURLTagAbsent, nil, nil
	}
	switch stored[0] {
	case NotificationChannelURLTagPlaintext, NotificationChannelURLTagEncrypted:
		return stored[0], stored[1:], nil
	default:
		return 0, nil, fmt.Errorf("notification channel URL: unrecognised at-rest format tag 0x%02x", stored[0])
	}
}
