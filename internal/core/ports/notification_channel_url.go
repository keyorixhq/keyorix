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

import "fmt"

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
func WrapNotificationChannelURL(tag byte, payload []byte) []byte {
	out := make([]byte, 0, len(payload)+1)
	out = append(out, tag)
	return append(out, payload...)
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
