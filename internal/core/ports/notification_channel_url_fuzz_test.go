package ports

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzNotificationChannelURL drives the on-disk codec for
// notification_channels.url_enc:  WrapNotificationChannelURL,
// UnwrapNotificationChannelURL, and NotificationChannelURLEnvelopeIsAADBound.
//
// url_enc is written by PUT /notification-channels (operator-authenticated
// HTTP) and read by GET /notification-channels; the bytes at rest therefore
// arrive from the network.  UnwrapNotificationChannelURL is explicitly
// fail-closed: an unrecognised tag byte must error rather than silently
// accept an attacker-crafted row.  IsAADBound matters for the
// decryption-oracle finding documented in notification_channel_url.go:
// a row with no aad_version falls back to a weaker no-AAD decrypt path,
// so a false "not bound" report would expand the attack surface.
//
// Oracles — all fatal (the code is in production and must hold today):
//
//	(a) NEVER-PANIC: none of the three functions panics on arbitrary input.
//	(b) EMPTY-IS-ABSENT: an empty or nil slice reports TagAbsent with nil
//	    payload and no error. The stored value always carries the fuzzed tag
//	    byte, so (b) is driven by unwrapping the bare payload when it is empty.
//	(c) WRAP→UNWRAP ROUND-TRIP: for the two valid tags (Plaintext,
//	    Encrypted) and any payload, Wrap then Unwrap recovers the same tag
//	    and payload byte-for-byte.
//	(d) UNKNOWN-TAG FAILS-CLOSED: a first byte that is neither 0x01 nor
//	    0x02 must return a non-nil error from UnwrapNotificationChannelURL.
//	(e) IsAADBound REJECTS INVALID JSON: for a payload tagged as Encrypted
//	    that json.Valid rejects, IsAADBound returns an error; it never reports
//	    (false, nil), which would send the row down the no-AAD decrypt path.
//	(f) IsAADBound MATCHES A CONSTRUCTED ENVELOPE: an envelope built with
//	    json.Marshal whose metadata.aad_version is the fuzzed payload (as a
//	    string) is reported bound, with no error, exactly when that string is
//	    non-empty. The envelope is built, not decoded, so the oracle does not
//	    restate the production decode.
//
// What this does NOT verify: that the plaintext or ciphertext payload is a
// valid URL, that the encryption envelope uses the correct algorithm, nor
// that the decryption path in internal/encryption behaves correctly.
func FuzzNotificationChannelURL(f *testing.F) {
	// Seeds: (tag byte, payload bytes)
	f.Add(byte(0x00), []byte(nil))
	f.Add(byte(0x01), []byte("https://example.com/webhook"))
	f.Add(byte(0x02), []byte(`{"metadata":{"aad_version":"v1"},"ciphertext":"aGVsbG8="}`))
	f.Add(byte(0x02), []byte(`{"metadata":{},"ciphertext":"aGVsbG8="}`))
	f.Add(byte(0x02), []byte(`{"metadata":{"aad_version":""}}`))
	f.Add(byte(0x03), []byte("unknown tag"))
	f.Add(byte(0xff), []byte("ff tag"))
	f.Add(byte(0x01), []byte{})
	f.Add(byte(0x02), []byte("not json at all"))
	f.Add(byte(0x02), []byte(`{}`))
	f.Add(byte(0x01), []byte("\x00\x01\x02\x03"))

	f.Fuzz(func(t *testing.T, tagByte byte, payload []byte) {
		if len(payload) > 65536 {
			return
		}

		// --- Oracle (a): UnwrapNotificationChannelURL never panics ---
		stored := append([]byte{tagByte}, payload...)
		var unwrappedTag byte
		var unwrappedPayload []byte
		var unwrapErr error
		fuzzutil.Guard(t.Fatalf, "UnwrapNotificationChannelURL", func() {
			unwrappedTag, unwrappedPayload, unwrapErr = UnwrapNotificationChannelURL(stored)
		})

		// --- Oracle (b): empty → TagAbsent, nil, nil ---
		if len(payload) == 0 {
			absentTag, absentPayload, absentErr := UnwrapNotificationChannelURL(payload)
			if absentTag != NotificationChannelURLTagAbsent || absentPayload != nil || absentErr != nil {
				t.Fatalf("UnwrapNotificationChannelURL(%#v): got (%02x, %v, %v), want (0x00, nil, nil)",
					payload, absentTag, absentPayload, absentErr)
			}
		}

		// --- Oracle (d): unknown tag fails closed ---
		if tagByte != NotificationChannelURLTagPlaintext && tagByte != NotificationChannelURLTagEncrypted {
			if unwrapErr == nil {
				t.Fatalf("UnwrapNotificationChannelURL: unknown tag 0x%02x accepted without error", tagByte)
			}
			return // error returned, correct — no more oracles apply
		}

		// Valid tag: unwrap must succeed.
		if unwrapErr != nil {
			t.Fatalf("UnwrapNotificationChannelURL: valid tag 0x%02x returned error: %v", tagByte, unwrapErr)
		}
		if unwrappedTag != tagByte {
			t.Fatalf("UnwrapNotificationChannelURL: got tag 0x%02x, want 0x%02x", unwrappedTag, tagByte)
		}

		// --- Oracle (c): Wrap→Unwrap round-trip ---
		wrapped := WrapNotificationChannelURL(tagByte, payload)
		rt, rtPayload, rtErr := UnwrapNotificationChannelURL(wrapped)
		if rtErr != nil {
			t.Fatalf("UnwrapNotificationChannelURL: round-trip failed for tag 0x%02x: %v", tagByte, rtErr)
		}
		if rt != tagByte {
			t.Fatalf("UnwrapNotificationChannelURL: round-trip tag mismatch: got 0x%02x, want 0x%02x", rt, tagByte)
		}
		if !bytes.Equal(rtPayload, payload) {
			t.Fatalf("UnwrapNotificationChannelURL: round-trip payload mismatch: got %q, want %q", rtPayload, payload)
		}

		// --- Oracles (e)+(f): NotificationChannelURLEnvelopeIsAADBound ---
		if tagByte != NotificationChannelURLTagEncrypted {
			return // IsAADBound only makes sense for encrypted envelopes
		}

		var isAADBound bool
		var aadErr error
		fuzzutil.Guard(t.Fatalf, "NotificationChannelURLEnvelopeIsAADBound", func() {
			isAADBound, aadErr = NotificationChannelURLEnvelopeIsAADBound(unwrappedPayload)
		})

		// Oracle (e): invalid JSON must return an error, not (false, nil).
		if !json.Valid(unwrappedPayload) && aadErr == nil {
			t.Fatalf("NotificationChannelURLEnvelopeIsAADBound(%q): invalid JSON but no error (got isAADBound=%v)",
				unwrappedPayload, isAADBound)
		}

		// Oracle (f): a constructed envelope carrying the payload as aad_version.
		// json.Marshal replaces invalid UTF-8 with U+FFFD, so the encoded string is
		// non-empty exactly when payload is.
		aadVersion := string(payload)
		built, err := json.Marshal(map[string]any{
			"metadata":   map[string]any{"aad_version": aadVersion},
			"ciphertext": "aGVsbG8=",
		})
		if err != nil {
			t.Fatalf("json.Marshal of a constructed envelope: %v", err)
		}
		bound, err := NotificationChannelURLEnvelopeIsAADBound(built)
		if err != nil {
			t.Fatalf("NotificationChannelURLEnvelopeIsAADBound(%s): constructed envelope returned error: %v", built, err)
		}
		if want := aadVersion != ""; bound != want {
			t.Fatalf("NotificationChannelURLEnvelopeIsAADBound(%s): got %v, want %v", built, bound, want)
		}
	})
}
