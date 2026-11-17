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
//	(b) EMPTY-IS-ABSENT: an empty slice reports TagAbsent with nil payload
//	    and no error.
//	(c) WRAP→UNWRAP ROUND-TRIP: for the two valid tags (Plaintext,
//	    Encrypted) and any payload, Wrap then Unwrap recovers the same tag
//	    and payload byte-for-byte.
//	(d) UNKNOWN-TAG FAILS-CLOSED: a first byte that is neither 0x01 nor
//	    0x02 must return a non-nil error from UnwrapNotificationChannelURL.
//	(e) IsAADBound PARSES OR ERRORS: for a byte slice tagged as Encrypted,
//	    IsAADBound either succeeds or returns an error; it never returns
//	    (false, nil) when the JSON is malformed.
//	(f) IsAADBound MATCHES FIELD: for well-formed JSON, the returned bool
//	    equals whether the metadata.aad_version field is non-empty.
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
		if len(stored) == 0 {
			if unwrappedTag != NotificationChannelURLTagAbsent || unwrappedPayload != nil || unwrapErr != nil {
				t.Fatalf("UnwrapNotificationChannelURL(nil): got (%02x, %v, %v), want (0x00, nil, nil)",
					unwrappedTag, unwrappedPayload, unwrapErr)
			}
			return
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

		// Oracle (e): malformed JSON must return an error, not (false, nil).
		var envelope struct {
			Metadata struct {
				AADVersion string `json:"aad_version"`
			} `json:"metadata"`
		}
		jsonErr := json.Unmarshal(unwrappedPayload, &envelope)
		if jsonErr != nil {
			if aadErr == nil {
				t.Fatalf("NotificationChannelURLEnvelopeIsAADBound: malformed JSON but no error (got isAADBound=%v)", isAADBound)
			}
			return
		}

		// Oracle (f): well-formed JSON — bool must match aad_version non-empty.
		if aadErr != nil {
			t.Fatalf("NotificationChannelURLEnvelopeIsAADBound: well-formed JSON returned error: %v", aadErr)
		}
		want := envelope.Metadata.AADVersion != ""
		if isAADBound != want {
			t.Fatalf("NotificationChannelURLEnvelopeIsAADBound(%q): got %v, want %v (aad_version=%q)",
				unwrappedPayload, isAADBound, want, envelope.Metadata.AADVersion)
		}
	})
}
