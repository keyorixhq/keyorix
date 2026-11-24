package libconformance

import (
	"testing"

	"github.com/boombuler/barcode/qr"
	"github.com/pquerna/otp/totp"
)

// TestQRFindingNumericSign is the regression test for finding LF1-QR-numeric-sign in
// boombuler/barcode (KFZ-2026-150, upstream issue #112, fixed by #113 and released in
// v1.1.1). Before the fix the numeric encoder validated each 3-byte group with
// strconv.Atoi, so a leading '+' or '-' passed the check and was dropped from the
// symbol: Numeric (and therefore Auto) encoded "+12" as "012", "-0" as "00" and "123+45"
// as "123045", while Content() still returned the requested string. The library now
// treats signed input as non-numeric data: Numeric refuses it, and Auto falls through to
// AlphaNumeric, whose charset includes '+' and '-', so the symbol carries the requested
// content.
//
// What this does NOT verify: keyorix reachability. keyorix never renders a QR code, and
// pquerna/otp's Key.Image always encodes a full otpauth:// URL, whose lowercase scheme
// makes Auto choose byte mode, so the numeric path is not reachable through either
// (TestQRFindingNumericSignNotReachableViaOTP). FuzzQRCodeRoundTrip covers the wider
// input space.
func TestQRFindingNumericSign(t *testing.T) {
	for _, in := range []string{"+12", "-0", "123+45"} {
		if _, err := qr.Encode(in, qr.M, qr.Numeric); err == nil {
			t.Fatalf("Encode(%q, Numeric) succeeded: a sign is not numeric data and must be refused", in)
		}
		bc, err := qr.Encode(in, qr.M, qr.Auto)
		if err != nil {
			t.Fatalf("Encode(%q, Auto): %v", in, err)
		}
		dec, err := decodeQR(bc)
		if err != nil {
			t.Fatalf("Encode(%q, Auto): %v", in, err)
		}
		if dec.content != in || dec.mode != 1 {
			t.Fatalf("Encode(%q, Auto) decodes to %q in mode %d, want %q in alphanumeric mode", in, dec.content, dec.mode, in)
		}
		if bc.Content() != in {
			t.Fatalf("Content() = %q, want the requested %q", bc.Content(), in)
		}
	}
}

// TestQRFindingNumericSignNotReachableViaOTP is the reachability half of the finding: a
// TOTP key's Image (the only QR path in keyorix's dependency graph) encodes the full
// otpauth:// URL, which decodes back exactly, in byte mode.
func TestQRFindingNumericSignNotReachableViaOTP(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Keyorix", AccountName: "+12"})
	if err != nil {
		t.Fatal(err)
	}
	bc, err := qr.Encode(key.String(), qr.M, qr.Auto) // what Key.Image does before scaling
	if err != nil {
		t.Fatal(err)
	}
	dec, err := decodeQR(bc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.content != key.String() || dec.mode != 2 {
		t.Fatalf("otpauth URL decodes to %q in mode %d, want %q in byte mode", dec.content, dec.mode, key.String())
	}
	img, err := key.Image(200, 200)
	if err != nil {
		t.Fatal(err)
	}
	if b := img.Bounds(); b.Dx() != 200 || b.Dy() != 200 {
		t.Fatalf("Key.Image(200, 200) is %v", b)
	}
}
