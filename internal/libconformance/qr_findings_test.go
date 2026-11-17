package libconformance

import (
	"testing"

	"github.com/boombuler/barcode/qr"
	"github.com/pquerna/otp/totp"
)

// TestQRFindingNumericSign pins finding LF1-QR-numeric-sign in boombuler/barcode
// v1.0.1-0.20190219062509-6c824513bacc: Numeric (and therefore Auto) mode accepts a
// leading '+' or '-' in a 3-digit group because it validates groups with strconv.Atoi,
// then drops the sign, so the symbol carries different content from the one requested
// ("+12" scans as "012", "-0" as "00"). Encode also returns the requested string from
// Content(), so the caller cannot see the change. This test goes red when the library
// is fixed; then delete qrAtoiNumeric's special case together with this test.
//
// What this does NOT verify: keyorix reachability. keyorix never renders a QR code, and
// pquerna/otp's Key.Image always encodes a full otpauth:// URL, whose lowercase scheme
// makes Auto choose byte mode, so the numeric path is not reachable through either
// (TestQRFindingNumericSignNotReachableViaOTP).
func TestQRFindingNumericSign(t *testing.T) {
	for in, want := range map[string]string{"+12": "012", "-0": "00", "123+45": "123045"} {
		bc, err := qr.Encode(in, qr.M, qr.Auto)
		if err != nil {
			t.Fatalf("Encode(%q) now fails (%v): finding fixed, remove the special case", in, err)
		}
		dec, err := decodeQR(bc)
		if err != nil {
			t.Fatalf("Encode(%q): %v", in, err)
		}
		if dec.content == in || dec.mode != 0 {
			t.Fatalf("Encode(%q) now decodes to %q in mode %d: finding fixed, remove the special case", in, dec.content, dec.mode)
		}
		if dec.content != want {
			t.Fatalf("Encode(%q) decodes to %q, the finding predicted %q", in, dec.content, want)
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
