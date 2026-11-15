//go:build ignore

// gen_corpus.go emits the shared differential corpus for the pkcs7 time-travel
// harness as "<id>\t<hex>" lines on stdout. The corpus is reproducible (no
// randomness that varies between runs) and combines:
//
//   - the f.Add seeds already committed in internal/libconformance's pkcs7
//     fuzz targets (so the differential starts from exactly what Keyorix's own
//     fuzzers consider interesting),
//   - minimal well-formed ASN.1/DER shapes and the PKCS#7 ContentInfo wrapper
//     (OID 1.2.840.113549.1.7.2 signedData / .7.1 data) so "accept" paths are
//     exercised, not only rejects,
//   - BER-specific encodings (indefinite length 0x80 … 00 00) that DER forbids
//     but ber2der must normalise — the exact surface the amplification DoS lived
//     in, and
//   - SAFE, moderate long-form length probes (declared lengths up to ~64 MiB,
//     never gigabytes) that reveal whether a version allocates proportional to
//     the DECLARED length before reading content (the amplification signature)
//     without threatening a shared host.
//
// It deliberately contains no multi-gigabyte declared length: the point is to
// show the behaviour *change* across versions at a safe magnitude, and the RLIMIT
// in run.sh is only a backstop, not the plan.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	emit := func(id string, b []byte) {
		fmt.Fprintf(w, "%s\t%s\n", id, hex.EncodeToString(b))
	}

	// -- committed f.Add seeds from the existing pkcs7 fuzz targets --
	emit("seed-min-der-seq", []byte{0x30, 0x03, 0x02, 0x01, 0x01})
	emit("seed-ber-ish", []byte("0\x81\xc400\x02\x01\xf8"))
	emit("seed-empty", []byte{})
	emit("seed-der-pkcs7bw-a", []byte{0x30, 0x03, 0x02, 0x01, 0x01})

	// -- minimal shapes --
	emit("der-null", []byte{0x05, 0x00})
	emit("der-int-0", []byte{0x02, 0x01, 0x00})
	emit("der-oid-signeddata", oid(oidSignedData))
	emit("der-empty-seq", []byte{0x30, 0x00})
	emit("der-set-empty", []byte{0x31, 0x00})

	// ContentInfo { contentType OID, [0] content } for each known pkcs7 OID.
	for name, o := range map[string][]int{
		"signeddata":    oidSignedData,
		"data":          {1, 2, 840, 113549, 1, 7, 1},
		"envelopeddata": {1, 2, 840, 113549, 1, 7, 3},
		"encrypteddata": {1, 2, 840, 113549, 1, 7, 6},
		"digesteddata":  {1, 2, 840, 113549, 1, 7, 5},
	} {
		ci := seq(cat(oid(o), expl0(seq(nil))))
		emit("contentinfo-"+name, ci)
		// same but with a bare empty content
		emit("contentinfo-"+name+"-nocontent", seq(oid(o)))
	}

	// -- BER indefinite-length forms (DER-illegal; ber2der must handle) --
	// SEQUENCE, indefinite length, one NULL, EOC.
	emit("ber-indef-seq-null", []byte{0x30, 0x80, 0x05, 0x00, 0x00, 0x00})
	// nested indefinite lengths.
	emit("ber-indef-nested", []byte{0x30, 0x80, 0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00})
	// indefinite OCTET STRING (BER constructed string) with two fragments.
	emit("ber-indef-octet", []byte{0x24, 0x80, 0x04, 0x01, 0x41, 0x04, 0x01, 0x42, 0x00, 0x00})
	// indefinite with missing EOC (truncated).
	emit("ber-indef-truncated", []byte{0x30, 0x80, 0x05, 0x00})

	// -- long-form length probes: declared length >> actual content --
	// These reveal "allocate proportional to declared length" amplification.
	// Magnitudes kept SAFE (<= 64 MiB) on purpose.
	type lp struct {
		id  string
		tag byte
		n   uint32
	}
	for _, p := range []lp{
		{"len-1k", 0x30, 1 << 10},
		{"len-64k", 0x30, 1 << 16},
		{"len-1m", 0x30, 1 << 20},
		{"len-16m", 0x30, 1 << 24},
		{"len-64m", 0x04, 1 << 26}, // OCTET STRING claiming 64 MiB, body = 2 bytes
	} {
		emit("ber-longlen-"+p.id, cat([]byte{p.tag}, longLen(p.n), []byte{0x41, 0x42}))
	}
	// A ContentInfo whose inner [0] content claims a huge length (the realistic
	// shape: a pkcs7 OID wrapper around an over-long inner TLV).
	inner := cat([]byte{0x04}, longLen(1<<25), []byte{0x00})
	emit("pkcs7-inner-overlong", seq(cat(oid(oidSignedData), expl0(inner))))

	// -- truncation / trailing-data family --
	emit("trailing-after-seq", []byte{0x30, 0x00, 0x41})
	emit("truncated-len", []byte{0x30, 0x05, 0x02})
	emit("longform-len-missing-bytes", []byte{0x30, 0x84, 0x00, 0x00})

	// -- deep indefinite-length nesting (the maxNestingDepth=500 fix in
	// ber2der, GHSA-3xqc-rpq8-wgp9) : (30 80)^D 05 00 (00 00)^D. Depths chosen to
	// straddle the 500 cap so the differential sees the exact boundary. Kept well
	// below any stack/memory hazard: the amplification here is per-level
	// re-encoding work, ~linear in D, so D<=4000 is safe on a shared host while
	// still exposing the unbounded-vs-capped behaviour change. --
	for _, d := range []int{100, 400, 490, 499, 500, 501, 510, 1000, 2000, 4000} {
		var b []byte
		for i := 0; i < d; i++ {
			b = append(b, 0x30, 0x80)
		}
		b = append(b, 0x05, 0x00) // innermost: a NULL primitive
		for i := 0; i < d; i++ {
			b = append(b, 0x00, 0x00) // end-of-contents markers
		}
		emit(fmt.Sprintf("nest-indef-%d", d), b)
	}

	// -- deep definite-length nesting: SEQUENCE wrappers around one 64 KiB
	// OCTET STRING. Not an overlap (well-formed), but exercises the same
	// recursive descent / re-encode path with a non-trivial payload. --
	for _, d := range []int{50, 200, 400, 520} {
		const S = 1 << 16
		body := cat([]byte{0x04}, longLen(uint32(S)), make([]byte, S))
		for i := 0; i < d; i++ {
			body = cat([]byte{0x30}, shortOrLongLen(len(body)), body)
		}
		emit(fmt.Sprintf("nest-def-d%d-s%d", d, S), body)
	}
}

var oidSignedData = []int{1, 2, 840, 113549, 1, 7, 2}

// --- tiny ASN.1 DER construction helpers (enough for corpus shapes) ---

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func tlv(tag byte, body []byte) []byte {
	return cat([]byte{tag}, shortOrLongLen(len(body)), body)
}
func seq(body []byte) []byte   { return tlv(0x30, body) }
func expl0(body []byte) []byte { return tlv(0xA0, body) } // [0] explicit

func shortOrLongLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	return longLen(uint32(n))
}

// longLen encodes n as a DER long-form length using 4 length octets (0x84).
func longLen(n uint32) []byte {
	return []byte{0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func oid(arcs []int) []byte {
	// encode OID value
	var body []byte
	body = append(body, byte(arcs[0]*40+arcs[1]))
	for _, a := range arcs[2:] {
		body = append(body, base128(a)...)
	}
	return tlv(0x06, body)
}

func base128(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var tmp []byte
	for n > 0 {
		tmp = append([]byte{byte(n & 0x7f)}, tmp...)
		n >>= 7
	}
	for i := 0; i < len(tmp)-1; i++ {
		tmp[i] |= 0x80
	}
	return tmp
}
