// key_commitment_pqwrap_test.go -- KEYCOMMIT-2 item 2: key-commitment oracles for
// the pqwrap keyset v1 KEK slot (internal/pqwrap/keyset.go).
//
// Premise correction. The task for this file assumed "the KEK slot binds kek_id in
// the AAD". It does not: the slot is kek_id[16] || nonce || AES-256-GCM(KEK, DEK)
// with AAD = header || slot index (0); the kek_id sits in front of the slot, outside
// the AAD (keyset.go sealKEKSlot/kekSlotAAD; pinned below with stock crypto/cipher,
// independent of keyset.go). What binds kek_id, and what commits the keyset to its
// KEK, are the two checks OpenKeyset runs after the GCM open:
//
//	mac = HMAC-SHA256(HKDF-SHA256(KEK, "keyorix/pqwrap/v1/keyset-mac"), header || slots)
//	      covers the kek_id bytes, so rewriting kek_id without the KEK breaks the MAC;
//	kcv = HKDF-SHA256(DEK, "keyorix/pqwrap/v1/dek-kcv")[:16] in the header, which is
//	      also part of the slot AAD, so a partitioned slot would need a hash fixed point.
//
// OpenKeyset takes no expected kek_id: "sealed for kek_id A never opens under kek_id
// B" is not a property of the API. The properties that exist, and are checked here:
//
//   - deny (kcKEKSlotDenyViolation): a keyset sealed under KEK A / kek_id A does not
//     open under KEK B, and no rewrite of the stored kek_id (any single byte, or the
//     whole id replaced by B) opens under KEK A while the MAC is untouched;
//   - partition (kcKEKSlotPartitionViolation): a KEK slot GHASH-partitioned across
//     (KEK A, KEK B) -- stock GCM opens it under both, checked first -- is never
//     accepted by the keyset open under both keys;
//   - what the AAD does and does not cover, pinned (kek_id outside the AAD; a KEK
//     holder can relabel a keyset by recomputing the MAC).
//
// Red-proof (TestKeyCommitmentPQWrap_RedProof): a planted opener that opens the KEK
// slot and nothing else (no MAC, no KCV: the binding dropped) is flagged by both
// oracles, a planted opener that ignores the KEK by the deny oracle; the real
// OpenKeyset is not flagged by either (control).
//
// What this does NOT verify: reachability (pqwrap has no production importer: only
// tests and tooling import it, checked with rg on internal/pqwrap imports);
// keysets with hybrid recipient slots (the partition is crafted for the KEK slot of
// a recipient-free keyset; recipient slots do not change the KEK slot's AAD
// derivation but do change the MAC input); legacy-60 (same gap as wrapKey, see
// key_commitment_fuzz_test.go); HMAC collision resistance across two keys (assumed,
// not tested); the fixed-point search a real attacker would need against the KCV.
package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/pqwrap"
)

const (
	kcKSHeaderSize = 22 // "KXKS" | version | kcv[16] | slot count
	kcKSIDOff      = kcKSHeaderSize + 3
)

// kcKeysetOpener is the open side of the keyset KEK slot: the DEK, the stored
// kek_id and the error.
type kcKeysetOpener struct {
	name string
	open func(blob, kek []byte) (dek []byte, id [pqwrap.KEKIDSize]byte, err error)
}

func kcRealKeysetOpener() kcKeysetOpener {
	return kcKeysetOpener{
		name: "pqwrap.OpenKeyset",
		open: func(blob, kek []byte) ([]byte, [pqwrap.KEKIDSize]byte, error) {
			ks, err := pqwrap.OpenKeyset(blob, kek)
			if err != nil {
				return nil, [pqwrap.KEKIDSize]byte{}, err
			}
			return ks.DEK, ks.KEKID, nil
		},
	}
}

// kcSlotOnlyOpener is the planted "binding dropped" opener: it parses the one-slot
// layout and opens the GCM slot with AAD header||0, nothing else (no MAC, no KCV).
func kcSlotOnlyOpener() kcKeysetOpener {
	return kcKeysetOpener{
		name: "planted slot-only open (MAC and KCV dropped)",
		open: func(blob, kek []byte) ([]byte, [pqwrap.KEKIDSize]byte, error) {
			var id [pqwrap.KEKIDSize]byte
			if len(blob) != kcKSHeaderSize+3+76+32 {
				return nil, id, errors.New("planted opener: unexpected layout")
			}
			copy(id[:], blob[kcKSIDOff:kcKSIDOff+16])
			seal := blob[kcKSIDOff+16 : kcKSIDOff+76]
			aad := append(bytes.Clone(blob[:kcKSHeaderSize]), 0)
			return kcStockOpen(kek, seal[:12], seal[12:], aad, id)
		},
	}
}

func kcStockGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func kcStockOpen(kek, nonce, ctTag, aad []byte, id [pqwrap.KEKIDSize]byte) ([]byte, [pqwrap.KEKIDSize]byte, error) {
	g, err := kcStockGCM(kek)
	if err != nil {
		return nil, id, err
	}
	dek, err := g.Open(nil, nonce, ctTag, aad)
	return dek, id, err
}

// kcKeylessKeysetOpener is the planted opener that ignores the KEK entirely: it
// returns dek (the one the test sealed, so the positive control passes and only
// the missing key binding is left to detect) and the stored kek_id.
func kcKeylessKeysetOpener(dek []byte) kcKeysetOpener {
	return kcKeysetOpener{
		name: "planted KEK-ignoring open",
		open: func(blob, _ []byte) ([]byte, [pqwrap.KEKIDSize]byte, error) {
			var id [pqwrap.KEKIDSize]byte
			if len(blob) < kcKSIDOff+16 {
				return nil, id, errors.New("short")
			}
			copy(id[:], blob[kcKSIDOff:kcKSIDOff+16])
			return bytes.Clone(dek), id, nil
		},
	}
}

// kcKeysetMAC mirrors keyset.go keysetMAC from the design note, not from keyset.go.
func kcKeysetMAC(kek, signed []byte) []byte {
	mk, err := hkdf.Key(sha256.New, kek, nil, "keyorix/pqwrap/v1/keyset-mac", 32)
	if err != nil {
		panic(err)
	}
	h := hmac.New(sha256.New, mk)
	h.Write(signed)
	return h.Sum(nil)
}

// kcBuildKeyset assembles a one-slot keyset from a header and a KEK slot body and
// MACs it under macKEK the way a KEK holder would.
func kcBuildKeyset(header, body, macKEK []byte) []byte {
	out := bytes.Clone(header)
	out = append(out, 1)                                        // slot type: KEK slot
	out = binary.BigEndian.AppendUint16(out, uint16(len(body))) // #nosec G115 -- the test slot body is 76 bytes
	out = append(out, body...)
	return append(out, kcKeysetMAC(macKEK, out)...)
}

func kcKeysetHeader(kcvSeed []byte) []byte {
	sum, err := hkdf.Key(sha256.New, kcvSeed, nil, "keyorix/pqwrap/v1/dek-kcv", 16)
	if err != nil {
		panic(err)
	}
	h := append([]byte("KXKS"), 1)
	h = append(h, sum...)
	return append(h, 1) // one slot: the KEK slot
}

// kcKEKSlotDenyViolation returns a non-empty description when o breaks the deny
// direction: a keyset sealed under kekA with idA must open under kekA to the
// sealed DEK and idA (positive control), must not open under kekB, and must not
// open under kekA once its stored kek_id is rewritten (one byte at a time, then
// replaced by idB) with the MAC untouched.
func kcKEKSlotDenyViolation(o kcKeysetOpener, kekA, kekB, dek []byte, idA, idB [pqwrap.KEKIDSize]byte) string {
	blob, err := pqwrap.SealKeyset(dek, kekA, idA, nil)
	if err != nil {
		panic(err)
	}
	if got, id, err := o.open(blob, kekA); err != nil || !bytes.Equal(got, dek) || id != idA {
		return o.name + ": positive control failed: the keyset does not open to its DEK and kek_id under its own KEK"
	}
	if _, _, err := o.open(blob, kekB); err == nil {
		return "KEY-COMMITMENT VIOLATION: " + o.name + ": keyset sealed under KEK A opened under KEK B != A"
	}
	for i := range pqwrap.KEKIDSize {
		c := bytes.Clone(blob)
		c[kcKSIDOff+i] ^= 0x01
		if _, id, err := o.open(c, kekA); err == nil {
			return fmt.Sprintf("KEK-ID BINDING VIOLATION: %s: kek_id byte %d rewritten (MAC untouched), keyset still opens, now as kek_id %x", o.name, i, id)
		}
	}
	if idB != idA {
		c := bytes.Clone(blob)
		copy(c[kcKSIDOff:], idB[:])
		if _, id, err := o.open(c, kekA); err == nil {
			return fmt.Sprintf("KEK-ID BINDING VIOLATION: %s: kek_id replaced by another id (MAC untouched), keyset still opens as %x", o.name, id)
		}
	}
	return ""
}

// kcKEKSlotPartitionViolation crafts a KEK slot that stock GCM opens under both
// kekA and kekB (AAD = the real header||0; a failure there is a harness bug, see
// partitioned), wraps it in a keyset MACed under kekA, and returns a non-empty
// description when o opens that keyset under BOTH keys. prefix must be 16 bytes
// (a 32-byte DEK is prefix plus the solved block).
func kcKEKSlotPartitionViolation(t testing.TB, o kcKeysetOpener, kekA, kekB, nonce, prefix []byte, id [pqwrap.KEKIDSize]byte) string {
	header := kcKeysetHeader([]byte("placeholder DEK: the KCV cannot match a crafted slot"))
	ct, tag, ok := partitioned(t, kekA, kekB, nonce, append(bytes.Clone(header), 0), prefix)
	if !ok {
		return ""
	}
	body := append(append(append(bytes.Clone(id[:]), nonce...), ct...), tag...)
	blob := kcBuildKeyset(header, body, kekA)
	_, _, eA := o.open(blob, kekA)
	_, _, eB := o.open(blob, kekB)
	if eA == nil && eB == nil {
		return "KEY-COMMITMENT VIOLATION: " + o.name + ": a GHASH-partitioned KEK slot opened under two different KEKs"
	}
	return ""
}

func kcPQKeys(s1, s2, dekSeed, id1, id2 []byte) (kekA, kekB, dek []byte, idA, idB [pqwrap.KEKIDSize]byte) {
	kekA, kekB = kcKeyPair(s1, s2)
	dek = kcDerive32(append([]byte{0x77}, dekSeed...))
	copy(idA[:], kcDerive32(append([]byte{0x11}, id1...)))
	copy(idB[:], kcDerive32(append([]byte{0x22}, id2...)))
	if idA == idB {
		idB[0] ^= 0xff
	}
	return
}

func FuzzPQWrapKEKSlotDeny(f *testing.F) {
	f.Add([]byte("kek-a"), []byte("kek-b"), []byte("dek"), []byte("id-a"), []byte("id-b"))
	f.Add([]byte{}, []byte{0}, []byte{}, []byte{}, []byte{})
	f.Add([]byte("same-prefix-a"), []byte("same-prefix-b"), bytes.Repeat([]byte{9}, 40), []byte("x"), []byte("x"))

	f.Fuzz(func(t *testing.T, s1, s2, dekSeed, id1, id2 []byte) {
		fuzzutil.Guard(t.Fatalf, "pqwrap kek slot deny", func() {
			kekA, kekB, dek, idA, idB := kcPQKeys(s1, s2, dekSeed, id1, id2)
			if v := kcKEKSlotDenyViolation(kcRealKeysetOpener(), kekA, kekB, dek, idA, idB); v != "" {
				panic(v)
			}
		})
	})
}

func FuzzPQWrapKEKSlotPartition(f *testing.F) {
	f.Add([]byte("kek-a"), []byte("kek-b"), []byte("0123456789ab"), []byte("0123456789abcdef"), []byte("id"))
	f.Add([]byte{1}, []byte{2}, make([]byte, 12), bytes.Repeat([]byte{7}, 16), []byte{})
	f.Add([]byte("a"), []byte("b"), []byte("nonce-nonce!"), []byte("short"), []byte("id-2"))

	f.Fuzz(func(t *testing.T, s1, s2, nonceSeed, prefixSeed, idSeed []byte) {
		fuzzutil.Guard(t.Fatalf, "pqwrap kek slot partition", func() {
			kekA, kekB, _, id, _ := kcPQKeys(s1, s2, nil, idSeed, nil)
			nonce := make([]byte, 12)
			copy(nonce, nonceSeed)
			prefix := make([]byte, 16)
			copy(prefix, prefixSeed)
			if v := kcKEKSlotPartitionViolation(t, kcRealKeysetOpener(), kekA, kekB, nonce, prefix, id); v != "" {
				panic(v)
			}
		})
	})
}

// TestKeyCommitmentPQWrap_RedProof shows both oracles fire on a planted opener
// with the binding dropped and stay quiet on the real OpenKeyset.
func TestKeyCommitmentPQWrap_RedProof(t *testing.T) {
	kekA, kekB, dek, idA, idB := kcPQKeys([]byte("a"), []byte("b"), []byte("d"), []byte("ia"), []byte("ib"))
	nonce, prefix := []byte("0123456789ab"), bytes.Repeat([]byte{0x33}, 16)

	for _, c := range []struct {
		o         kcKeysetOpener
		denyWant  string // substring of the deny verdict, "" = must stay quiet
		splitWant string // same for the partition oracle
	}{
		{kcRealKeysetOpener(), "", ""},
		{kcSlotOnlyOpener(), "KEK-ID BINDING VIOLATION", "KEY-COMMITMENT VIOLATION"},
		{kcKeylessKeysetOpener(dek), "KEY-COMMITMENT VIOLATION", "KEY-COMMITMENT VIOLATION"},
	} {
		dv := kcKEKSlotDenyViolation(c.o, kekA, kekB, dek, idA, idB)
		pv := kcKEKSlotPartitionViolation(t, c.o, kekA, kekB, nonce, prefix, idA)
		t.Logf("%-46s deny=%q partition=%q", c.o.name, dv, pv)
		for _, chk := range []struct{ what, got, want string }{{"deny", dv, c.denyWant}, {"partition", pv, c.splitWant}} {
			switch {
			case chk.want == "" && chk.got != "":
				t.Errorf("control %s flagged by the %s oracle: %s", c.o.name, chk.what, chk.got)
			case chk.want != "" && !containsStr(chk.got, chk.want):
				t.Errorf("red-proof failed: the %s oracle did not report %q for %s (got %q)", chk.what, chk.want, c.o.name, chk.got)
			}
		}
	}
}

func containsStr(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

// TestKeyCommitment_PQWrapPartitionedSlot_RefusedAtMACAndKCV pins WHERE the real
// open refuses a partitioned KEK slot, so the partition oracle's green is not a
// refusal for an unrelated reason (malformed, wrong magic): stock GCM opens the
// slot under both keys; under the KEK that MACed the keyset the open gets past the
// slot and the MAC and stops at the KCV (a crafted slot cannot satisfy the KCV in
// its own AAD without a hash fixed point); under the other KEK it stops at the MAC.
func TestKeyCommitment_PQWrapPartitionedSlot_RefusedAtMACAndKCV(t *testing.T) {
	kekA, kekB := kcKeyPair([]byte("kek-one"), []byte("kek-two"))
	nonce, prefix := []byte("0123456789ab"), bytes.Repeat([]byte{0x42}, 16)
	var id [pqwrap.KEKIDSize]byte
	copy(id[:], "kek-id-for-test!")

	header := kcKeysetHeader([]byte("placeholder"))
	ct, tag, ok := partitioned(t, kekA, kekB, nonce, append(bytes.Clone(header), 0), prefix)
	if !ok {
		t.Fatal("construction degenerate for the fixed test keys")
	}
	body := append(append(append(bytes.Clone(id[:]), nonce...), ct...), tag...)

	for _, c := range []struct {
		macKEK, openKEK []byte
		want            error
		label           string
	}{
		{kekA, kekA, pqwrap.ErrKCV, "MAC under A, open under A"},
		{kekA, kekB, pqwrap.ErrKeysetMAC, "MAC under A, open under B"},
		{kekB, kekA, pqwrap.ErrKeysetMAC, "MAC under B, open under A"},
		{kekB, kekB, pqwrap.ErrKCV, "MAC under B, open under B"},
	} {
		blob := kcBuildKeyset(header, body, c.macKEK)
		if _, err := pqwrap.OpenKeyset(blob, c.openKEK); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.label, err, c.want)
		}
	}
}

// TestKeyCommitment_PQWrapKEKIDNotInSlotAAD pins the as-built AAD with stock
// crypto/cipher, independent of keyset.go: the KEK slot opens with AAD = header ||
// 0 and not with the kek_id appended, so kek_id is NOT bound by the GCM slot. A KEK
// holder can therefore relabel a keyset (recompute the MAC); a non-holder cannot.
// If kek_id is ever added to the AAD this goes red: flip it to the deny direction
// and update INV-ENCRYPTION-no-key-commitment-gap.
func TestKeyCommitment_PQWrapKEKIDNotInSlotAAD(t *testing.T) {
	kek, _ := kcKeyPair([]byte("kek"), []byte("other"))
	dek := kcDerive32([]byte("dek"))
	var idA, idB [pqwrap.KEKIDSize]byte
	copy(idA[:], "kek-id-AAAAAAAAA")
	copy(idB[:], "kek-id-BBBBBBBBB")
	blob, err := pqwrap.SealKeyset(dek, kek, idA, nil)
	if err != nil {
		t.Fatal(err)
	}
	header := bytes.Clone(blob[:kcKSHeaderSize])
	seal := blob[kcKSIDOff+16 : kcKSIDOff+76]

	open := func(aad []byte) error {
		_, _, err := kcStockOpen(kek, seal[:12], seal[12:], aad, idA)
		return err
	}
	if err := open(append(bytes.Clone(header), 0)); err != nil {
		t.Fatalf("GAP CHANGED? the KEK slot no longer opens with AAD = header||0 (%v): the AAD changed, re-inventory it", err)
	}
	if open(append(append(bytes.Clone(header), 0), idA[:]...)) == nil {
		t.Fatal("the KEK slot opens with kek_id appended to the AAD as well: impossible for one GCM tag")
	}

	// A KEK holder relabels: same slot, other kek_id, MAC recomputed under the KEK.
	signed := bytes.Clone(blob[:len(blob)-32])
	copy(signed[kcKSIDOff:], idB[:])
	relabelled := append(signed, kcKeysetMAC(kek, signed)...)
	ks, err := pqwrap.OpenKeyset(relabelled, kek)
	if err != nil {
		t.Fatalf("GAP CLOSED? a KEK holder's relabelled keyset no longer opens (%v): kek_id is now bound by the slot; flip this test", err)
	}
	if ks.KEKID != idB || !bytes.Equal(ks.DEK, dek) {
		t.Fatalf("relabelled keyset opened to kek_id %x / DEK %x, want %x / %x", ks.KEKID, ks.DEK, idB, dek)
	}
}
