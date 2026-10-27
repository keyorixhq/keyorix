package pqwrap

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

// The helpers below re-implement the keyset layout from
// docs/design/pq-key-wrapping.md §7 independently of keyset.go, so the tests
// check the implementation against the note, not against itself.

const (
	tKeysetHeaderSize = 22
	tKeysetMACSize    = 32
	tOffKCV           = 5
	tOffCount         = 21
)

func tKEK(label string) []byte {
	s := sha256.Sum256([]byte("pqwrap-test-kek/" + label))
	return s[:]
}

func tDEK(label string) []byte {
	s := sha256.Sum256([]byte("pqwrap-test-dek/" + label))
	return s[:]
}

func tKEKID(label string) [KEKIDSize]byte {
	s := sha256.Sum256([]byte("pqwrap-test-kekid/" + label))
	return [KEKIDSize]byte(s[:KEKIDSize])
}

type tSlot struct {
	typ  byte
	body []byte
}

// tSplit cuts a keyset into header, slots and MAC per §7.
func tSplit(t *testing.T, b []byte) (header []byte, slots []tSlot, mac []byte) {
	t.Helper()
	if len(b) < tKeysetHeaderSize+tKeysetMACSize {
		t.Fatalf("keyset too short: %d", len(b))
	}
	header = bytes.Clone(b[:tKeysetHeaderSize])
	rest := b[tKeysetHeaderSize : len(b)-tKeysetMACSize]
	for len(rest) > 0 {
		n := int(binary.BigEndian.Uint16(rest[1:3]))
		slots = append(slots, tSlot{typ: rest[0], body: bytes.Clone(rest[3 : 3+n])})
		rest = rest[3+n:]
	}
	return header, slots, bytes.Clone(b[len(b)-tKeysetMACSize:])
}

// tJoin re-assembles a keyset and, when kek is non-nil, recomputes the MAC
// the way a KEK holder would. With kek nil it keeps mac as given.
func tJoin(t *testing.T, header []byte, slots []tSlot, mac, kek []byte) []byte {
	t.Helper()
	out := bytes.Clone(header)
	for _, s := range slots {
		out = append(out, s.typ)
		out = binary.BigEndian.AppendUint16(out, uint16(len(s.body))) // #nosec G115 -- test slots are < 4 KiB
		out = append(out, s.body...)
	}
	if kek != nil {
		mk, err := hkdf.Key(sha256.New, kek, nil, "keyorix/pqwrap/v1/keyset-mac", 32)
		if err != nil {
			t.Fatal(err)
		}
		h := hmac.New(sha256.New, mk)
		h.Write(out)
		mac = h.Sum(nil)
	}
	return append(out, mac...)
}

func tKCV(t *testing.T, dek []byte) []byte {
	t.Helper()
	k, err := hkdf.Key(sha256.New, dek, nil, "keyorix/pqwrap/v1/dek-kcv", 16)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func tRecipients(t testing.TB, labels ...string) ([]*PrivateKey, []*PublicKey) {
	t.Helper()
	var privs []*PrivateKey
	var pubs []*PublicKey
	for _, l := range labels {
		k := testKey(t, RecipientSuite, l)
		privs = append(privs, k)
		pubs = append(pubs, k.PublicKey())
	}
	return privs, pubs
}

func mustSeal(t testing.TB, dek, kek []byte, id [KEKIDSize]byte, rs []*PublicKey) []byte {
	t.Helper()
	b, err := SealKeyset(dek, kek, id, rs)
	if err != nil {
		t.Fatalf("SealKeyset: %v", err)
	}
	return b
}

func TestKeyset_RoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("%d-recipients", n), func(t *testing.T) {
			privs, pubs := tRecipients(t, []string{"esc-a", "esc-b"}[:n]...)
			dek, kek, id := tDEK("rt"), tKEK("rt"), tKEKID("rt")
			b := mustSeal(t, dek, kek, id, pubs)

			if f := DetectFormat(b); f != FormatKeysetV1 {
				t.Fatalf("DetectFormat = %v, want keyset-v1", f)
			}
			header, slots, _ := tSplit(t, b)
			if string(header[:4]) != "KXKS" || header[4] != KeysetVersion {
				t.Fatalf("header magic/version: %x", header[:5])
			}
			if !bytes.Equal(header[tOffKCV:tOffKCV+16], tKCV(t, dek)) {
				t.Errorf("header KCV is not HKDF(DEK, dek-kcv)[:16]")
			}
			if int(header[tOffCount]) != 1+n || len(slots) != 1+n {
				t.Fatalf("slot count %d / %d slots, want %d", header[tOffCount], len(slots), 1+n)
			}
			if slots[0].typ != 1 || !bytes.Equal(slots[0].body[:KEKIDSize], id[:]) {
				t.Errorf("slot 0 is not the KEK slot carrying kek_id")
			}
			for i, s := range slots[1:] {
				if s.typ != 2 || !bytes.HasPrefix(s.body, pubs[i].Bytes()) {
					t.Errorf("slot %d is not a hybrid slot carrying its recipient public key", i+1)
				}
			}

			ks, err := OpenKeyset(b, kek)
			if err != nil {
				t.Fatalf("OpenKeyset: %v", err)
			}
			if !bytes.Equal(ks.DEK, dek) || ks.KEKID != id || len(ks.Recipients) != n {
				t.Fatalf("OpenKeyset returned the wrong DEK, kek id or recipients")
			}
			for i := range n {
				if ks.Recipients[i].KeyID() != pubs[i].KeyID() {
					t.Errorf("recipient %d out of order", i)
				}
				got, err := UnwrapRecipientSlot(b, i+1, privs[i])
				if err != nil || !bytes.Equal(got, dek) {
					t.Errorf("escrow unwrap of slot %d: %v", i+1, err)
				}
			}
			ks2, f, err := OpenKeyFile(b, kek)
			if err != nil || f != FormatKeysetV1 || !bytes.Equal(ks2.DEK, dek) {
				t.Fatalf("OpenKeyFile: %v %v", f, err)
			}
		})
	}
}

// TestKeyset_SizeBudget pins §14: at most 8 KB for a KEK slot plus two
// hybrid slots.
func TestKeyset_SizeBudget(t *testing.T) {
	_, pubs := tRecipients(t, "sz-a", "sz-b")
	b := mustSeal(t, tDEK("sz"), tKEK("sz"), tKEKID("sz"), pubs)
	if len(b) > 8*1024 {
		t.Fatalf("keyset with two hybrid slots is %d bytes, budget 8192", len(b))
	}
}

func TestKeyset_WrongKEKRefused(t *testing.T) {
	b := mustSeal(t, tDEK("wk"), tKEK("wk"), tKEKID("wk"), nil)
	if _, err := OpenKeyset(b, tKEK("other")); !errors.Is(err, ErrKEKSlot) {
		t.Fatalf("wrong KEK: got %v, want ErrKEKSlot", err)
	}
}

// TestKeyset_DEKSubstitutionRefused is the KEM-DEM gap of §6: anyone holding
// a recipient public key can make a valid envelope around a DEK of their
// choice. Inside a keyset that must never yield a DEK at boot.
func TestKeyset_DEKSubstitutionRefused(t *testing.T) {
	_, pubs := tRecipients(t, "sub-a")
	kek, dek := tKEK("sub"), tDEK("sub")
	b := mustSeal(t, dek, kek, tKEKID("sub"), pubs)
	header, slots, mac := tSplit(t, b)
	evil := tDEK("attacker")

	t.Run("hybrid slot re-wrapped to the attacker's DEK, header kept", func(t *testing.T) {
		env, err := Wrap(pubs[0], PurposeDEK, header, evil)
		if err != nil {
			t.Fatal(err)
		}
		s := append([]tSlot(nil), slots...)
		s[1] = tSlot{typ: 2, body: append(pubs[0].Bytes(), env...)}
		forged := tJoin(t, header, s, mac, nil)
		if _, err := OpenKeyset(forged, kek); !errors.Is(err, ErrKeysetMAC) {
			t.Fatalf("boot: got %v, want ErrKeysetMAC", err)
		}
		// The escrow holder cannot check the MAC; the KCV still catches a
		// slot that disagrees with the header it was spliced under.
		priv := testKey(t, RecipientSuite, "sub-a")
		if _, err := UnwrapRecipientSlot(forged, 1, priv); !errors.Is(err, ErrKCV) {
			t.Fatalf("escrow: got %v, want ErrKCV", err)
		}
	})

	t.Run("header KCV and hybrid slot both rewritten", func(t *testing.T) {
		h := bytes.Clone(header)
		copy(h[tOffKCV:], tKCV(t, evil))
		env, err := Wrap(pubs[0], PurposeDEK, h, evil)
		if err != nil {
			t.Fatal(err)
		}
		s := append([]tSlot(nil), slots...)
		s[1] = tSlot{typ: 2, body: append(pubs[0].Bytes(), env...)}
		if _, err := OpenKeyset(tJoin(t, h, s, mac, nil), kek); !errors.Is(err, ErrKEKSlot) {
			t.Fatalf("got %v, want ErrKEKSlot (the header is the KEK slot's AAD)", err)
		}
	})

	t.Run("whole keyset rebuilt under the attacker's KEK", func(t *testing.T) {
		forged := mustSeal(t, evil, tKEK("attacker"), tKEKID("sub"), pubs)
		if _, err := OpenKeyset(forged, kek); !errors.Is(err, ErrKEKSlot) {
			t.Fatalf("got %v, want ErrKEKSlot", err)
		}
	})

	t.Run("KEK slot replaced by the legacy wrap of another keyset", func(t *testing.T) {
		other := mustSeal(t, evil, kek, tKEKID("sub"), pubs)
		_, oslots, _ := tSplit(t, other)
		s := append([]tSlot(nil), slots...)
		s[0] = oslots[0]
		if _, err := OpenKeyset(tJoin(t, header, s, mac, nil), kek); !errors.Is(err, ErrKEKSlot) {
			t.Fatalf("got %v, want ErrKEKSlot (the KEK slot is bound to its header)", err)
		}
	})
}

// TestKeyset_KCVIsNotOriginAuthentication pins the property §6 states: a
// public-key holder who rewrites the header KCV and the hybrid slot together
// produces a slot that the escrow holder opens to the attacker's DEK. Only
// the KEK-keyed MAC (unavailable offline) or archive origin authentication
// (Q10) can catch it. If this test ever fails, update §6, do not delete it.
func TestKeyset_KCVIsNotOriginAuthentication(t *testing.T) {
	privs, pubs := tRecipients(t, "kcv-a")
	b := mustSeal(t, tDEK("kcv"), tKEK("kcv"), tKEKID("kcv"), pubs)
	header, slots, mac := tSplit(t, b)
	evil := tDEK("attacker-kcv")
	copy(header[tOffKCV:], tKCV(t, evil))
	env, err := Wrap(pubs[0], PurposeDEK, header, evil)
	if err != nil {
		t.Fatal(err)
	}
	slots[1] = tSlot{typ: 2, body: append(pubs[0].Bytes(), env...)}
	got, err := UnwrapRecipientSlot(tJoin(t, header, slots, mac, nil), 1, privs[0])
	if err != nil || !bytes.Equal(got, evil) {
		t.Fatalf("expected the escrow unwrap to yield the substituted DEK (no origin authentication offline); got %x, %v", got, err)
	}
}

// TestKeyset_DroppedSlotFailsBeforeMAC is design test 5 (§7): removing a
// hybrid slot fails the boot before the MAC check, whether or not the slot
// count is adjusted, and the remaining slot no longer opens for its escrow
// holder either when the count is adjusted.
func TestKeyset_DroppedSlotFailsBeforeMAC(t *testing.T) {
	privs, pubs := tRecipients(t, "drop-a", "drop-b")
	kek := tKEK("drop")
	b := mustSeal(t, tDEK("drop"), kek, tKEKID("drop"), pubs)
	header, slots, mac := tSplit(t, b)
	kept := []tSlot{slots[0], slots[1]}

	t.Run("count left as is", func(t *testing.T) {
		_, err := OpenKeyset(tJoin(t, header, kept, mac, nil), kek)
		if !errors.Is(err, ErrKeysetMalformed) {
			t.Fatalf("got %v, want ErrKeysetMalformed", err)
		}
	})
	t.Run("count adjusted", func(t *testing.T) {
		h := bytes.Clone(header)
		h[tOffCount]--
		edited := tJoin(t, h, kept, mac, nil)
		if _, err := OpenKeyset(edited, kek); !errors.Is(err, ErrKEKSlot) {
			t.Fatalf("got %v, want ErrKEKSlot", err)
		}
		// Even with a MAC recomputed by a KEK holder the KEK slot's AAD no
		// longer matches, so the failure is the KEK slot, not the MAC.
		if _, err := OpenKeyset(tJoin(t, h, kept, nil, kek), kek); !errors.Is(err, ErrKEKSlot) {
			t.Fatalf("re-MACed: got %v, want ErrKEKSlot", err)
		}
		if _, err := UnwrapRecipientSlot(edited, 1, privs[0]); err == nil {
			t.Fatal("escrow holder opened a slot of an edited keyset")
		}
	})
}

// TestKeyset_SlotFromOlderKeysetRefused: a hybrid slot spliced in from an
// older keyset (old DEK, old KCV) fails at boot and for the escrow holder.
func TestKeyset_SlotFromOlderKeysetRefused(t *testing.T) {
	privs, pubs := tRecipients(t, "old-a")
	kek := tKEK("old")
	oldKS := mustSeal(t, tDEK("old-1"), kek, tKEKID("old"), pubs)
	newKS := mustSeal(t, tDEK("old-2"), kek, tKEKID("old"), pubs)
	_, oslots, _ := tSplit(t, oldKS)
	header, slots, mac := tSplit(t, newKS)
	slots[1] = oslots[1]
	spliced := tJoin(t, header, slots, mac, nil)
	if _, err := OpenKeyset(spliced, kek); !errors.Is(err, ErrKeysetMAC) {
		t.Fatalf("boot: got %v, want ErrKeysetMAC", err)
	}
	if _, err := OpenKeyset(tJoin(t, header, slots, nil, kek), kek); err == nil {
		t.Fatal("boot accepted a stale slot even after a KEK holder re-MACed it")
	}
	if _, err := UnwrapRecipientSlot(spliced, 1, privs[0]); err == nil {
		t.Fatal("escrow holder opened a slot spliced from an older keyset")
	}
}

// TestKeyset_HybridSlotStructureCheckedAtBoot: even under a valid MAC (a KEK
// holder's mistake, or a future writer bug), boot refuses a hybrid slot whose
// stored public key does not match the envelope's key id, or whose envelope
// is for another purpose.
func TestKeyset_HybridSlotStructureCheckedAtBoot(t *testing.T) {
	_, pubs := tRecipients(t, "st-a", "st-b")
	kek := tKEK("st")
	b := mustSeal(t, tDEK("st"), kek, tKEKID("st"), pubs)
	header, slots, _ := tSplit(t, b)

	t.Run("key id mismatch", func(t *testing.T) {
		s := append([]tSlot(nil), slots...)
		pkLen := len(pubs[0].Bytes())
		// slot 1's public key with slot 2's envelope
		s[1] = tSlot{typ: 2, body: append(bytes.Clone(slots[1].body[:pkLen]), slots[2].body[pkLen:]...)}
		_, err := OpenKeyset(tJoin(t, header, s, nil, kek), kek)
		if !errors.Is(err, ErrKeysetMalformed) {
			t.Fatalf("got %v, want ErrKeysetMalformed", err)
		}
	})
	t.Run("wrong purpose", func(t *testing.T) {
		env, err := Wrap(pubs[0], PurposeBackupKey, header, tDEK("st"))
		if err != nil {
			t.Fatal(err)
		}
		s := append([]tSlot(nil), slots...)
		s[1] = tSlot{typ: 2, body: append(pubs[0].Bytes(), env...)}
		if _, err := OpenKeyset(tJoin(t, header, s, nil, kek), kek); !errors.Is(err, ErrKeysetMalformed) {
			t.Fatalf("got %v, want ErrKeysetMalformed", err)
		}
	})
	t.Run("hybrid slot in position 0", func(t *testing.T) {
		s := []tSlot{slots[1], slots[0], slots[2]}
		if _, err := OpenKeyset(tJoin(t, header, s, nil, kek), kek); !errors.Is(err, ErrKeysetMalformed) {
			t.Fatalf("got %v, want ErrKeysetMalformed", err)
		}
	})
	t.Run("two KEK slots", func(t *testing.T) {
		s := []tSlot{slots[0], slots[0], slots[2]}
		if _, err := OpenKeyset(tJoin(t, header, s, nil, kek), kek); !errors.Is(err, ErrKeysetMalformed) {
			t.Fatalf("got %v, want ErrKeysetMalformed", err)
		}
	})
}

// TestKeyset_EveryByteFlipFails: no single-byte change to a keyset opens.
func TestKeyset_EveryByteFlipFails(t *testing.T) {
	_, pubs := tRecipients(t, "flip-a")
	kek := tKEK("flip")
	b := mustSeal(t, tDEK("flip"), kek, tKEKID("flip"), pubs)
	for i := range b {
		c := bytes.Clone(b)
		c[i] ^= 0x01
		if _, err := OpenKeyset(c, kek); err == nil {
			t.Fatalf("keyset with byte %d flipped opened", i)
		}
	}
}

func TestKeyset_TruncationAndTrailingRefused(t *testing.T) {
	kek := tKEK("trunc")
	b := mustSeal(t, tDEK("trunc"), kek, tKEKID("trunc"), nil)
	for _, n := range []int{0, 4, tKeysetHeaderSize, len(b) - 1} {
		if _, err := OpenKeyset(b[:n], kek); err == nil {
			t.Errorf("keyset truncated to %d bytes opened", n)
		}
	}
	if _, err := OpenKeyset(append(bytes.Clone(b), 0), kek); !errors.Is(err, ErrKeysetMalformed) {
		t.Errorf("trailing byte: got %v, want ErrKeysetMalformed", err)
	}
}

// TestKeyset_NewerVersionFailsClosedWithClearError: a keyset from a newer
// binary is refused with ErrKeysetVersion, never guessed at (§13).
func TestKeyset_NewerVersionFailsClosedWithClearError(t *testing.T) {
	kek := tKEK("ver")
	b := mustSeal(t, tDEK("ver"), kek, tKEKID("ver"), nil)
	b[4] = KeysetVersion + 1
	_, _, err := OpenKeyFile(b, kek)
	if !errors.Is(err, ErrKeysetVersion) {
		t.Fatalf("got %v, want ErrKeysetVersion", err)
	}
}

func TestDetectFormat(t *testing.T) {
	ks := mustSeal(t, tDEK("df"), tKEK("df"), tKEKID("df"), nil)
	legacyKXKS := append([]byte("KXKS"), make([]byte, LegacyKeyFileSize-4)...)
	cases := []struct {
		name string
		b    []byte
		want KeyFileFormat
	}{
		{"empty", nil, FormatUnknown},
		{"59 bytes", make([]byte, 59), FormatUnknown},
		{"60 bytes", make([]byte, 60), FormatLegacy60},
		// A legacy file starts with a random nonce: a 60-byte file is legacy
		// even if its nonce happens to start with the keyset magic.
		{"60 bytes starting KXKS", legacyKXKS, FormatLegacy60},
		{"61 bytes", make([]byte, 61), FormatUnknown},
		{"keyset", ks, FormatKeysetV1},
		{"short KXKS", []byte("KXKS\x01"), FormatUnknown},
	}
	for _, c := range cases {
		if got := DetectFormat(c.b); got != c.want {
			t.Errorf("%s: DetectFormat = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestOpenKeyFile_UnknownFormatRefused(t *testing.T) {
	for _, b := range [][]byte{nil, make([]byte, 59), make([]byte, 61), []byte("KXKS\x01")} {
		if _, f, err := OpenKeyFile(b, tKEK("u")); !errors.Is(err, ErrUnknownFormat) || f != FormatUnknown {
			t.Errorf("%d bytes: got %v %v, want ErrUnknownFormat", len(b), f, err)
		}
	}
}

func TestSealLegacy_RoundTrip(t *testing.T) {
	kek, dek := tKEK("leg"), tDEK("leg")
	b, err := SealLegacy(dek, kek)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != LegacyKeyFileSize || DetectFormat(b) != FormatLegacy60 {
		t.Fatalf("SealLegacy wrote %d bytes, format %v", len(b), DetectFormat(b))
	}
	ks, f, err := OpenKeyFile(b, kek)
	if err != nil || f != FormatLegacy60 || !bytes.Equal(ks.DEK, dek) || len(ks.Recipients) != 0 {
		t.Fatalf("OpenKeyFile(legacy): %v %v", f, err)
	}
	if _, _, err := OpenKeyFile(b, tKEK("other")); !errors.Is(err, ErrLegacyOpen) {
		t.Fatalf("wrong KEK on legacy: got %v, want ErrLegacyOpen", err)
	}
}

// TestRekeyKeyset_KeepsHybridSlotsByteForByte is the rotate-kek /
// migrate-provider rule (§8): the KEK slot and MAC move to the new KEK, the
// header and every hybrid slot stay byte for byte, escrow still works.
func TestRekeyKeyset_KeepsHybridSlotsByteForByte(t *testing.T) {
	privs, pubs := tRecipients(t, "rk-a", "rk-b")
	oldKEK, newKEK, dek := tKEK("rk-old"), tKEK("rk-new"), tDEK("rk")
	b := mustSeal(t, dek, oldKEK, tKEKID("rk-old"), pubs)
	nb, err := RekeyKeyset(b, oldKEK, newKEK, tKEKID("rk-new"))
	if err != nil {
		t.Fatalf("RekeyKeyset: %v", err)
	}
	oh, oslots, omac := tSplit(t, b)
	nh, ns, nmac := tSplit(t, nb)
	if !bytes.Equal(oh, nh) {
		t.Error("header changed")
	}
	for i := 1; i < len(oslots); i++ {
		if !bytes.Equal(oslots[i].body, ns[i].body) {
			t.Errorf("hybrid slot %d changed", i)
		}
	}
	if bytes.Equal(omac, nmac) {
		t.Error("MAC did not change with the KEK")
	}
	ks, err := OpenKeyset(nb, newKEK)
	if err != nil || !bytes.Equal(ks.DEK, dek) || ks.KEKID != tKEKID("rk-new") {
		t.Fatalf("open under new KEK: %v", err)
	}
	if _, err := OpenKeyset(nb, oldKEK); err == nil {
		t.Fatal("rekeyed keyset still opens under the old KEK")
	}
	for i, p := range privs {
		if got, err := UnwrapRecipientSlot(nb, i+1, p); err != nil || !bytes.Equal(got, dek) {
			t.Errorf("escrow slot %d after rekey: %v", i+1, err)
		}
	}
	if _, err := RekeyKeyset(b, tKEK("wrong"), newKEK, tKEKID("x")); err == nil {
		t.Fatal("RekeyKeyset accepted the wrong current KEK")
	}
}

// TestSealKeyset_DEKRotationRewrapsEverySlot is design test 1 at the codec
// level: a new keyset for a new DEK built from an opened keyset's recipients
// has every hybrid slot on the new DEK, in the same order, and nothing in it
// opens to the old DEK.
func TestSealKeyset_DEKRotationRewrapsEverySlot(t *testing.T) {
	privs, pubs := tRecipients(t, "rot-a", "rot-b")
	kek := tKEK("rot")
	oldDEK, newDEK := tDEK("rot-1"), tDEK("rot-2")
	cur, err := OpenKeyset(mustSeal(t, oldDEK, kek, tKEKID("rot"), pubs), kek)
	if err != nil {
		t.Fatal(err)
	}
	nb := mustSeal(t, newDEK, kek, cur.KEKID, cur.Recipients)
	next, err := OpenKeyset(nb, kek)
	if err != nil {
		t.Fatal(err)
	}
	if err := SameRecipients(cur, next); err != nil {
		t.Fatalf("SameRecipients after rotation: %v", err)
	}
	h, _, _ := tSplit(t, nb)
	if !bytes.Equal(h[tOffKCV:tOffKCV+16], tKCV(t, newDEK)) {
		t.Error("header KCV is not the new DEK's")
	}
	for i, p := range privs {
		got, err := UnwrapRecipientSlot(nb, i+1, p)
		if err != nil || !bytes.Equal(got, newDEK) {
			t.Errorf("slot %d does not open to the new DEK: %v", i+1, err)
		}
	}
}

func TestSameRecipients(t *testing.T) {
	_, pubs := tRecipients(t, "same-a", "same-b")
	kek := tKEK("same")
	open := func(rs []*PublicKey) *Keyset {
		ks, err := OpenKeyset(mustSeal(t, tDEK("same"), kek, tKEKID("same"), rs), kek)
		if err != nil {
			t.Fatal(err)
		}
		return ks
	}
	a, b := open(pubs), open([]*PublicKey{pubs[1], pubs[0]})
	if err := SameRecipients(a, open(pubs)); err != nil {
		t.Errorf("identical sets: %v", err)
	}
	if SameRecipients(a, b) == nil {
		t.Error("reordered set reported as the same")
	}
	if SameRecipients(a, open(pubs[:1])) == nil {
		t.Error("smaller set reported as the same")
	}
}

func TestSealKeyset_RefusesBadInput(t *testing.T) {
	_, pubs := tRecipients(t, "bad-a")
	k768 := testKey(t, SuiteX25519MLKEM768, "bad-768").PublicKey()
	many := make([]*PublicKey, MaxRecipients+1)
	for i := range many {
		many[i] = testKey(t, RecipientSuite, fmt.Sprintf("many-%d", i)).PublicKey()
	}
	cases := map[string]func() ([]byte, error){
		"short DEK":         func() ([]byte, error) { return SealKeyset(make([]byte, 16), tKEK("b"), tKEKID("b"), nil) },
		"short KEK":         func() ([]byte, error) { return SealKeyset(tDEK("b"), make([]byte, 16), tKEKID("b"), nil) },
		"zero KEK":          func() ([]byte, error) { return SealKeyset(tDEK("b"), make([]byte, 32), tKEKID("b"), nil) },
		"zero DEK":          func() ([]byte, error) { return SealKeyset(make([]byte, 32), tKEK("b"), tKEKID("b"), nil) },
		"nil recipient":     func() ([]byte, error) { return SealKeyset(tDEK("b"), tKEK("b"), tKEKID("b"), []*PublicKey{nil}) },
		"768 recipient":     func() ([]byte, error) { return SealKeyset(tDEK("b"), tKEK("b"), tKEKID("b"), []*PublicKey{k768}) },
		"duplicate":         func() ([]byte, error) { return SealKeyset(tDEK("b"), tKEK("b"), tKEKID("b"), []*PublicKey{pubs[0], pubs[0]}) },
		"too many":          func() ([]byte, error) { return SealKeyset(tDEK("b"), tKEK("b"), tKEKID("b"), many) },
		"legacy short DEK":  func() ([]byte, error) { return SealLegacy(make([]byte, 16), tKEK("b")) },
		"legacy short KEK":  func() ([]byte, error) { return SealLegacy(tDEK("b"), make([]byte, 16)) },
	}
	for name, f := range cases {
		if _, err := f(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
