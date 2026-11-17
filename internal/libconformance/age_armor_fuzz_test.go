package libconformance

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// FuzzAgeArmorRecoveryKey pins what keyorix relies on in filippo.io/age for
// `keyorix-server admin recovery-key --recipient` (server/admin/recovery_key_encrypt.go):
// parseRecoveryKeyRecipient takes an operator-supplied "age1pq1…" (hybrid ML-KEM-768 +
// X25519) or "age1…" (X25519) string, and encryptRecoveryKeyForRecipient writes the raw
// recovery key through age.Encrypt into an armor.NewWriter. The operator later decrypts
// that output with the age CLI, so the armored bytes are the only copy of the key that
// leaves the server: they must decrypt back exactly, and be the single canonical
// spelling a strict reader accepts.
//
//   - O1 RECOVERY ROUND-TRIP: the keyorix encrypt shape, to a fixed X25519 and a fixed
//     hybrid identity, decrypts (armor.NewReader + age.Decrypt) back to the plaintext;
//     the output starts with the armor header and has no line over 64 columns.
//   - O2 ARMOR CANONICALITY: whatever armor.NewReader reads to EOF re-armors to the same
//     bytes, up to what the format lets a reader ignore (leading/trailing whitespace,
//     CRLF line ends). A second spelling of the same payload is a malleability defect.
//   - O3 RECIPIENT PARSE: a string ParseX25519Recipient or ParseHybridRecipient accepts
//     prints back (String) as its lower-case form, and is accepted in lower case too; a
//     mixed-case string is rejected (BIP 173).
//
// The identities are generated once per process, so a seed's recipient string differs
// between runs; any valid recipient exercises the same paths.
//
// What this does NOT verify: ssh-ed25519 recipients (agessh/x/crypto/ssh are kept out of
// this package's coverage map); scrypt/passphrase recipients; the age header and payload
// formats beyond what Decrypt checks; decryption of attacker-supplied age files (keyorix
// never decrypts one); bounded work (inputs are capped at 4 KiB).
func FuzzAgeArmorRecoveryKey(f *testing.F) {
	ids := ageTestIdentities(f)
	f.Add([]byte("kx-recovery-0123456789abcdef"), ids.x.Recipient().String(), []byte(nil))
	f.Add([]byte(""), ids.pq.Recipient().String(), []byte(nil))
	f.Add(bytes.Repeat([]byte{0xff}, 48), strings.ToUpper(ids.x.Recipient().String()), []byte(nil))
	if enc, err := ageArmorEncrypt([]byte("x"), ids.x.Recipient()); err == nil {
		f.Add([]byte("x"), "age1", enc)
		f.Add([]byte("y"), "age1pq1", bytes.ReplaceAll(enc, []byte("\n"), []byte("\r\n")))
		f.Add([]byte("z"), "", append([]byte("\n \n"), append(enc, " \n\t"...)...))
	}
	f.Add([]byte(nil), "", []byte(armor.Header+"\n"+armor.Footer+"\n"))
	f.Add([]byte(nil), "A"+ids.x.Recipient().String()[1:], []byte(armor.Header+"\nAB==\n"+armor.Footer+"\n")) // mixed-case HRP; non-zero pad bits
	f.Add([]byte(nil), ageMixedCaseData(ids.x.Recipient().String()), []byte(nil))                             // mixed case in the data part only
	f.Fuzz(func(t *testing.T, plaintext []byte, recipient string, armored []byte) {
		if len(plaintext) > 4<<10 || len(recipient) > 4<<10 || len(armored) > 4<<10 {
			return
		}
		checkAgeArmor(t, ids, plaintext, recipient, armored)
	})
}

// ageMixedCaseData upper-cases the first letter after the "age1" separator, so only
// bech32's mixed-case rule (not the "age" HRP comparison) can reject the string.
func ageMixedCaseData(s string) string {
	for i := len("age1"); i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' {
			return s[:i] + string(c-'a'+'A') + s[i+1:]
		}
	}
	return s
}

type ageIdentities struct {
	x  *age.X25519Identity
	pq *age.HybridIdentity
}

var (
	ageIDsOnce sync.Once
	ageIDs     ageIdentities
	ageIDsErr  error
)

func ageTestIdentities(tb testing.TB) ageIdentities {
	tb.Helper()
	ageIDsOnce.Do(func() {
		if ageIDs.x, ageIDsErr = age.GenerateX25519Identity(); ageIDsErr != nil {
			return
		}
		ageIDs.pq, ageIDsErr = age.GenerateHybridIdentity()
	})
	if ageIDsErr != nil {
		tb.Fatal(ageIDsErr)
	}
	return ageIDs
}

// ageArmorEncrypt is server/admin's encryptRecoveryKeyForRecipient, byte for byte in
// behaviour (it is unexported there).
func ageArmorEncrypt(plaintext []byte, r age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ageArmorEncode(payload []byte) []byte {
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	_, _ = aw.Write(payload)
	_ = aw.Close()
	return buf.Bytes()
}

func checkAgeArmor(t *testing.T, ids ageIdentities, plaintext []byte, recipient string, armored []byte) {
	t.Helper()

	// O1: round-trip through both recipient kinds keyorix accepts. The hybrid KEM is
	// slow, so it runs on a quarter of the inputs.
	pairs := []struct {
		r  age.Recipient
		id age.Identity
	}{{ids.x.Recipient(), ids.x}}
	if len(plaintext)%4 == 0 {
		pairs = append(pairs, struct {
			r  age.Recipient
			id age.Identity
		}{ids.pq.Recipient(), ids.pq})
	}
	for _, p := range pairs {
		enc, err := ageArmorEncrypt(plaintext, p.r)
		if err != nil {
			t.Fatalf("O1 ROUND-TRIP: encrypt failed: %v", err)
		}
		if !bytes.HasPrefix(enc, []byte(armor.Header+"\n")) {
			t.Fatalf("O1 ROUND-TRIP: output does not start with the armor header: %q", enc)
		}
		for line := range bytes.SplitSeq(enc, []byte("\n")) {
			if len(line) > 64 && !bytes.Equal(line, []byte(armor.Header)) && !bytes.Equal(line, []byte(armor.Footer)) {
				t.Fatalf("O1 ROUND-TRIP: %d-column armor line", len(line))
			}
		}
		dr, err := age.Decrypt(armor.NewReader(bytes.NewReader(enc)), p.id)
		if err != nil {
			t.Fatalf("O1 ROUND-TRIP: decrypt failed: %v", err)
		}
		got, err := io.ReadAll(dr)
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("O1 ROUND-TRIP: decrypted %q (err %v), want %q", got, err, plaintext)
		}
	}

	// O2: armor canonicality.
	if payload, err := io.ReadAll(armor.NewReader(bytes.NewReader(armored))); err == nil {
		norm := bytes.ReplaceAll(bytes.TrimSpace(armored), []byte("\r\n"), []byte("\n"))
		if re := bytes.TrimSpace(ageArmorEncode(payload)); !bytes.Equal(norm, re) {
			t.Fatalf("O2 ARMOR CANONICALITY: armor.NewReader accepted a second spelling of %d payload bytes\n in=%q\n canonical=%q", len(payload), armored, re)
		}
	}

	// O3: recipient parse. Bech32 (BIP 173) is case-insensitive but forbids mixed case.
	lower := strings.ToLower(recipient)
	if mixed := lower != recipient && strings.ToUpper(recipient) != recipient; mixed {
		if _, err := age.ParseX25519Recipient(recipient); err == nil {
			t.Fatalf("O3 RECIPIENT: mixed-case X25519 recipient %q accepted", recipient)
		}
		if _, err := age.ParseHybridRecipient(recipient); err == nil {
			t.Fatalf("O3 RECIPIENT: mixed-case hybrid recipient %q accepted", recipient)
		}
		return
	}
	if r, err := age.ParseHybridRecipient(recipient); err == nil {
		if r.String() != lower {
			t.Fatalf("O3 RECIPIENT: hybrid %q prints as %q", recipient, r.String())
		}
		if _, err := age.ParseHybridRecipient(lower); err != nil {
			t.Fatalf("O3 RECIPIENT: hybrid %q accepted but its lower case is not: %v", recipient, err)
		}
	}
	if r, err := age.ParseX25519Recipient(recipient); err == nil {
		if r.String() != lower {
			t.Fatalf("O3 RECIPIENT: X25519 %q prints as %q", recipient, r.String())
		}
		if _, err := age.ParseX25519Recipient(lower); err != nil {
			t.Fatalf("O3 RECIPIENT: X25519 %q accepted but its lower case is not: %v", recipient, err)
		}
	}
}
