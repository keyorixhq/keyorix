package admin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/complexity"
)

// LIB-FUZZ-1 items 2 and 3: filippo.io/age and golang.org/x/crypto/ssh as keyorix's
// `admin recovery-key rotate --recipient` uses them.
//
// INVENTORY (who calls what, with input from whom):
//   - age.ParseHybridRecipient / age.ParseX25519Recipient: the --recipient flag
//     string, typed by the operator on the host (parseRecoveryKeyRecipient).
//   - ssh.ParseAuthorizedKey + agessh.NewEd25519Recipient: the CONTENT of the file
//     the same flag names (a copied id_ed25519.pub, a file from a ticket or chat).
//     This is the only place keyorix parses an SSH key; no authorized_keys of
//     users, no SSH certificates and no host keys are parsed anywhere else in
//     non-test code (rg "x/crypto/ssh" shows recovery_key_encrypt.go only; the
//     egress guard lists ssh.Dial only as a forbidden sink).
//   - age.Encrypt + armor.NewWriter: encrypt the new recovery key to that recipient.
//   - age.Decrypt is NOT called by keyorix: the operator decrypts with `age -d`. The
//     "attacker-supplied ciphertext" surface therefore does not exist in this
//     binary; FuzzAgeDecryptArmoredBounded below pins memory/time of the library's
//     decrypt path with keyorix's own armor+age pairing anyway, because a future
//     importer (restore of an encrypted export) would call exactly that.
// The operator is trusted, so this is a hardening and wrapper-logic target, not a
// remote surface: the oracles are about keyorix's dispatch and about the key that
// actually ends up as the recipient (a mis-parsed recipient means the recovery key
// is encrypted to a key nobody holds, or to a different one).
//
// Each oracle returns an error rather than calling t.Fatalf, so the red-proof tests
// at the bottom can feed it a broken parser and show it goes red without editing
// production code.

type parseRecipientFn func(spec string) (age.Recipient, error)

// checkRecipientSpecOracles covers the age1... string branch of
// parseRecoveryKeyRecipient. Specs that do not start with "age1" take the file-path
// branch, which reads arbitrary files and is fuzzed through its content instead.
func checkRecipientSpecOracles(spec string, parse parseRecipientFn) error {
	if !strings.HasPrefix(spec, "age1") {
		return nil
	}
	r, err := parse(spec)
	if (r == nil) == (err == nil) {
		return fmt.Errorf("parse(%.60q) returned recipient=%v err=%v: exactly one must be set", spec, r, err)
	}
	if err != nil {
		// An age1... string that fails to parse must be refused AS an age string. If it
		// fell through to the file branch, a file in the working directory named like
		// the spec would be read instead.
		if strings.Contains(err.Error(), "recipient public key file") || strings.Contains(err.Error(), "SSH public key") {
			return fmt.Errorf("age1-prefixed spec %.60q was handled as a file path: %v", spec, err)
		}
		return nil
	}
	wantHybrid := strings.HasPrefix(spec, "age1pq1")
	switch v := r.(type) {
	case *age.HybridRecipient:
		if !wantHybrid {
			return fmt.Errorf("classical-looking spec %.60q produced a hybrid recipient", spec)
		}
		if v.String() != spec {
			return fmt.Errorf("hybrid spec was accepted but is not canonical: %.60q parses to %.60q", spec, v.String())
		}
	case *age.X25519Recipient:
		if wantHybrid {
			return fmt.Errorf("hybrid spec %.60q produced a classical recipient", spec)
		}
		if v.String() != spec {
			return fmt.Errorf("spec was accepted but is not canonical: %.60q parses to %.60q (two spellings, one recipient)", spec, v.String())
		}
	default:
		return fmt.Errorf("spec %.60q produced unexpected recipient type %T", spec, r)
	}
	return nil
}

// checkRecipientMutation: bech32's checksum detects EVERY substitution of up to 4
// characters in a string of at most 89 characters (BCH code, minimum distance 5). An
// X25519 recipient is 62 characters, so a spec that differs from a valid recipient in
// 1..4 positions (same length) must be refused. Accepting it would mean the recovery
// key is encrypted to a key that is not the one the operator named.
func checkRecipientMutation(orig, spec string, parse parseRecipientFn) error {
	if len(spec) != len(orig) || spec == orig || len(orig) > 89 {
		return nil
	}
	diff := 0
	for i := 0; i < len(orig); i++ {
		if orig[i] != spec[i] {
			diff++
		}
	}
	if diff > 4 {
		return nil
	}
	if r, err := parse(spec); err == nil {
		return fmt.Errorf("a recipient %d character(s) away from a valid one was accepted: %q -> %v", diff, spec, r)
	}
	return nil
}

// recipientFixture builds a real recipient of the requested kind together with the
// identity that can open what is encrypted to it. kind 1 writes the ssh public key
// file (with the comment and the leading '#' noise lines) and returns its path.
type recipientFixture struct {
	spec string
	id   age.Identity
}

func newRecipientFixture(kind uint8, dir, noise, comment string) (recipientFixture, error) {
	switch kind % 3 {
	case 0:
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return recipientFixture{}, err
		}
		return recipientFixture{spec: id.Recipient().String(), id: id}, nil
	case 2:
		id, err := age.GenerateHybridIdentity()
		if err != nil {
			return recipientFixture{}, err
		}
		return recipientFixture{spec: id.Recipient().String(), id: id}, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return recipientFixture{}, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return recipientFixture{}, err
	}
	id, err := agessh.NewEd25519Identity(priv)
	if err != nil {
		return recipientFixture{}, err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	comment = strings.NewReplacer("\n", " ", "\r", " ").Replace(comment)
	var b strings.Builder
	if noise != "" {
		b.WriteString("#" + strings.ReplaceAll(noise, "\n", "\n#") + "\n\n")
	}
	b.WriteString(line)
	if comment != "" {
		b.WriteString(" " + comment)
	}
	b.WriteString("\n")
	path := filepath.Join(dir, "recipient.pub")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return recipientFixture{}, err
	}
	return recipientFixture{spec: path, id: id}, nil
}

type encryptFn func(rawKey string, r age.Recipient) ([]byte, error)

const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// checkEncryptRoundTrip: the armored output of encryptRecoveryKeyForRecipient opens
// with the recipient's identity to exactly the key that was encrypted, is printable
// (the code's own promise: "safe to print to a terminal"), does not contain the
// plaintext key, and a changed or cut armored body never opens to a DIFFERENT key.
func checkEncryptRoundTrip(rawKey string, fx recipientFixture, parse parseRecipientFn, encrypt encryptFn, tamperPos uint32, tamperChar uint8) error {
	r, err := parse(fx.spec)
	if err != nil {
		return fmt.Errorf("a freshly generated recipient (%.40q) was refused: %w", fx.spec, err)
	}
	ct, err := encrypt(rawKey, r)
	if err != nil {
		return fmt.Errorf("encrypt of a %d-byte key failed: %w", len(rawKey), err)
	}
	for i, c := range ct {
		if c != '\n' && (c < 0x20 || c > 0x7e) {
			return fmt.Errorf("armored output has a non-printable byte 0x%02x at %d", c, i)
		}
	}
	if !bytes.HasPrefix(ct, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) {
		return fmt.Errorf("armored output does not start with the armor header: %.40q", ct)
	}
	open := func(in []byte) (string, error) {
		dr, err := age.Decrypt(armor.NewReader(bytes.NewReader(in)), fx.id)
		if err != nil {
			return "", err
		}
		out, err := io.ReadAll(dr)
		return string(out), err
	}
	got, err := open(ct)
	if err != nil {
		return fmt.Errorf("the recipient's own identity cannot open the ciphertext: %w", err)
	}
	if got != rawKey {
		return fmt.Errorf("round trip changed the key: %d bytes in, %d bytes out", len(rawKey), len(got))
	}

	// The plaintext key must not appear in what is printed (body lines only: the
	// header and footer are fixed text a long key could coincide with).
	if len(rawKey) >= 24 {
		for line := range strings.SplitSeq(string(ct), "\n") {
			if !strings.HasPrefix(line, "-----") && strings.Contains(line, rawKey) {
				return fmt.Errorf("the plaintext key appears in the armored output")
			}
		}
	}

	// Tamper: change one body character, or cut the output. Either must fail to open
	// or open to the SAME key (a base64 character whose low bits are padding).
	var bodyIdx []int
	off := 0
	for _, line := range strings.SplitAfter(string(ct), "\n") {
		if !strings.HasPrefix(line, "-----") {
			for j := 0; j < len(line); j++ {
				if strings.IndexByte(base64Alphabet, line[j]) >= 0 {
					bodyIdx = append(bodyIdx, off+j)
				}
			}
		}
		off += len(line)
	}
	if len(bodyIdx) > 0 {
		pos := bodyIdx[int(tamperPos)%len(bodyIdx)]
		mut := bytes.Clone(ct)
		nc := base64Alphabet[int(tamperChar)%len(base64Alphabet)]
		if nc == mut[pos] {
			nc = base64Alphabet[(int(tamperChar)+1)%len(base64Alphabet)]
		}
		mut[pos] = nc
		if out, err := open(mut); err == nil && out != rawKey {
			return fmt.Errorf("a changed armored character (pos %d) opened to a DIFFERENT key (%d bytes)", pos, len(out))
		}
		if out, err := open(ct[:int(tamperPos)%len(ct)]); err == nil && out != rawKey {
			return fmt.Errorf("a truncated armored output opened to a DIFFERENT key (%d bytes)", len(out))
		}
	}
	return nil
}

// sshOracleOK checks the x/crypto/ssh side for any file content ssh accepts: the key
// re-marshals and re-parses to the same wire bytes and fingerprint, and its algorithm
// name is stable through the wire form.
func checkSSHRoundTrip(content []byte) error {
	pk, _, _, _, err := ssh.ParseAuthorizedKey(content)
	if err != nil {
		return nil
	}
	wire := pk.Marshal()
	pk2, _, _, _, err := ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(pk))
	if err != nil {
		return fmt.Errorf("MarshalAuthorizedKey output of an accepted %s key does not parse: %w", pk.Type(), err)
	}
	if !bytes.Equal(pk2.Marshal(), wire) {
		return fmt.Errorf("%s key changed through MarshalAuthorizedKey/ParseAuthorizedKey", pk.Type())
	}
	if ssh.FingerprintSHA256(pk) != ssh.FingerprintSHA256(pk2) || ssh.FingerprintLegacyMD5(pk) != ssh.FingerprintLegacyMD5(pk2) {
		return fmt.Errorf("fingerprint of a %s key is not stable across a round trip", pk.Type())
	}
	pk3, err := ssh.ParsePublicKey(wire)
	if err != nil {
		return fmt.Errorf("the wire form of an accepted %s key does not parse: %w", pk.Type(), err)
	}
	if pk3.Type() != pk.Type() || ssh.FingerprintSHA256(pk3) != ssh.FingerprintSHA256(pk) {
		return fmt.Errorf("wire parse of a %s key disagrees (%s)", pk.Type(), pk3.Type())
	}
	return nil
}

// checkRecipientFile: keyorix accepts a recipient file only if an independent reading
// of the bytes finds an ssh-ed25519 key in it, and the accepted key is exactly what
// ssh parses (the first key; keyorix reads no further lines).
func checkRecipientFile(content []byte, spec string, parse parseRecipientFn) error {
	r, err := parse(spec)
	if (r == nil) == (err == nil) {
		return fmt.Errorf("parse returned recipient=%v err=%v: exactly one must be set", r, err)
	}
	if err == nil {
		if !bytes.Contains(content, []byte("ssh-ed25519")) {
			return fmt.Errorf("accepted a recipient file with no \"ssh-ed25519\" token in it")
		}
		pk, _, _, _, perr := ssh.ParseAuthorizedKey(bytes.TrimSpace(content))
		if perr != nil || pk.Type() != ssh.KeyAlgoED25519 {
			return fmt.Errorf("accepted a file whose key is not an ssh-ed25519 key (type %v, err %v)", pk, perr)
		}
	}
	return checkSSHRoundTrip(content)
}

// ---- fuzz targets --------------------------------------------------------------

func FuzzRecoveryKeyRecipientSpec(f *testing.F) {
	x, err := age.GenerateX25519Identity()
	if err != nil {
		f.Fatal(err)
	}
	h, err := age.GenerateHybridIdentity()
	if err != nil {
		f.Fatal(err)
	}
	orig := x.Recipient().String()
	for _, s := range []string{
		orig, orig + " ", orig + "\n", strings.ToUpper(orig), orig[:len(orig)-1], orig + "q",
		"age1", "age1pq1", "age1pq1" + orig[4:], "age1" + strings.Repeat("q", 100),
		h.Recipient().String(), strings.Replace(h.Recipient().String(), "age1pq1", "age1", 1),
		"age1\x00", "age1\xff\xfe", "age1/etc/passwd", "age1foo.pub",
	} {
		f.Add(s)
	}
	// one-character substitutions of a valid recipient
	for _, i := range []int{4, 10, 30, 55, 61} {
		b := []byte(orig)
		b[i] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"[(strings.IndexByte("qpzry9x8gf2tvdw0s3jn54khce6mua7l", b[i])+1)%32]
		f.Add(string(b))
	}
	f.Fuzz(func(t *testing.T, spec string) {
		fuzzutil.Guard(t.Fatalf, "parseRecoveryKeyRecipient(age1...)", func() {
			if err := checkRecipientSpecOracles(spec, parseRecoveryKeyRecipient); err != nil {
				t.Errorf("RECIPIENT SPEC ORACLE: %v", err)
			}
			if err := checkRecipientMutation(orig, spec, parseRecoveryKeyRecipient); err != nil {
				t.Errorf("RECIPIENT MUTATION ORACLE: %v", err)
			}
		})
	})
}

func FuzzRecoveryKeyEncryptRoundTrip(f *testing.F) {
	dir := f.TempDir()
	long := strings.Repeat("ABCDE-FGHJK-", 6)
	for _, kind := range []uint8{0, 1, 2} {
		f.Add("ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ2-34567-89ABC-DEFGH-JKLMN-PQRST-UV", kind, "", "", uint32(7), uint8(3))
		f.Add(long+long, kind, "a comment\n# second", "operator@laptop", uint32(300), uint8(9))
		f.Add("", kind, "", "", uint32(0), uint8(0))
		f.Add("\x00\xff\n", kind, "x", "key with spaces", uint32(1), uint8(60))
	}
	f.Fuzz(func(t *testing.T, rawKey string, kind uint8, noise, comment string, tamperPos uint32, tamperChar uint8) {
		if len(rawKey) > 1<<16 || len(noise) > 1<<12 || len(comment) > 1<<12 {
			return
		}
		fx, err := newRecipientFixture(kind, dir, noise, comment)
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
		fuzzutil.Guard(t.Fatalf, "recovery-key encrypt round trip", func() {
			if err := checkEncryptRoundTrip(rawKey, fx, parseRecoveryKeyRecipient, encryptRecoveryKeyForRecipient, tamperPos, tamperChar); err != nil {
				t.Errorf("ENCRYPT ORACLE (kind %d): %v", kind%3, err)
			}
		})
	})
}

func FuzzRecoveryKeyRecipientFile(f *testing.F) {
	dir := f.TempDir()
	path := filepath.Join(dir, "recipient.pub")
	ed := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	edPub, _ := ssh.NewPublicKey(ed.Public())
	edLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(edPub)))
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecPub, _ := ssh.NewPublicKey(&ec.PublicKey)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rkPub, _ := ssh.NewPublicKey(&rk.PublicKey)
	for _, s := range []string{
		edLine, edLine + "\n", edLine + " operator@host\n", edLine + "\r\n",
		"# comment\n\n" + edLine + "\n", `from="10.0.0.1",no-pty ` + edLine,
		edLine + "\n" + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ecPub))) + "\n",
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ecPub))),
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(rkPub))),
		"sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t", "ssh-ed25519", "ssh-ed25519 ",
		"ssh-ed25519 AAAA", "ssh-ed25519 !!!!", "ssh-ed25519 " + strings.Repeat("A", 100000),
		"ssh-ed25519-cert-v01@openssh.com AAAA", "", "\x00", "\xff\xfe\xfd",
		strings.Replace(edLine, "ssh-ed25519 ", "ssh-ed25519\t", 1),
		strings.Replace(edLine, "AAAAC3", "AAAAD3", 1),
	} {
		f.Add([]byte(s))
	}
	budget := complexity.Budget{MaxAllocBytesPerByte: 64, FloorBytes: 1 << 20, AbsMaxAllocBytes: 256 << 20}
	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 1<<20 {
			return
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		fuzzutil.Guard(t.Fatalf, "parseRecoveryKeyRecipient(file)", func() {
			c := complexity.Measure(func() {
				if err := checkRecipientFile(content, path, parseRecoveryKeyRecipient); err != nil {
					t.Errorf("RECIPIENT FILE ORACLE: %v", err)
				}
			})
			budget.Check(t.Errorf, "recovery recipient file parse", len(content), c)
		})
	})
}

// FuzzAgeDecryptArmoredBounded: memory and time of the age+armor decrypt path on
// arbitrary bytes. keyorix never calls it (the operator runs `age -d`); it is here so
// that a hostile header cannot turn a few bytes into a large allocation, the failure
// class pkcs7 had (130 B -> 1.8 GB), in the one library pairing keyorix ships output
// for.
func FuzzAgeDecryptArmoredBounded(f *testing.F) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		f.Fatal(err)
	}
	ct, err := encryptRecoveryKeyForRecipient("ABCDE-FGHJK", id.Recipient())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ct)
	f.Add([]byte("age-encryption.org/v1\n-> X25519 " + strings.Repeat("A", 1<<20) + "\n"))
	f.Add([]byte("age-encryption.org/v1\n-> " + strings.Repeat("a ", 50000) + "\n"))
	f.Add([]byte("age-encryption.org/v1\n-> scrypt " + strings.Repeat("A", 22) + " 99\nAAAA\n--- AAAA\n"))
	f.Add([]byte("-----BEGIN AGE ENCRYPTED FILE-----\n" + strings.Repeat("A", 1<<20) + "\n-----END AGE ENCRYPTED FILE-----\n"))
	f.Add([]byte("age-encryption.org/v1\n" + strings.Repeat("-> X25519 AAAA\nAAAA\n", 5000) + "--- AAAA\n"))
	budget := complexity.Budget{MaxAllocBytesPerByte: 64, FloorBytes: 4 << 20, AbsMaxAllocBytes: 256 << 20}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4<<20 {
			return
		}
		fuzzutil.Guard(t.Fatalf, "age+armor decrypt", func() {
			c := complexity.Measure(func() {
				for _, in := range []io.Reader{bytes.NewReader(data), armor.NewReader(bytes.NewReader(data))} {
					if r, err := age.Decrypt(in, id); err == nil {
						_, _ = io.Copy(io.Discard, io.LimitReader(r, 1<<20))
					}
				}
			})
			budget.Check(t.Errorf, "age.Decrypt", len(data), c)
		})
	})
}

// ---- red-proof -----------------------------------------------------------------
//
// Each oracle is shown green on the real implementation and red on a plausible wrong
// one. No production file is edited: the wrong implementations are passed in.

func TestRecoveryKeyRecipientOracles_RedGreen(t *testing.T) {
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	orig := x.Recipient().String()
	oneOff := []byte(orig)
	oneOff[20] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"[(strings.IndexByte("qpzry9x8gf2tvdw0s3jn54khce6mua7l", oneOff[20])+1)%32]

	// green on the real parser
	for _, s := range []string{orig, orig + " ", strings.ToUpper(orig), "age1", "age1pq1", string(oneOff), "age1foo.pub"} {
		if err := checkRecipientSpecOracles(s, parseRecoveryKeyRecipient); err != nil {
			t.Errorf("real parser, spec %.40q: %v", s, err)
		}
		if err := checkRecipientMutation(orig, s, parseRecoveryKeyRecipient); err != nil {
			t.Errorf("real parser, mutation %.40q: %v", s, err)
		}
	}

	// red: an age1 spec falls through to the file branch
	fallthroughFile := func(spec string) (age.Recipient, error) {
		if _, err := parseRecoveryKeyRecipient(spec); err != nil {
			return nil, fmt.Errorf("read recipient public key file %q: %w", spec, err)
		}
		return parseRecoveryKeyRecipient(spec)
	}
	if checkRecipientSpecOracles("age1foo.pub", fallthroughFile) == nil {
		t.Error("spec oracle stayed green when an age1 spec falls through to the file branch")
	}
	// red: whitespace is trimmed, so two spellings name one recipient
	trims := func(spec string) (age.Recipient, error) { return parseRecoveryKeyRecipient(strings.TrimSpace(spec)) }
	if checkRecipientSpecOracles(orig+" ", trims) == nil {
		t.Error("spec oracle stayed green on a parser that trims whitespace (non-canonical accept)")
	}
	// red: the checksum is ignored, so a one-character change is accepted
	noChecksum := func(spec string) (age.Recipient, error) {
		if len(spec) == len(orig) && spec[:len(spec)-6] == orig[:len(orig)-6] {
			return parseRecoveryKeyRecipient(orig)
		}
		return parseRecoveryKeyRecipient(spec)
	}
	last := []byte(orig)
	last[len(last)-1] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"[(strings.IndexByte("qpzry9x8gf2tvdw0s3jn54khce6mua7l", last[len(last)-1])+1)%32]
	if checkRecipientMutation(orig, string(last), noChecksum) == nil {
		t.Error("mutation oracle stayed green on a parser that ignores the bech32 checksum")
	}
	// red: hybrid dispatch broken, a hybrid string handed back as classical
	h, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wrongType := func(spec string) (age.Recipient, error) {
		if strings.HasPrefix(spec, "age1pq1") {
			return x.Recipient(), nil
		}
		return parseRecoveryKeyRecipient(spec)
	}
	if checkRecipientSpecOracles(h.Recipient().String(), wrongType) == nil {
		t.Error("spec oracle stayed green when a hybrid spec yields a classical recipient")
	}
}

func TestRecoveryKeyEncryptOracle_RedGreen(t *testing.T) {
	dir := t.TempDir()
	key := "ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ2-34567-89ABC-DEFGH-JKLMN-PQRST-UV"
	for kind := range uint8(3) {
		fx, err := newRecipientFixture(kind, dir, "# noise", "operator@host")
		if err != nil {
			t.Fatal(err)
		}
		if err := checkEncryptRoundTrip(key, fx, parseRecoveryKeyRecipient, encryptRecoveryKeyForRecipient, 5, 9); err != nil {
			t.Errorf("real implementation, kind %d: %v", kind, err)
		}
		// red: plaintext fallback (the exact failure the rotate command promises not to have)
		plain := func(rawKey string, _ age.Recipient) ([]byte, error) { return []byte(rawKey + "\n"), nil }
		if checkEncryptRoundTrip(key, fx, parseRecoveryKeyRecipient, plain, 5, 9) == nil {
			t.Errorf("kind %d: oracle stayed green on a plaintext fallback", kind)
		}
		// red: encrypted to a different recipient, so the named identity cannot open it
		other, _ := age.GenerateX25519Identity()
		wrongRecipient := func(rawKey string, _ age.Recipient) ([]byte, error) {
			return encryptRecoveryKeyForRecipient(rawKey, other.Recipient())
		}
		if checkEncryptRoundTrip(key, fx, parseRecoveryKeyRecipient, wrongRecipient, 5, 9) == nil {
			t.Errorf("kind %d: oracle stayed green when the key is encrypted to a different recipient", kind)
		}
		// red: the key is altered on the way in
		altered := func(rawKey string, r age.Recipient) ([]byte, error) {
			return encryptRecoveryKeyForRecipient(strings.ToLower(rawKey), r)
		}
		if checkEncryptRoundTrip(key, fx, parseRecoveryKeyRecipient, altered, 5, 9) == nil {
			t.Errorf("kind %d: oracle stayed green when the key is altered before encryption", kind)
		}
		// red: binary (non-armored) output
		binary := func(rawKey string, r age.Recipient) ([]byte, error) {
			var buf bytes.Buffer
			w, err := age.Encrypt(&buf, r)
			if err != nil {
				return nil, err
			}
			_, _ = io.WriteString(w, rawKey)
			_ = w.Close()
			return buf.Bytes(), nil
		}
		if checkEncryptRoundTrip(key, fx, parseRecoveryKeyRecipient, binary, 5, 9) == nil {
			t.Errorf("kind %d: oracle stayed green on non-armored output", kind)
		}
	}
}

func TestRecoveryKeyRecipientFileOracle_RedGreen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.pub")
	ed := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	edPub, _ := ssh.NewPublicKey(ed.Public())
	edLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(edPub)))
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rkPub, _ := ssh.NewPublicKey(&rk.PublicKey)
	rsaLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(rkPub)))

	for _, s := range []string{edLine, edLine + " c\n", "# x\n" + edLine, rsaLine, "garbage", ""} {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := checkRecipientFile([]byte(s), path, parseRecoveryKeyRecipient); err != nil {
			t.Errorf("real parser, content %.30q: %v", s, err)
		}
	}
	// red: the type gate is gone (RSA accepted, as agessh itself would)
	noGate := func(spec string) (age.Recipient, error) {
		data, _ := os.ReadFile(spec)
		pk, _, _, _, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(data))
		if err != nil {
			return nil, err
		}
		return agessh.NewRSARecipient(pk)
	}
	if err := os.WriteFile(path, []byte(rsaLine), 0o600); err != nil {
		t.Fatal(err)
	}
	if checkRecipientFile([]byte(rsaLine), path, noGate) == nil {
		t.Error("file oracle stayed green when an ssh-rsa key is accepted")
	}
	// red: garbage accepted
	acceptAll := func(string) (age.Recipient, error) {
		id, _ := age.GenerateX25519Identity()
		return id.Recipient(), nil
	}
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if checkRecipientFile([]byte("garbage"), path, acceptAll) == nil {
		t.Error("file oracle stayed green when a file with no key is accepted")
	}
}

// TestRecoveryKeyRecipient_Age1PrefixNeverReadsAFile is the executable form of the
// dispatch rule: a spec that starts with "age1" is an age string and is never looked
// up as a path, even if a valid ssh-ed25519 key file of that name exists.
func TestRecoveryKeyRecipient_Age1PrefixNeverReadsAFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	ed := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	edPub, _ := ssh.NewPublicKey(ed.Public())
	line := ssh.MarshalAuthorizedKey(edPub)
	for _, name := range []string{"age1foo.pub", "age1pq1foo.pub"} {
		if err := os.WriteFile(name, line, 0o600); err != nil {
			t.Fatal(err)
		}
		if r, err := parseRecoveryKeyRecipient(name); err == nil {
			t.Errorf("%q was read as a key file and accepted as %T", name, r)
		}
	}
}
