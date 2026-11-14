// Reachability-first fuzz harness for golang.org/x/crypto/ssh authorized-key
// parsing, the path Keyorix uses to accept an admin-supplied recovery-key
// recipient.
//
// Live caller (traced from reachgen, prov=request-body):
//   - server/admin/recovery_key_encrypt.go:53 parseRecoveryKeyRecipient
//       -> ssh.ParseAuthorizedKey(raw)
//   `raw` is an authorized_keys line submitted by an administrator; it is
//   attacker-influenced input to a parser.
//
// Oracle (sound round-trip stability): if ParseAuthorizedKey accepts input and
// yields a key, then serializing that key with MarshalAuthorizedKey and parsing
// the result again must:
//   - succeed, and
//   - produce a key with the SAME wire form (Marshal()) and SAME Type().
// i.e. parse∘marshal∘parse is a stable fixed point. A parser/serializer pair
// that round-trips to a DIFFERENT key (or fails to re-parse its own output)
// would let two representations of "the same" recipient diverge. Plus: no
// panic on arbitrary bytes.
//
// What this oracle does NOT verify:
//   - NOT that ParseAuthorizedKey REJECTS keys it should (no key-policy /
//     weak-key / algorithm-allowlist check — recovery_key_encrypt.go layers its
//     own checks on top, untested here).
//   - NOT round-trip of the comment or options (ParseAuthorizedKey returns them
//     separately; only the key is checked).
//   - NOT that the key is usable for encryption downstream.
//   - NOT the "invalid lines are ignored" scanning behaviour across multi-line
//     input beyond the first accepted key.
package sshhostile

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/ssh"
)

func FuzzSSHParseAuthorizedKey(f *testing.F) {
	// A couple of structurally-valid-ish seeds (truncated, so parsing fails
	// cleanly) plus junk; real keys are large, the fuzzer will explore.
	// A genuinely valid ed25519 authorized_keys line so the round-trip body is
	// actually exercised (truncated keys below just test clean rejection).
	f.Add([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMCNPj70vRk7BvDxM2cSOWZ0f1ayczW+5stLTUgYD7D5 admin@keyorix"))
	f.Add([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 comment"))
	f.Add([]byte("ssh-rsa AAAAB3NzaC1yc2E"))
	f.Add([]byte(""))
	f.Add([]byte("# just a comment line\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil || pub == nil {
			return // rejected input: nothing to round-trip, and no panic occurred
		}
		marshaled := marshalKey(pub)
		pub2, _, _, _, err2 := ssh.ParseAuthorizedKey(marshaled)
		if err2 != nil || pub2 == nil {
			t.Fatalf("round-trip: MarshalAuthorizedKey output of a %s key did not re-parse: %v", pub.Type(), err2)
		}
		if pub.Type() != pub2.Type() {
			t.Fatalf("round-trip: key type changed %q -> %q", pub.Type(), pub2.Type())
		}
		if !bytes.Equal(pub.Marshal(), pub2.Marshal()) {
			t.Fatalf("round-trip: wire form changed for a %s key", pub.Type())
		}
	})
}

// marshalKey is factored out so the red-proof can plant a defect here in a
// scratch copy (e.g. flip a byte of the marshaled output) and watch the
// round-trip assertion fire while the unmodified path stays green.
func marshalKey(pub ssh.PublicKey) []byte {
	return ssh.MarshalAuthorizedKey(pub)
}
