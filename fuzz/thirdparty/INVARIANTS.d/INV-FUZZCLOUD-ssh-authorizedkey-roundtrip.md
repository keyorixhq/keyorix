- **INV-FUZZCLOUD-ssh-authorizedkey-roundtrip** `golang.org/x/crypto/ssh`
  authorized-key parsing is a stable fixed point as `server/admin/
  recovery_key_encrypt.go` uses it: if `ParseAuthorizedKey` accepts input and
  yields a key, then `MarshalAuthorizedKey` of that key re-parses to a key with
  the same wire form (`Marshal()`) and same `Type()`; arbitrary bytes never
  panic. A parse/marshal pair that round-trips to a *different* recipient would
  let two representations of one key diverge. Does NOT check key-acceptance
  policy / weak-key rejection (recovery_key_encrypt.go layers its own), nor
  round-trip of the comment/options. Why: reachgen flagged
  `ssh.ParseAuthorizedKey` as an uncovered untrusted-input parser on the admin
  recovery-key path. Guard: `FuzzSSHParseAuthorizedKey`
  (`fuzz/thirdparty/ssh/ssh_authorizedkey_fuzz_test.go`), red-proofed by
  corrupting the marshaled bytes before re-parse.
