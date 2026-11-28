package secretenv

// FuzzCheckOwnerFailClosed pins the standalone contract of CheckOwner -- the
// owner half of the key-material rule (#3393/#3410) that callers which judge the
// file MODE themselves rely on: --passphrase-file, the DEK/salt and TLS key
// files. For those callers CheckOwner's owner verdict is load-bearing on its own
// (checkInfo's full policy is NOT in the loop), so it is worth pinning
// separately from FuzzCheckInfoNeverAcceptsUnsafe.
//
// The rule (CheckOwner doc): the file must be owned by the running euid or by
// root (uid 0) -- whoever owns a file can chmod and rewrite it, so a foreign
// owner can substitute the key material whatever the mode; and an owner the
// platform cannot report is refused too (fail closed).
//
// ORACLE (fail-closed, one-directional -- cannot false-positive):
//
//	If CheckOwner ACCEPTS (returns nil), then BOTH necessary conditions hold:
//	  - the owner was determinable (fileOwner reported ok), and
//	  - the owner uid is the running euid OR root (uid 0).
//
// Each is a hard requirement from the doc; asserting accept => condition can
// only fire when CheckOwner trusts a file it must refuse (a foreign owner, or an
// owner it could not even read). The reject direction is not asserted.
//
// WHAT THIS DOES NOT VERIFY:
//   - It says nothing about the file MODE (perm bits, setuid/group): CheckOwner
//     deliberately does not look at the mode -- its callers do. Mode policy is
//     the classifier fuzzer's and the permission matrix's job.
//   - It does not check the *ForeignOwnerError TYPE / message on refusal (that it
//     is a ForeignOwnerError naming the uids); the mutation suite covers that.
//   - It drives the owner through the fileOwner/processUID seams, not a real
//     fstat; the "judged on the descriptor that is read" no-swap property is
//     OpenRegular's, tested elsewhere.

import (
	"os"
	"testing"
)

func FuzzCheckOwnerFailClosed(f *testing.F) {
	basePath := f.TempDir() + "/base"
	if err := os.WriteFile(basePath, []byte("x"), 0o600); err != nil {
		f.Fatalf("write base: %v", err)
	}
	base, err := os.Stat(basePath)
	if err != nil {
		f.Fatalf("stat base: %v", err)
	}

	// seeds: (fileUID, procUID, ownerOK)
	f.Add(1000, 1000, true)  // self-owned -> accept
	f.Add(0, 1000, true)     // root-owned -> accept
	f.Add(4242, 1000, true)  // foreign -> refuse
	f.Add(1000, 1000, false) // undeterminable -> refuse

	f.Fuzz(func(t *testing.T, fileUID, procUID int, ownerOK bool) {
		oldUID, oldOwner := processUID, fileOwner
		defer func() { processUID, fileOwner = oldUID, oldOwner }()
		processUID = func() int { return procUID }
		fileOwner = func(os.FileInfo) (int, int, bool) { return fileUID, 0, ownerOK }

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("CheckOwner panicked (uid=%d euid=%d ok=%v): %v", fileUID, procUID, ownerOK, r)
			}
		}()

		if err := CheckOwner(base); err != nil {
			return // a refusal is always safe
		}
		if !ownerOK {
			t.Fatalf("CheckOwner ACCEPTED a file whose owner could not be determined (euid=%d)", procUID)
		}
		if fileUID != procUID && fileUID != 0 {
			t.Fatalf("CheckOwner ACCEPTED a foreign-owned file: uid=%d is neither euid %d nor root", fileUID, procUID)
		}
	})
}
