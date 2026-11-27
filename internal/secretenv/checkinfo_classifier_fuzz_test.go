package secretenv

// FuzzCheckInfoNeverAcceptsUnsafe explores the whole mode-bit + owner/group
// identity space of checkInfo -- the key-material permission classifier behind
// LookupChecked, CheckPermissions, CheckInfo and CheckOwner. checkInfo decides
// whether a secret/key file (KEK, master password, Shamir share, admin creds)
// is safe to trust given its fstat'd mode and owner; its inputs come from the
// filesystem a (possibly attacker-influenced) orchestrator mounts, so this is a
// trust boundary.
//
// It complements TestPermissionMatrix_Server (a fixed reference table) by
// exercising arbitrary mode bits -- every combination of setuid/setgid/sticky,
// the full perm range, and arbitrary owner/group identity -- rather than the
// table's hand-picked rows.
//
// ORACLE (fail-closed, one-directional -- cannot false-positive):
//
//	If checkInfo ACCEPTS (returns nil), then EVERY individually-necessary safety
//	condition the package doc states as "always refused" must hold:
//	  - no setuid/setgid/sticky bit
//	  - no access for "other" (perm & 0o007 == 0)
//	  - no group-write (perm & 0o020 == 0)
//	  - the owner is determinable, and is the running euid or root (uid 0)
//	  - if the file is group-readable/executable (perm & 0o050 != 0): it is NOT
//	    owned by the running user (so it is root-owned, per the rule above) AND
//	    its group is one the process holds.
//
// Each clause is a hard requirement checkInfo's own code structurally enforces,
// so asserting accept => clause can only fire on a genuine over-acceptance; it
// never fires on a merely-over-strict rejection. The reject direction is NOT
// asserted (an over-strict refusal is safe, and asserting it would need a full
// reference parser that could itself be wrong -- a false-positive risk).
//
// WHAT THIS DOES NOT VERIFY:
//   - It does not drive the real filesystem: the mode and owner come through the
//     fileOwner/processUID/processGroups seams and a fakeModeInfo, not a real
//     fstat. OpenRegular's regular-file gate, the O_NONBLOCK open and the
//     no-swap-window property are out of scope here (they have their own tests).
//   - It says nothing about the error TEXT on refusal (that it names the reason,
//     omits the secret) -- covered by TestCheckInfo_RefusesSpecialBitsGroupWriteAndOther
//     and the describe/leak tests.
//   - It does not assert the reject direction, so it cannot catch a regression
//     that makes checkInfo refuse a legitimately-safe file (a correctness, not a
//     security, concern).

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzCheckInfoNeverAcceptsUnsafe(f *testing.F) {
	// A real base FileInfo, stat'd once; only its non-Mode methods are used
	// (fakeModeInfo overrides Mode, and fileOwner is seamed below).
	basePath := filepath.Join(f.TempDir(), "base")
	if err := os.WriteFile(basePath, []byte("x\n"), 0o600); err != nil {
		f.Fatalf("write base: %v", err)
	}
	base, err := os.Stat(basePath)
	if err != nil {
		f.Fatalf("stat base: %v", err)
	}

	// Seeds: a safe 0600 self-owned file, a root-owned group-readable mount, and
	// several shapes that must be refused.
	f.Add(uint32(0o600), 1000, 1000, 1000, true, true)                       // safe, self-owned
	f.Add(uint32(0o640), 0, 5555, 1000, true, true)                          // safe k8s/fsGroup mount
	f.Add(uint32(0o644), 0, 5555, 1000, true, true)                          // other-readable -> refuse
	f.Add(uint32(0o600)|uint32(os.ModeSetuid), 1000, 1000, 1000, true, true) // setuid -> refuse
	f.Add(uint32(0o620), 1000, 1000, 1000, true, true)                       // group-write -> refuse
	f.Add(uint32(0o640), 4242, 5555, 1000, true, true)                       // foreign owner -> refuse
	f.Add(uint32(0o640), 0, 5555, 1000, true, false)                         // group not held -> refuse
	f.Add(uint32(0o600), 1000, 1000, 1000, false, true)                      // owner undeterminable -> refuse

	f.Fuzz(func(t *testing.T, modeBits uint32, fileUID, fileGID, procUID int, ownerOK, groupHeld bool) {
		mode := os.FileMode(modeBits)
		perm := mode.Perm()

		// processGroups reports exactly one gid: the file's gid when groupHeld,
		// otherwise a gid guaranteed distinct from it.
		heldGID := fileGID
		if !groupHeld {
			heldGID = fileGID ^ 0x4000 // flips a high bit -> never equal to fileGID
		}

		oldUID, oldGroups, oldOwner := processUID, processGroups, fileOwner
		defer func() { processUID, processGroups, fileOwner = oldUID, oldGroups, oldOwner }()
		processUID = func() int { return procUID }
		processGroups = func() []int { return []int{heldGID} }
		fileOwner = func(os.FileInfo) (int, int, bool) { return fileUID, fileGID, ownerOK }

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("checkInfo panicked (mode=%#o uid=%d gid=%d euid=%d ok=%v held=%v): %v",
					modeBits, fileUID, fileGID, procUID, ownerOK, groupHeld, r)
			}
		}()

		if err := checkInfo(fakeModeInfo{FileInfo: base, mode: mode}); err != nil {
			return // a refusal is always safe; this oracle asserts nothing about it
		}

		// Accepted -> every necessary condition must hold.
		fail := func(why string) {
			t.Fatalf("checkInfo ACCEPTED an unsafe file (%s): mode=%#o perm=%#o uid=%d gid=%d euid=%d ownerOK=%v groupHeld=%v",
				why, modeBits, uint32(perm), fileUID, fileGID, procUID, ownerOK, groupHeld)
		}
		if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			fail("setuid/setgid/sticky bit set")
		}
		if perm&0o007 != 0 {
			fail("accessible to other users")
		}
		if perm&0o020 != 0 {
			fail("group-writable")
		}
		if !ownerOK {
			fail("owner was undeterminable")
		}
		if fileUID != procUID && fileUID != 0 {
			fail("owner is neither the running user nor root")
		}
		if perm&0o050 != 0 {
			if fileUID == procUID {
				fail("group-readable/executable but owned by the running user")
			}
			if !groupHeld {
				fail("group-readable/executable by a group the process does not hold")
			}
		}
	})
}
