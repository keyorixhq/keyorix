package integrity

import (
	"path/filepath"
	"strings"
	"testing"
)

// manifestEnv builds a host where Secure Boot, lockdown and IMA are ok but
// fs-verity is off, so rung 3 can only be held by the release manifest.
func manifestEnv(t *testing.T, sigName, sigContent string) Env {
	t.Helper()
	const bin = "pretend binary"
	root := fakeRoot(t, map[string]string{
		secureBootVar:                    "\x07\x00\x00\x00\x01",
		"sys/kernel/security/lockdown":   "none [integrity] confidentiality",
		"sys/kernel/security/ima/policy": "appraise func=BPRM_CHECK\n",
		"bin/keyorix-server":             bin,
	})
	exe := filepath.Join(root, "bin", "keyorix-server")
	h, err := hashFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "bin/checksums.txt", h+"  keyorix-server\n")
	if sigName != "" {
		writeFile(t, root, "bin/"+sigName, sigContent)
	}
	env := linuxEnv(root)
	env.Executable = func() (string, error) { return exe, nil }
	return env
}

// A signature file that is empty or garbage verifies nothing: it must not lift
// the tier past rung 3, and the line must say the signature was not verified.
func TestUnverifiedManifestSignatureDoesNotReachRung3(t *testing.T) {
	for _, sig := range []string{"checksums.txt.sig", "checksums.txt.sigstore.json", "checksums.txt.bundle"} {
		for name, content := range map[string]string{"empty": "", "garbage": "not a signature"} {
			t.Run(sig+"/"+name, func(t *testing.T) {
				r := Collect(manifestEnv(t, sig, content))
				if r.Tier >= 3 {
					t.Fatalf("tier = %d (%s): an unverified signature file credited rung 3", r.Tier, r.TierWhy)
				}
				l := lineOf(r, CheckManifest)
				if l.State == StateOK {
					t.Fatalf("manifest line is plain %q although no signature was verified: %s", l.State, l)
				}
				if s := l.String(); !strings.Contains(s, "release-manifest: ok (signature not verified)") {
					t.Fatalf("line must read ok (signature not verified): %s", s)
				}
			})
		}
	}
}

// fs-verity still holds rung 3 on its own, so the manifest change does not
// lower the tier of a host that really has a verified binary identity.
func TestFSVerityStillHoldsRung3WithUnverifiedManifest(t *testing.T) {
	env := manifestEnv(t, "checksums.txt.sig", "")
	env.FSVerity = fakeVerity{on: true}
	if r := Collect(env); r.Tier < 4 {
		t.Fatalf("tier = %d (%s), want >= 4 with fs-verity on", r.Tier, r.TierWhy)
	}
}
