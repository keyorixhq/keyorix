package integrity

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func defaultExecutable() (string, error) { return os.Executable() }

// secureBootVar is the SecureBoot EFI variable (EFI_GLOBAL_VARIABLE guid).
const secureBootVar = "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

func readUnder(root, rel string) ([]byte, error) {
	return os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- rel is a constant, root is the injectable fake-tree root
}

func unreadable(id, what string, err error) Line {
	return Line{ID: id, State: StateUnknown, Detail: fmt.Sprintf("%s could not be read (%v); treated as unknown, never ok", what, err)}
}

// checkSecureBoot reads the SecureBoot EFI variable: 4 attribute bytes, then
// one data byte (1 = enabled).
func checkSecureBoot(e Env) Line {
	if !e.linux() {
		return notApplicable(CheckSecureBoot, "efivars")
	}
	b, err := readUnder(e.Root, secureBootVar)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Line{ID: CheckSecureBoot, State: StateUnknown, Detail: "no SecureBoot EFI variable visible (legacy BIOS boot, no efivarfs, or a container without /sys/firmware); cannot tell whether Secure Boot is on"}
	case err != nil:
		return unreadable(CheckSecureBoot, "the SecureBoot EFI variable", err)
	case len(b) < 5:
		return Line{ID: CheckSecureBoot, State: StateUnknown, Detail: fmt.Sprintf("the SecureBoot EFI variable has %d bytes, expected 5; treated as unknown", len(b))}
	}
	switch b[4] {
	case 1:
		return Line{ID: CheckSecureBoot, State: StateOK, Detail: "firmware reports Secure Boot enabled"}
	case 0:
		return Line{ID: CheckSecureBoot, State: StateDegraded, Detail: "firmware reports Secure Boot disabled"}
	default:
		return Line{ID: CheckSecureBoot, State: StateUnknown, Detail: fmt.Sprintf("the SecureBoot EFI variable holds %d, expected 0 or 1; treated as unknown", b[4])}
	}
}

// checkLockdown parses /sys/kernel/security/lockdown, e.g.
// "none [integrity] confidentiality": the bracketed word is the active mode.
func checkLockdown(e Env) Line {
	if !e.linux() {
		return notApplicable(CheckLockdown, "kernel lockdown")
	}
	b, err := readUnder(e.Root, "sys/kernel/security/lockdown")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Line{ID: CheckLockdown, State: StateUnknown, Detail: "/sys/kernel/security/lockdown is absent (kernel without the lockdown LSM, or securityfs not visible); cannot tell"}
	case err != nil:
		return unreadable(CheckLockdown, "/sys/kernel/security/lockdown", err)
	}
	mode := ""
	for f := range strings.FieldsSeq(string(b)) {
		if strings.HasPrefix(f, "[") && strings.HasSuffix(f, "]") {
			mode = strings.Trim(f, "[]")
		}
	}
	switch mode {
	case "integrity", "confidentiality":
		return Line{ID: CheckLockdown, State: StateOK, Detail: "kernel lockdown mode is " + mode}
	case "none":
		return Line{ID: CheckLockdown, State: StateDegraded, Detail: "kernel lockdown mode is none"}
	default:
		return Line{ID: CheckLockdown, State: StateUnknown, Detail: fmt.Sprintf("no active lockdown mode found in %q; treated as unknown", strings.TrimSpace(string(b)))}
	}
}

// checkIMA reads the loaded IMA policy. "appraise" rules mean files are
// verified against signatures/hashes before use; a policy with only measure
// rules records but does not enforce.
func checkIMA(e Env) Line {
	if !e.linux() {
		return notApplicable(CheckIMA, "IMA")
	}
	b, err := readUnder(e.Root, "sys/kernel/security/ima/policy")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Line{ID: CheckIMA, State: StateUnknown, Detail: "/sys/kernel/security/ima/policy is absent (kernel without IMA, or securityfs not visible); cannot tell"}
	case err != nil:
		return unreadable(CheckIMA, "the IMA policy (usually root-only)", err)
	}
	var appraise, measure int
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "appraise"):
			appraise++
		case strings.HasPrefix(line, "measure"):
			measure++
		}
	}
	switch {
	case appraise > 0:
		return Line{ID: CheckIMA, State: StateOK, Detail: fmt.Sprintf("IMA policy loaded with %d appraise rule(s) (enforcement depends on the ima_appraise boot mode, which this check does not read)", appraise)}
	case measure > 0:
		return Line{ID: CheckIMA, State: StateDegraded, Detail: fmt.Sprintf("IMA policy has %d measure rule(s) and no appraise rule: files are recorded, not verified", measure)}
	default:
		return Line{ID: CheckIMA, State: StateDegraded, Detail: "IMA policy is empty"}
	}
}

// checkFSVerity asks whether fs-verity is enabled on the running binary.
func checkFSVerity(e Env) Line {
	if !e.linux() {
		return notApplicable(CheckFSVerity, "fs-verity")
	}
	exe, err := e.Executable()
	if err != nil {
		return unreadable(CheckFSVerity, "the running binary's path", err)
	}
	on, err := e.FSVerity.Enabled(exe)
	switch {
	case err != nil:
		return unreadable(CheckFSVerity, "the fs-verity flag of "+exe, err)
	case on:
		return Line{ID: CheckFSVerity, State: StateOK, Detail: "fs-verity is enabled on the running binary " + exe}
	default:
		return Line{ID: CheckFSVerity, State: StateDegraded, Detail: "fs-verity is not enabled on the running binary " + exe}
	}
}

// manifestName and manifestSigs: the release ships checksums.txt with a
// cosign signature (RELEASING.md). Only a manifest with a signature file next
// to it is compared, and even then the result is only "ok (signature not
// verified)": it never counts toward a tier rung.
const manifestName = "checksums.txt"

var manifestSigs = []string{"checksums.txt.sig", "checksums.txt.sigstore.json", "checksums.txt.bundle"}

// checkManifest compares the running binary's SHA-256 with a release manifest
// ONLY if one is already on disk next to the binary. No network. The
// signature is NOT verified here (that needs cosign, scripts/release/
// verify-release.sh): the line says so.
func checkManifest(e Env) Line {
	exe, err := e.Executable()
	if err != nil {
		return unreadable(CheckManifest, "the running binary's path", err)
	}
	dir := filepath.Dir(exe)
	sigFile := ""
	for _, s := range manifestSigs {
		if _, err := os.Stat(filepath.Join(dir, s)); err == nil {
			sigFile = s
			break
		}
	}
	mpath := filepath.Join(dir, manifestName)
	f, err := os.Open(mpath) // #nosec G304 -- next to the running binary, read-only
	if errors.Is(err, fs.ErrNotExist) {
		return Line{ID: CheckManifest, State: StateNotChecked, Detail: "no release manifest (" + manifestName + ") next to the binary; nothing to compare, nothing fetched"}
	}
	if err != nil {
		return unreadable(CheckManifest, mpath, err)
	}
	defer func() { _ = f.Close() }()
	if sigFile == "" {
		return Line{ID: CheckManifest, State: StateNotChecked, Detail: mpath + " has no signature file next to it; an unsigned manifest is ignored"}
	}
	sum, err := hashFile(exe)
	if err != nil {
		return unreadable(CheckManifest, "the running binary for hashing", err)
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && strings.EqualFold(fields[0], sum) {
			// Never StateOK: the signature file is not verified here, so the match
			// proves nothing about the binary and must not count toward a tier rung.
			return Line{ID: CheckManifest, State: StateOKQualified, Qualifier: "signature not verified", Detail: fmt.Sprintf("binary SHA-256 matches %q in %s; the signature file %s is present but NOT verified by this check, so this does not count toward the tier (run scripts/release/verify-release.sh)", strings.TrimPrefix(fields[1], "*"), manifestName, sigFile)}
		}
	}
	if err := sc.Err(); err != nil {
		return unreadable(CheckManifest, mpath, err)
	}
	return Line{ID: CheckManifest, State: StateDegraded, Detail: fmt.Sprintf("binary SHA-256 %s… is not listed in %s (locally built, modified, or a different release)", sum[:12], manifestName)}
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- the running binary
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// checkTPM reports the TPM provider's sealing state from configuration. It
// does not talk to the TPM (that is the provider's job and is not touched).
func checkTPM(e Env) Line {
	t := e.TPM
	switch {
	case !t.Configured:
		return Line{ID: CheckTPMSealing, State: StateDegraded, Detail: "the KEK is not sealed to a TPM (key_provider.type is not tpm)"}
	case t.BlobErr != nil:
		return unreadable(CheckTPMSealing, "the TPM-sealed KEK blob", t.BlobErr)
	case !t.BlobPresent:
		return Line{ID: CheckTPMSealing, State: StateDegraded, Detail: "key_provider.type is tpm but no sealed KEK blob exists yet"}
	default:
		return Line{ID: CheckTPMSealing, State: StateOK, Detail: "key_provider.type is tpm and a sealed KEK blob exists. The seal binds the KEK to this TPM chip, not to a verified boot state (no PCR policy)"}
	}
}

// checkKeylime reports whether a Keylime agent process is present. Presence is
// not attestation: whether a verifier accepts this host is not visible here.
func checkKeylime(e Env) Line {
	if !e.linux() {
		return notApplicable(CheckKeylime, "the Keylime agent check")
	}
	present, err := e.KeylimePresent()
	switch {
	case err != nil:
		return unreadable(CheckKeylime, "the process list", err)
	case present:
		return Line{ID: CheckKeylime, State: StateOK, Detail: "a keylime_agent process is running. That is presence only: whether a verifier currently accepts this host is not visible from here"}
	default:
		return Line{ID: CheckKeylime, State: StateDegraded, Detail: "no keylime_agent process found"}
	}
}

// keylimeInProc scans <root>/proc/<pid>/comm for the agent's process name.
func keylimeInProc(root string) (bool, error) {
	entries, err := os.ReadDir(filepath.Join(root, "proc"))
	if err != nil {
		return false, err
	}
	for _, en := range entries {
		if !en.IsDir() || !isDigits(en.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, "proc", en.Name(), "comm")) // #nosec G304 -- pid dir under the injectable root
		if err != nil {
			continue // a process that exited or is hidden: skip, the scan goes on
		}
		if strings.TrimSpace(string(b)) == "keylime_agent" {
			return true, nil
		}
	}
	return false, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
