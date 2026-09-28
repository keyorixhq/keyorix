// recovery_key_encrypt.go — optional age-encrypted output for
// `admin recovery-key rotate --recipient ...` (F8). Uses filippo.io/age
// (BSD-3-Clause, pure Go, works air-gapped, no GPG dependency -- license
// verified against this repo's dependency allowlist, see
// .github/workflows/ci.yml's `licenses` job and the PR description for
// this change) so the printed key can be delivered pre-encrypted even to
// an operator with no GPG installed.
package admin

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"
)

// parseRecoveryKeyRecipient accepts either a raw age recipient string
// ("age1...") or a path to a file containing a single ssh-ed25519 PUBLIC
// key (the "ssh-ed25519 AAAA... comment" line `ssh-keygen` produces) and
// returns the corresponding age.Recipient. Only ssh-ed25519 is supported --
// other SSH key types (agessh itself also supports ssh-rsa) are refused
// explicitly rather than silently accepted, keeping the supported input
// shape narrow and exactly what's documented.
func parseRecoveryKeyRecipient(spec string) (age.Recipient, error) {
	if strings.HasPrefix(spec, "age1") {
		r, err := age.ParseX25519Recipient(spec)
		if err != nil {
			return nil, fmt.Errorf("invalid age recipient %q: %w", spec, err)
		}
		return r, nil
	}
	data, err := os.ReadFile(spec) // #nosec G304 -- operator-supplied path, same trust level as --config/--passphrase-file
	if err != nil {
		return nil, fmt.Errorf("read recipient public key file %q: %w", spec, err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(data))
	if err != nil {
		return nil, fmt.Errorf("parse %q as an SSH public key: %w", spec, err)
	}
	if pk.Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("recipient key in %q is %q, not ssh-ed25519 (only ssh-ed25519 is supported)", spec, pk.Type())
	}
	r, err := agessh.NewEd25519Recipient(pk)
	if err != nil {
		return nil, fmt.Errorf("build age recipient from %q: %w", spec, err)
	}
	return r, nil
}

// encryptRecoveryKeyForRecipient ASCII-armors rawKey encrypted to recipient
// -- armored (not binary), so the output is always safe to print to a
// terminal or paste into a text file, matching age's own `-a`/`--armor` CLI
// convention. Decrypt with: age -d -i <identity file> <output>.
func encryptRecoveryKeyForRecipient(rawKey string, recipient age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	if _, err := io.WriteString(w, rawKey); err != nil {
		return nil, fmt.Errorf("age encrypt write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("age encrypt close: %w", err)
	}
	if err := aw.Close(); err != nil {
		return nil, fmt.Errorf("age armor close: %w", err)
	}
	return buf.Bytes(), nil
}

// writeRecoveryKeyOutputFile writes data to path with mode 0600, refusing
// to overwrite an existing file (O_EXCL) -- an operator re-running rotate
// with the same --output path by mistake must not silently clobber
// whatever is already there (which could itself be a still-needed prior
// encrypted key).
func writeRecoveryKeyOutputFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-supplied output path
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("output file %q already exists -- refusing to overwrite", path)
		}
		return fmt.Errorf("create output file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write output file %q: %w", path, err)
	}
	return nil
}
