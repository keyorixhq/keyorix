package admin

import (
	"bytes"

	"github.com/keyorixhq/keyorix/internal/crypto"
)

// masterPassphrase yields the master passphrase for one unlock (password key
// provider only, so it is called lazily); the caller wipes the result.
type masterPassphrase func() ([]byte, error)

func passphraseFrom(src crypto.PassphraseSource) masterPassphrase {
	return func() ([]byte, error) { return crypto.ResolvePassphrase(src, "KEYORIX_MASTER_PASSWORD") }
}

// passphraseOnce reads its source at most once and hands every later caller a
// copy. A piped --passphrase-stdin is at EOF after the first read and
// --passphrase-fd is closed by it (its number may already belong to another
// file by the second read), so one command that unlocks more than once must
// not go back to the source (REVIEW-3807-DEEP-2).
type passphraseOnce struct {
	src  crypto.PassphraseSource
	b    []byte
	err  error
	read bool
}

func (p *passphraseOnce) resolve() ([]byte, error) {
	if !p.read {
		p.b, p.err = crypto.ResolvePassphrase(p.src, "KEYORIX_MASTER_PASSWORD")
		p.read = true
	}
	if p.err != nil {
		return nil, p.err
	}
	return bytes.Clone(p.b), nil
}

// wipe zeroes the held copy; a later resolve reads the source again.
func (p *passphraseOnce) wipe() {
	crypto.WipeBytes(p.b)
	*p = passphraseOnce{src: p.src}
}

// restorePassphrase is the passphrase of the current `admin restore` run:
// the manifest-key unwrap, the notification-URL backfill and the automatic
// verify-audit all unlock with it. runAdminRestore binds it to the flags and
// wipes it when the run ends.
var restorePassphrase = &passphraseOnce{}
