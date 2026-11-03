package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/integrity"
)

type verityStub struct{ on bool }

func (v verityStub) Enabled(string) (bool, error) { return v.on, nil }

func fakeIntegrityEnv(t *testing.T, best bool) integrity.Env {
	t.Helper()
	root := t.TempDir()
	if best {
		for rel, content := range map[string]string{
			"sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c": "\x07\x00\x00\x00\x01",
			"sys/kernel/security/lockdown":                                             "none [integrity] confidentiality",
			"sys/kernel/security/ima/policy":                                           "appraise func=BPRM_CHECK\n",
		} {
			p := filepath.Join(root, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return integrity.Env{
		Root:           root,
		GOOS:           "linux",
		Executable:     func() (string, error) { return filepath.Join(root, "bin", "keyorix-server"), nil },
		FSVerity:       verityStub{on: best},
		TPM:            integrity.TPMState{Configured: best, BlobPresent: best},
		KeylimePresent: func() (bool, error) { return best, nil },
	}
}

// TestIntegrityPostureNeverChangesTheOutcome: whatever the tier (0 and 6 here),
// the integrity lines add informational text only. runAdminValidatePosture
// turns len(report.deviations) into its non-zero exit and prints warnings
// without counting them; both must stay exactly as they were.
func TestIntegrityPostureNeverChangesTheOutcome(t *testing.T) {
	for _, best := range []bool{false, true} {
		report := &postureReport{}
		report.deviate("seed", "an unrelated deviation") // the exit code must stay driven by this alone
		report.warn("an unrelated warning")
		collectIntegrityPostureWith(fakeIntegrityEnv(t, best), report)
		if len(report.deviations) != 1 || len(report.warnings) != 1 {
			t.Fatalf("best=%v: deviations=%d warnings=%d, want 1 and 1", best, len(report.deviations), len(report.warnings))
		}
		clean := &postureReport{}
		collectIntegrityPostureWith(fakeIntegrityEnv(t, best), clean)
		if len(clean.deviations) != 0 || len(clean.warnings) != 0 {
			t.Fatalf("best=%v: integrity lines produced a deviation or warning (would change the exit code): %+v", best, clean)
		}
		if len(clean.informational) != 8 {
			t.Fatalf("best=%v: %d informational lines, want 8", best, len(clean.informational))
		}
		for _, l := range clean.informational {
			if !strings.Contains(l, integrity.Label) {
				t.Errorf("line lacks the advisory label: %s", l)
			}
		}
		want := "integrity/tier: 0 of 6"
		if best {
			want = "integrity/tier: 6 of 6"
		}
		if !strings.Contains(strings.Join(clean.informational, "\n"), want) {
			t.Errorf("best=%v: no %q line in %v", best, want, clean.informational)
		}
	}
}

func TestIntegrityEnvReadsTPMStateFromConfig(t *testing.T) {
	dir := t.TempDir()
	blob := filepath.Join(dir, "kek.tpm")
	cfg := &config.Config{}
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Encryption.KeyProvider.Type = "tpm"
	cfg.Storage.Encryption.KeyProvider.WrappedKeyPath = blob

	if st := integrityEnv(cfg).TPM; !st.Configured || st.BlobPresent || st.BlobErr != nil {
		t.Fatalf("no blob yet: %+v", st)
	}
	if err := os.WriteFile(blob, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := integrityEnv(cfg).TPM; !st.Configured || !st.BlobPresent {
		t.Fatalf("blob present: %+v", st)
	}
	cfg.Storage.Encryption.KeyProvider.Type = "password"
	if st := integrityEnv(cfg).TPM; st.Configured {
		t.Fatalf("password provider reported as tpm: %+v", st)
	}
}
