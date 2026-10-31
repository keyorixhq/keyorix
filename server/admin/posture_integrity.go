package admin

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/integrity"
)

// collectIntegrityPosture adds the RD-INTEG-POSTURE-1 / RD-TIER-POSTURE-1
// lines. They are INFORMATIONAL ONLY, by construction: this function calls
// report.info and nothing else, so it can neither add a deviation nor a warning
// and therefore cannot change the command's exit code
// (TestIntegrityPostureNeverChangesTheOutcome). Every line is labelled
// "advisory (self-reported)": a process cannot prove its own host's integrity;
// TPM attestation (ADR-117/119) is the proof. See docs/security/integrity-posture.md.
func collectIntegrityPosture(cfg *config.Config, report *postureReport) {
	collectIntegrityPostureWith(integrityEnvFor(cfg), report)
}

// integrityEnvFor is a seam for golden tests, whose recorded output must not
// depend on the host that runs them.
var integrityEnvFor = integrityEnv

func collectIntegrityPostureWith(env integrity.Env, report *postureReport) {
	for _, line := range integrity.Collect(env).Strings() {
		report.info(line)
	}
}

// integrityEnv reads the TPM key provider's configured state (type and sealed
// blob) without touching the provider or the TPM device.
func integrityEnv(cfg *config.Config) integrity.Env {
	kp := cfg.Storage.Encryption.KeyProvider
	tpm := integrity.TPMState{Configured: cfg.Storage.Encryption.Enabled && kp.Type == "tpm"}
	if tpm.Configured && kp.WrappedKeyPath != "" {
		p := kp.WrappedKeyPath
		if !filepath.IsAbs(p) {
			p = filepath.Join(".", p) // the same base the key-file-set check uses
		}
		switch _, err := os.Stat(p); {
		case err == nil:
			tpm.BlobPresent = true
		case !errors.Is(err, fs.ErrNotExist):
			tpm.BlobErr = err
		}
	}
	return integrity.Env{TPM: tpm}
}
