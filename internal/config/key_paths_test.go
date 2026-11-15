package config

// #4249: a relative storage.encryption key-material path is defined against
// Load's config base (the base storage.database.path uses, recorded as
// KeyPathBase). CheckRelativeKeyPathBase refuses one when the process runs
// elsewhere, so a relative key path and the DEK lock beside it mean one place
// for every process. Load never rewrites the values (backup archives record the
// configured key paths) and never refuses on its own.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeKeyPathConfig(t *testing.T, dir, encryption string) string {
	t.Helper()
	p := filepath.Join(dir, "keyorix.yaml")
	if err := os.WriteFile(p, []byte("storage:\n  encryption:\n"+encryption), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// loadKeyPaths loads cfgPath with the process running in cwd.
func loadKeyPaths(t *testing.T, cwd, cfgPath string) *EncryptionConfig {
	t.Helper()
	t.Chdir(cwd)
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return &cfg.Storage.Encryption
}

const relativeKeys = "    enabled: true\n    dek_path: keys/dek.key\n    salt_path: keys/kek.salt\n"

func TestCheckRelativeKeyPathBase_FromAnotherCwd_Refused(t *testing.T) {
	cfgDir := t.TempDir()
	enc := loadKeyPaths(t, t.TempDir(), writeKeyPathConfig(t, cfgDir, relativeKeys))
	if enc.DEKPath != "keys/dek.key" || enc.SaltPath != "keys/kek.salt" {
		t.Fatalf("Load rewrote the key paths: %q %q", enc.DEKPath, enc.SaltPath)
	}
	err := enc.CheckRelativeKeyPathBase(".")
	if err == nil {
		t.Fatal("relative key paths from a cwd that is not the config's directory must be refused")
	}
	for _, want := range []string{"storage.encryption.dek_path", `"keys/dek.key"`, cfgDir, "absolute paths",
		filepath.Join(cfgDir, "keys/dek.key"), "#4249"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not contain %q", err, want)
		}
	}
}

// Every key-material key is covered, not only dek_path: a relative provider
// path alone is refused too, and named.
func TestCheckRelativeKeyPathBase_RelativeProviderPath_Refused(t *testing.T) {
	keyDir := t.TempDir()
	for _, tc := range []struct{ name, yaml, key string }{
		{"wrapped", "      type: aws-kms\n      wrapped_key_path: kek.wrapped\n", "storage.encryption.key_provider.wrapped_key_path"},
		{"file", "      type: file\n      file_path: kek.hex\n", "storage.encryption.key_provider.file_path"},
		{"fallback shamir", "      type: password\n      fallbacks:\n        - type: shamir\n          shamir_share_files: [" +
			filepath.Join(keyDir, "a") + ", b]\n", "storage.encryption.key_provider.fallbacks[0].shamir_share_files[1]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := writeKeyPathConfig(t, t.TempDir(), "    enabled: true\n    dek_path: "+filepath.Join(keyDir, "dek.key")+
				"\n    salt_path: "+filepath.Join(keyDir, "kek.salt")+"\n    key_provider:\n"+tc.yaml)
			err := loadKeyPaths(t, t.TempDir(), cfgPath).CheckRelativeKeyPathBase(".")
			if err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("CheckRelativeKeyPathBase = %v, want a refusal naming %s", err, tc.key)
			}
		})
	}
}

// From the config's own directory (by an absolute or a relative config path,
// or through a symlink to it) relative key paths are accepted.
func TestCheckRelativeKeyPathBase_FromConfigDir_Accepted(t *testing.T) {
	cfgDir := t.TempDir()
	cfgPath := writeKeyPathConfig(t, cfgDir, relativeKeys)
	link := filepath.Join(t.TempDir(), "data")
	if err := os.Symlink(cfgDir, link); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ cwd, path string }{
		"absolute config path":         {cfgDir, cfgPath},
		"relative config path":         {cfgDir, "keyorix.yaml"},
		"cwd is a symlink to the dir":  {link, cfgPath},
		"relative path through a link": {link, "keyorix.yaml"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := loadKeyPaths(t, tc.cwd, tc.path).CheckRelativeKeyPathBase("."); err != nil {
				t.Fatalf("CheckRelativeKeyPathBase: %v", err)
			}
		})
	}
}

func TestCheckRelativeKeyPathBase_AbsoluteKeyPaths_AcceptedFromAnyCwd(t *testing.T) {
	keyDir := t.TempDir()
	cfgPath := writeKeyPathConfig(t, t.TempDir(), "    enabled: true\n    dek_path: "+filepath.Join(keyDir, "data.key")+
		"\n    salt_path: "+filepath.Join(keyDir, "kek.salt")+"\n")
	if err := loadKeyPaths(t, t.TempDir(), cfgPath).CheckRelativeKeyPathBase("."); err != nil {
		t.Fatalf("absolute key paths must be accepted from any cwd: %v", err)
	}
}

// With encryption disabled the key paths are not used: no refusal.
func TestCheckRelativeKeyPathBase_EncryptionDisabled_NotJudged(t *testing.T) {
	cfgPath := writeKeyPathConfig(t, t.TempDir(), "    enabled: false\n    dek_path: keys/dek.key\n    salt_path: keys/kek.salt\n")
	if err := loadKeyPaths(t, t.TempDir(), cfgPath).CheckRelativeKeyPathBase("."); err != nil {
		t.Fatalf("CheckRelativeKeyPathBase with encryption disabled: %v", err)
	}
}

// A config built in code (no Load, so no KeyPathBase) is not judged.
func TestCheckRelativeKeyPathBase_ConfigNotFromLoad_NotJudged(t *testing.T) {
	enc := &EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"}
	t.Chdir(t.TempDir())
	if err := enc.CheckRelativeKeyPathBase("."); err != nil {
		t.Fatalf("CheckRelativeKeyPathBase on a config without KeyPathBase: %v", err)
	}
}

// The base a caller opens key files against decides whether it is judged: the
// working directory however it is spelled ("." or os.Getwd(), as
// `admin encryption status` passes) is; another directory the caller chose
// (backup's staging directory, a test's) is not.
func TestCheckRelativeKeyPathBase_OpenBase(t *testing.T) {
	cwd := t.TempDir()
	enc := loadKeyPaths(t, cwd, writeKeyPathConfig(t, t.TempDir(), relativeKeys))
	abs, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, base := range []string{".", abs, cwd} {
		if err := enc.CheckRelativeKeyPathBase(base); err == nil || !strings.Contains(err.Error(), "#4249") {
			t.Errorf("CheckRelativeKeyPathBase(%q) = %v, want the refusal: %q is the working directory", base, err, base)
		}
	}
	if err := enc.CheckRelativeKeyPathBase(t.TempDir()); err != nil {
		t.Errorf("an explicit base directory other than the cwd is the caller's choice, not judged: %v", err)
	}
}
