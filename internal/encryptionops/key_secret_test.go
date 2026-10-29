// key_secret_test.go — `admin encryption key-secret` (HA-SECRET-KEYS-1): the
// Secret manifest a Secret-mode install mounts read-only, what generate, export
// and unpack refuse, and the rotation commands run in an unpacked workspace.
package encryptionops

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"gopkg.in/yaml.v3"
)

// parsedKeySecret is the subset of a Secret manifest the tests check.
type parsedKeySecret struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Type       string `yaml:"type"`
	Immutable  bool   `yaml:"immutable"`
	Metadata   struct {
		Name        string            `yaml:"name"`
		Namespace   string            `yaml:"namespace"`
		Labels      map[string]string `yaml:"labels"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Data map[string]string `yaml:"data"`
}

func readKeySecretManifest(t *testing.T, path string) (parsedKeySecret, []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var s parsedKeySecret
	if err := yaml.Unmarshal(raw, &s); err != nil {
		t.Fatalf("manifest %s does not parse: %v", path, err)
	}
	return s, raw
}

func (s parsedKeySecret) file(t *testing.T, key string) []byte {
	t.Helper()
	v, ok := s.Data[key]
	if !ok {
		t.Fatalf("Secret has no %q key (has %v)", key, s.Data)
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("data %q: %v", key, err)
	}
	return b
}

// chartConfig is testConfig with the Helm chart's key file names.
func chartConfig() *config.Config {
	cfg := testConfig(true)
	cfg.Storage.Encryption.DEKPath = "data.key"
	return cfg
}

func fileOpts(out string) KeySecretOpts {
	return KeySecretOpts{Name: "keyorix-keys-1", Namespace: "keyorix", Out: out}
}

// openedFingerprint opens the key set in dir (data.key, kek.salt) with
// passphrase and returns its DEK fingerprint.
func openedFingerprint(t *testing.T, dir, passphrase string) (string, error) {
	t.Helper()
	svc, err := InitLocalKeyOpService(chartConfig(), dir, passphrase, false)
	if err != nil {
		return "", err
	}
	defer svc.Shutdown()
	return svc.DEKFingerprint()
}

// generate writes a fresh key set's manifest to <cwd>/name and returns it parsed.
func generate(t *testing.T, name string) parsedKeySecret {
	t.Helper()
	var msg bytes.Buffer
	if err := GenerateKeySecret(chartConfig(), fileOpts(name), zeroPassSrc(), &msg); err != nil {
		t.Fatalf("GenerateKeySecret: %v (%s)", err, msg.String())
	}
	s, _ := readKeySecretManifest(t, name)
	return s
}

// TestKeySecret_GenerateThenUnpack_OpensWithTheSamePassphrase is the first
// install: a new key set straight into a manifest (nothing left on disk but the
// manifest), unpacked into the files a Secret-mode pod sees, which open with the
// master passphrase and carry the fingerprint the manifest names.
func TestKeySecret_GenerateThenUnpack_OpensWithTheSamePassphrase(t *testing.T) {
	cwd := chdirTemp(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	setPassphraseEnv(t, testBaselinePassphrase)

	cfg := testConfig(true)
	// Absolute key paths, as in the Helm chart: generate must not create them.
	live := filepath.Join(t.TempDir(), "app", "keys")
	cfg.Storage.Encryption.DEKPath = filepath.Join(live, "data.key")
	cfg.Storage.Encryption.SaltPath = filepath.Join(live, "kek.salt")
	cfg.Storage.Encryption.KeyDirLock = config.KeyDirLockDatabase
	var msg bytes.Buffer
	if err := GenerateKeySecret(cfg, fileOpts("keys.yaml"), zeroPassSrc(), &msg); err != nil {
		t.Fatalf("GenerateKeySecret: %v", err)
	}
	if _, err := os.Stat(live); !os.IsNotExist(err) {
		t.Fatalf("generate touched the configured key directory %s: %v", live, err)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("generate left %d entries in the temporary directory, want none", len(left))
	}
	if m := fileMode(t, "keys.yaml"); m != 0o600 {
		t.Fatalf("manifest mode %o, want 600", m)
	}

	s, raw := readKeySecretManifest(t, "keys.yaml")
	if s.APIVersion != "v1" || s.Kind != "Secret" || s.Type != "Opaque" || !s.Immutable {
		t.Fatalf("not an immutable v1 Opaque Secret: %+v", s)
	}
	if s.Metadata.Name != "keyorix-keys-1" || s.Metadata.Namespace != "keyorix" || s.Metadata.Labels["keyorix.io/key-set"] != "true" {
		t.Fatalf("metadata: %+v", s.Metadata)
	}
	// The generated set carries the key-set manifest its first boot wrote
	// (#2900), so a read-only Secret mount is checked for a mixed generation.
	if len(s.Data) != 3 || s.Data["data.key"] == "" || s.Data["kek.salt"] == "" || s.Data[KeySetManifestName] == "" {
		t.Fatalf("Secret keys %v, want exactly data.key, kek.salt and %s", s.Data, KeySetManifestName)
	}
	if len(s.file(t, "kek.salt")) != 32 {
		t.Fatalf("kek.salt is %d bytes, want 32", len(s.file(t, "kek.salt")))
	}
	if bytes.Contains(raw, []byte(testBaselinePassphrase)) || strings.Contains(msg.String(), testBaselinePassphrase) {
		t.Fatal("the manifest or the messages contain the master passphrase")
	}
	if strings.Contains(msg.String(), s.Data["data.key"]) {
		t.Fatal("the messages contain the wrapped DEK")
	}

	if err := UnpackKeySecret("keys.yaml", "pod-keys", nil, &msg); err != nil {
		t.Fatalf("UnpackKeySecret: %v", err)
	}
	for _, f := range []string{"data.key", "kek.salt"} {
		if m := fileMode(t, filepath.Join(cwd, "pod-keys", f)); m != 0o600 {
			t.Fatalf("%s mode %o, want 600", f, m)
		}
	}
	m, err := keyfiles.LoadManifest(filepath.Join(cwd, "pod-keys", KeySetManifestName))
	if err != nil {
		t.Fatalf("the unpacked set must carry its key-set manifest: %v", err)
	}
	for _, f := range []string{"data.key", "kek.salt"} {
		if m.Files[f].SHA256 != keyfiles.HashBytes(s.file(t, f)) {
			t.Fatalf("the unpacked manifest does not record the unpacked %s", f)
		}
	}
	fp, err := openedFingerprint(t, filepath.Join(cwd, "pod-keys"), testBaselinePassphrase)
	if err != nil {
		t.Fatalf("the unpacked key set does not open with the master passphrase: %v", err)
	}
	if want := s.Metadata.Annotations[KeySecretFingerprintAnnotation]; fp != want || len(fp) != 32 {
		t.Fatalf("DEK fingerprint %q, manifest says %q", fp, want)
	}
	if _, err := openedFingerprint(t, filepath.Join(cwd, "pod-keys"), testWrongPassphrase); err == nil {
		t.Fatal("the key set opened with a wrong passphrase")
	}
}

// TestKeySecret_ExportIncludesTheKeySetManifest: a key-set manifest next to the
// DEK (#2900) travels with the set, so the read-only mount matches it.
func TestKeySecret_ExportIncludesTheKeySetManifest(t *testing.T) {
	chdirTemp(t)
	setPassphraseEnv(t, testBaselinePassphrase)
	generate(t, "keys.yaml")
	if err := UnpackKeySecret("keys.yaml", "ws", nil, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("ws", KeySetManifestName), []byte(`{"format":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir("ws"); err != nil {
		t.Fatal(err)
	}
	if err := ExportKeySecret(chartConfig(), fileOpts("../out.yaml"), zeroPassSrc(), &bytes.Buffer{}); err != nil {
		t.Fatalf("ExportKeySecret: %v", err)
	}
	s, _ := readKeySecretManifest(t, "../out.yaml")
	if got := string(s.file(t, KeySetManifestName)); got != `{"format":1}` {
		t.Fatalf("manifest file in the Secret: %q", got)
	}
	if s.Metadata.Annotations["keyorix.io/key-files"] != "data.key,kek.salt,"+KeySetManifestName {
		t.Fatalf("key-files annotation %q", s.Metadata.Annotations["keyorix.io/key-files"])
	}
}

// TestKeySecret_Refusals: everything that must stop generate/export before a
// manifest is written, and nothing written when it does.
func TestKeySecret_Refusals(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, cfg *config.Config, opts *KeySecretOpts)
		wantErr string
	}{
		{"interrupted DEK rotation", func(t *testing.T, _ *config.Config, _ *KeySecretOpts) {
			writeFile(t, "dek.key.pending", "x")
		}, "dek.key.pending exists"},
		{"interrupted KEK rotation", func(t *testing.T, _ *config.Config, _ *KeySecretOpts) {
			writeFile(t, "kek.salt.pending", "x")
		}, "kek.salt.pending exists"},
		{"interrupted key-set manifest write", func(t *testing.T, cfg *config.Config, _ *KeySecretOpts) {
			killManifestWriteBeforeRename(t, cfg)
		}, KeySetManifestName + ".pending-"},
		{"legacy key-set manifest staging file", func(t *testing.T, _ *config.Config, _ *KeySecretOpts) {
			writeFile(t, KeySetManifestName+".pending", "x")
		}, KeySetManifestName + ".pending exists"},
		{"missing salt", func(t *testing.T, _ *config.Config, _ *KeySecretOpts) {
			if err := os.Remove("kek.salt"); err != nil {
				t.Fatal(err)
			}
		}, "kek.salt"},
		{"symlinked DEK", func(t *testing.T, _ *config.Config, _ *KeySecretOpts) {
			if err := os.Rename("dek.key", "real.key"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("real.key", "dek.key"); err != nil {
				t.Fatal(err)
			}
		}, "not a regular file"},
		{"existing output file", func(t *testing.T, _ *config.Config, opts *KeySecretOpts) {
			writeFile(t, opts.Out, "previous key set")
		}, "already exists"},
		{"tpm provider", func(t *testing.T, cfg *config.Config, _ *KeySecretOpts) {
			cfg.Storage.Encryption.KeyProvider = config.KeyProviderConfig{Type: "tpm", WrappedKeyPath: "kek.tpm"}
		}, "TPM"},
		{"shamir fallback", func(t *testing.T, cfg *config.Config, _ *KeySecretOpts) {
			cfg.Storage.Encryption.KeyProvider.Fallbacks = []config.KeyProviderConfig{{Type: "shamir"}}
		}, "shamir"},
		{"invalid Secret name", func(t *testing.T, _ *config.Config, opts *KeySecretOpts) {
			opts.Name = "Keyorix_Keys"
		}, "not a valid Kubernetes Secret name"},
		{"invalid namespace", func(t *testing.T, _ *config.Config, opts *KeySecretOpts) {
			opts.Namespace = "a.b"
		}, "not a valid Kubernetes namespace"},
		{"no output", func(t *testing.T, _ *config.Config, opts *KeySecretOpts) {
			opts.Out = ""
		}, "--out is required"},
		{"stdout inside a pod", func(t *testing.T, _ *config.Config, opts *KeySecretOpts) {
			opts.Out, opts.Stdout = "-", pipeWriter(t)
			t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		}, "pod log"},
		{"stdout under systemd", func(t *testing.T, _ *config.Config, opts *KeySecretOpts) {
			opts.Out, opts.Stdout = "-", pipeWriter(t)
			t.Setenv("JOURNAL_STREAM", "8:1234")
		}, "journal"},
		{"wrong passphrase", func(t *testing.T, _ *config.Config, _ *KeySecretOpts) {
			setPassphraseEnv(t, testWrongPassphrase)
		}, "unwrap"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chdirTemp(t)
			t.Setenv("KUBERNETES_SERVICE_HOST", "")
			t.Setenv("JOURNAL_STREAM", "")
			setPassphraseEnv(t, testBaselinePassphrase)
			cfg := testConfig(true)
			if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
				t.Fatal(err)
			}
			opts := fileOpts("out.yaml")
			tc.setup(t, cfg, &opts)
			before, _ := os.ReadFile("out.yaml")
			err := ExportKeySecret(cfg, opts, zeroPassSrc(), &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ExportKeySecret: %v, want an error containing %q", err, tc.wantErr)
			}
			if after, _ := os.ReadFile("out.yaml"); !bytes.Equal(before, after) {
				t.Fatal("a refused export changed out.yaml")
			}
			if tc.name == "tpm provider" || tc.name == "shamir fallback" || strings.HasPrefix(tc.name, "invalid") || tc.name == "stdout inside a pod" {
				// The same refusal applies before generating.
				if err := GenerateKeySecret(cfg, opts, zeroPassSrc(), &bytes.Buffer{}); err == nil {
					t.Fatal("GenerateKeySecret accepted it")
				}
			}
		})
	}
}

// TestKeySecret_StdoutPipeCarriesOnlyTheManifest: --out - to a pipe gets the
// manifest and nothing else.
func TestKeySecret_StdoutPipeCarriesOnlyTheManifest(t *testing.T) {
	chdirTemp(t)
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("JOURNAL_STREAM", "")
	setPassphraseEnv(t, testBaselinePassphrase)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	var msg bytes.Buffer
	opts := KeySecretOpts{Name: "k", Out: "-", Stdout: w}
	if err := GenerateKeySecret(chartConfig(), opts, zeroPassSrc(), &msg); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	var s parsedKeySecret
	if err := yaml.Unmarshal(out.Bytes(), &s); err != nil || s.Kind != "Secret" || len(s.Data) != 3 {
		t.Fatalf("stdout is not exactly the manifest (%v): %q", err, out.String())
	}
	if !strings.Contains(msg.String(), "to stdout") {
		t.Fatalf("messages: %q", msg.String())
	}
}

// TestKeySecret_UnpackRefusals: unpack writes only into an empty directory, and
// only file names.
func TestKeySecret_UnpackRefusals(t *testing.T) {
	chdirTemp(t)
	setPassphraseEnv(t, testBaselinePassphrase)
	generate(t, "keys.yaml")

	// A workspace that already holds files may be an interrupted rotation's:
	// its dek.key.pending would be the only copy of the new DEK.
	if err := os.Mkdir("busy", 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, "busy/dek.key.pending", "only copy")
	if err := UnpackKeySecret("keys.yaml", "busy", nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("unpack into a non-empty directory: %v", err)
	}
	if b, _ := os.ReadFile("busy/dek.key.pending"); string(b) != "only copy" {
		t.Fatal("unpack changed the existing workspace")
	}

	bad := map[string]string{
		"traversal key": "kind: Secret\ndata:\n  ../dek.key: \"eA==\"\n",
		"not a Secret":  "kind: ConfigMap\ndata:\n  dek.key: \"eA==\"\n",
		"stringData":    "kind: Secret\nstringData:\n  dek.key: x\n",
		"no data":       "kind: Secret\n",
		"not base64":    "kind: Secret\ndata:\n  dek.key: \"!!\"\n",
	}
	for name, manifest := range bad {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "ws")
			if err := UnpackKeySecret("-", dir, strings.NewReader(manifest), &bytes.Buffer{}); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("a refused unpack created %s", dir)
			}
		})
	}
}

// TestKeySecret_RotateKEKInWorkspace_NewSecretSameDEK is the rotate-kek
// procedure of Secret mode: unpack the live Secret into a workspace, rotate
// there, export the next Secret. The DEK (and so the DEK epoch) is unchanged,
// data.key and kek.salt are new, and only the new passphrase opens the new set.
func TestKeySecret_RotateKEKInWorkspace_NewSecretSameDEK(t *testing.T) {
	cwd := chdirTemp(t)
	setPassphraseEnv(t, testBaselinePassphrase)
	before := generate(t, "keys-1.yaml")
	if err := UnpackKeySecret("keys-1.yaml", "ws", nil, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir("ws"); err != nil {
		t.Fatal(err)
	}
	db := migrateEncOpsTables(t, testDBFile)
	closeTestDB(db)
	setNewPassphraseEnv(t, testNewPassphrase)
	if _, err := captureOutput(t, func() error {
		return RotateKEKWithConfig(chartConfig(), true, zeroPassSrc(), zeroPassSrc())
	}); err != nil {
		t.Fatalf("RotateKEKWithConfig in the workspace: %v", err)
	}
	setPassphraseEnv(t, testNewPassphrase)
	opts := fileOpts("../keys-2.yaml")
	opts.Name = "keyorix-keys-2"
	if err := ExportKeySecret(chartConfig(), opts, zeroPassSrc(), &bytes.Buffer{}); err != nil {
		t.Fatalf("ExportKeySecret after rotate-kek: %v", err)
	}
	after, _ := readKeySecretManifest(t, "../keys-2.yaml")
	if bytes.Equal(before.file(t, "data.key"), after.file(t, "data.key")) || bytes.Equal(before.file(t, "kek.salt"), after.file(t, "kek.salt")) {
		t.Fatal("rotate-kek must rewrap the DEK under a new salt")
	}
	fp := KeySecretFingerprintAnnotation
	if before.Metadata.Annotations[fp] != after.Metadata.Annotations[fp] {
		t.Fatalf("rotate-kek changed the DEK fingerprint %q -> %q", before.Metadata.Annotations[fp], after.Metadata.Annotations[fp])
	}
	if err := UnpackKeySecret("../keys-2.yaml", filepath.Join(cwd, "new"), nil, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := openedFingerprint(t, filepath.Join(cwd, "new"), testNewPassphrase); err != nil {
		t.Fatalf("new Secret does not open with the new passphrase: %v", err)
	}
	if _, err := openedFingerprint(t, filepath.Join(cwd, "new"), testBaselinePassphrase); err == nil {
		t.Fatal("new Secret opens with the old passphrase")
	}
}

// TestKeySecret_RotateDEKInWorkspace_NewFingerprintDataFollows is the DEK
// rotation of Secret mode: export the current set, rotate in the workspace,
// export again. The new Secret has a new DEK fingerprint, the same salt, and the
// rows decrypt under it; the previous Secret's set is not the one the rows need.
func TestKeySecret_RotateDEKInWorkspace_NewFingerprintDataFollows(t *testing.T) {
	cwd := chdirTemp(t)
	cfg, plaintext, userID := rotateFixture(t)
	if err := ExportKeySecret(cfg, fileOpts("keys-1.yaml"), zeroPassSrc(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := captureOutput(t, func() error { return RotateWithConfig(cfg, true, false, zeroPassSrc()) }); err != nil {
		t.Fatalf("RotateWithConfig: %v", err)
	}
	opts := fileOpts("keys-2.yaml")
	opts.Name = "keyorix-keys-2"
	if err := ExportKeySecret(cfg, opts, zeroPassSrc(), &bytes.Buffer{}); err != nil {
		t.Fatalf("ExportKeySecret after rotate: %v", err)
	}
	k1, _ := readKeySecretManifest(t, "keys-1.yaml")
	k2, _ := readKeySecretManifest(t, "keys-2.yaml")
	fp := KeySecretFingerprintAnnotation
	if k1.Metadata.Annotations[fp] == k2.Metadata.Annotations[fp] {
		t.Fatal("a DEK rotation must change the fingerprint")
	}
	if !bytes.Equal(k1.file(t, "kek.salt"), k2.file(t, "kek.salt")) {
		t.Fatal("a DEK rotation must keep the KEK salt")
	}
	onDisk, err := os.ReadFile(filepath.Join(cwd, "dek.key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, k2.file(t, "dek.key")) { // testConfig's name
		t.Fatal("the exported DEK is not the one the workspace rotated to")
	}
	if got := decryptPasswordResetRow(t, cfg, testBaselinePassphrase, userID); got != plaintext {
		t.Fatalf("row after rotation: %q", got)
	}
}

// killManifestWriteBeforeRename leaves the staging file a key operation's
// manifest write leaves when the process dies between writing it and renaming
// it into place: the real keyfiles writer runs, and the rename never returns.
// The refusal test then checks whatever name the writer actually stages under.
func killManifestWriteBeforeRename(t *testing.T, cfg *config.Config) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	w, err := keyfiles.NewSetWriter(&cfg.Storage.Encryption, cwd)
	if err != nil || w == nil {
		t.Fatalf("NewSetWriter: %v, %v", w, err)
	}
	type killed struct{}
	func() {
		defer func() {
			if r := recover(); r != nil && r != (killed{}) {
				panic(r)
			}
		}()
		_ = w.WithFS(keyfiles.ManifestFS{Rename: func(string, string) error { panic(killed{}) }}).
			CommitManifestFromDisk(keyfiles.OpRotateKEK, filepath.Join(cwd, cfg.Storage.Encryption.SaltPath))
		t.Fatal("the manifest write returned without reaching its rename")
	}()
	staged, err := filepath.Glob(filepath.Join(cwd, KeySetManifestName+".pending*"))
	if err != nil || len(staged) != 1 {
		t.Fatalf("the interrupted manifest write left %v (%v), want one staging file", staged, err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func pipeWriter(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	return w
}
