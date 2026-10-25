// key_secret.go is the logic of `keyorix-server admin encryption key-secret`
// (HA-SECRET-KEYS-1): the key files of a multi-replica Kubernetes install reach
// the pods read-only from a Kubernetes Secret (docs/multi-replica-keys.md,
// "Secret mode"), so the key set has to travel between a key directory and a
// Secret manifest without any replica generating its own keys, and without the
// key material passing through logs, environment variables or Helm values.
//
//   - GenerateKeySecret: a brand-new key set for a new install, generated in a
//     private temporary directory and written out as a Secret manifest. It needs
//     no database: a server whose database is already encrypted under another
//     DEK refuses to start with it (DEK epoch, #3344), so a mistaken generate
//     cannot reach data.
//   - ExportKeySecret: the key set in the configured key directory (a rotation
//     workspace, or the keys volume of a single-replica install) as a Secret
//     manifest. Refused while a key operation is half done there.
//   - UnpackKeySecret: a Secret manifest (ours, or `kubectl get secret -o yaml`)
//     back into key files in an empty directory, the writable workspace the key
//     rotation commands run in.
//
// The manifest is written to a new file (O_EXCL, 0600) or to stdout when stdout
// is a pipe. It is never printed to a terminal, nor to stdout inside a
// Kubernetes pod or a systemd unit, where stdout is collected as logs.
package encryptionops

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

const (
	// KeySetManifestName is the key-set manifest a newer server writes next to
	// the DEK (#2900). Exported with the set when present, so a read-only Secret
	// mount carries the same set the manifest describes.
	KeySetManifestName = "keyset.manifest.json"

	// KeySecretFingerprintAnnotation names the DEK fingerprint on an exported
	// Secret: the value of the database's dek.epoch row that this key set opens.
	KeySecretFingerprintAnnotation = "keyorix.io/dek-fingerprint" // #nosec G101 -- an annotation name, not a credential

	// maxKeySecretBytes bounds the key files of one Secret, well under the
	// API server's 1 MiB object limit (a key set is a few hundred bytes).
	maxKeySecretBytes = 256 << 10
	// maxKeySecretManifestBytes bounds what UnpackKeySecret reads.
	maxKeySecretManifestBytes = 1 << 20
)

var (
	// Kubernetes object names: a DNS-1123 subdomain (Secret) and label (namespace).
	secretNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	namespaceRE  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	// Secret data keys, which become file names in the mounted volume.
	secretKeyRE = regexp.MustCompile(`^[-._a-zA-Z0-9]+$`)
)

// KeySecretOpts names the Secret to write and where the manifest goes.
type KeySecretOpts struct {
	Name      string
	Namespace string
	// Out is a path for a new file, or "-" for Stdout.
	Out string
	// Stdout receives the manifest when Out is "-".
	Stdout *os.File
}

func (o KeySecretOpts) validate() error {
	if !secretNameRE.MatchString(o.Name) || len(o.Name) > 253 {
		return fmt.Errorf("--name %q is not a valid Kubernetes Secret name (lower-case DNS subdomain, at most 253 characters)", o.Name)
	}
	if o.Namespace != "" && (!namespaceRE.MatchString(o.Namespace) || len(o.Namespace) > 63) {
		return fmt.Errorf("--namespace %q is not a valid Kubernetes namespace name", o.Namespace)
	}
	switch o.Out {
	case "":
		return errors.New("--out is required: a path for a new file (created 0600, never overwritten), or - for stdout when it is a pipe")
	case "-":
		return refuseLoggedStdout(o.Stdout)
	}
	if _, err := os.Lstat(o.Out); err == nil {
		return fmt.Errorf("--out %s already exists: refusing to overwrite it (it may hold the only copy of a key set)", o.Out)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("--out %s: %w", o.Out, err)
	}
	return nil
}

// refuseLoggedStdout refuses stdout as the manifest's destination wherever its
// content would end up in a log or on screen: a terminal, a Kubernetes pod (the
// container runtime collects stdout as the pod log) or a systemd unit (journald).
func refuseLoggedStdout(stdout *os.File) error {
	if stdout == nil {
		return errors.New("--out -: no stdout")
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return errors.New("--out -: refusing to write key material to stdout inside a Kubernetes pod, where stdout is collected as the pod log; write it to a file (--out <path>) on a volume you control")
	}
	if os.Getenv("JOURNAL_STREAM") != "" {
		return errors.New("--out -: refusing to write key material to stdout under systemd, where stdout goes to the journal; use --out <path>")
	}
	if term.IsTerminal(int(stdout.Fd())) { // #nosec G115 -- a file descriptor fits an int
		return errors.New("--out -: refusing to print key material to a terminal; pipe it (… --out - | kubectl create -f -) or use --out <path>")
	}
	return nil
}

// refuseUnsupportedProviders refuses KEK providers whose key material cannot be
// carried in, or must not share, a key Secret.
func refuseUnsupportedProviders(enc *config.EncryptionConfig) error {
	providers := append([]config.KeyProviderConfig{enc.KeyProvider}, enc.KeyProvider.Fallbacks...)
	for _, kp := range providers {
		switch kp.Type {
		case "tpm":
			return errors.New("key_provider tpm: a TPM-sealed KEK can only be unsealed by the TPM of the host that sealed it, so replicas on other nodes cannot use a copy; use a cloud KMS provider (aws-kms, gcp-kms, azure-kms) or password for Secret mode")
		case "shamir":
			return errors.New("key_provider shamir: the shares are held by separate custodians and must never be stored next to the wrapped DEK; Secret mode does not support the shamir provider")
		}
	}
	return nil
}

// keySetFile is one file of a key set, named by its Secret data key.
type keySetFile struct {
	key  string
	data []byte
}

func wipeKeySet(files []keySetFile) {
	for i := range files {
		crypto.WipeBytes(files[i].data)
	}
}

// readKeySet reads the key files enc requires under baseDir, plus the key-set
// manifest when there is one. It refuses a set a key operation left half done
// (a .pending staging file), a missing file, anything but a regular file, and
// two files that would need the same Secret key.
func readKeySet(enc *config.EncryptionConfig, baseDir string) ([]keySetFile, error) {
	paths, err := keyfiles.RequiredKeyFilePaths(enc, baseDir)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, errors.New("the configuration names no key files (storage.encryption.dek_path)")
	}
	dekFull := filepath.Join(baseDir, enc.DEKPath)
	if filepath.IsAbs(enc.DEKPath) {
		dekFull = filepath.Clean(enc.DEKPath)
	}
	manifest := filepath.Join(filepath.Dir(dekFull), KeySetManifestName)
	for _, p := range append(slices.Clone(paths), manifest) {
		if _, err := os.Lstat(p + ".pending"); err != nil {
			continue
		}
		if p == dekFull {
			return nil, fmt.Errorf("%s.pending exists: a DEK rotation was interrupted in this directory. Run `keyorix-server admin encryption upgrade-aad` here (with the replicas stopped): its crash recovery promotes the pending DEK if the database committed the rotation and discards it otherwise. Then export. Never delete this directory or copy a key set with a staging file: the pending file may be the only copy of the DEK the database is encrypted under", p)
		}
		return nil, fmt.Errorf("%s.pending exists: a key operation (rotate-kek, migrate-provider) was interrupted in this directory; do not export it (docs/multi-replica-keys.md, \"Crash at any step\")", p)
	}
	if info, err := os.Lstat(manifest); err == nil && info.Mode().IsRegular() {
		paths = append(paths, manifest)
	}

	var files []keySetFile
	total := 0
	seen := make(map[string]string)
	for _, p := range paths {
		info, err := os.Lstat(p)
		if err != nil {
			wipeKeySet(files)
			return nil, fmt.Errorf("key file %s: %w (export needs the complete key set)", p, err)
		}
		if !info.Mode().IsRegular() {
			wipeKeySet(files)
			return nil, fmt.Errorf("key file %s is not a regular file", p)
		}
		key := filepath.Base(p)
		if !secretKeyRE.MatchString(key) {
			wipeKeySet(files)
			return nil, fmt.Errorf("key file %s: its name is not a valid Secret key", p)
		}
		if other, dup := seen[key]; dup {
			wipeKeySet(files)
			return nil, fmt.Errorf("key files %s and %s have the same name, so they cannot both be keys of one Secret (mounted as one directory)", other, p)
		}
		seen[key] = p
		data, err := secretenv.ReadRegularFile("key file", p) // a path from the operator's own encryption config; refuses a FIFO/device instead of hanging
		if err != nil {
			wipeKeySet(files)
			return nil, err
		}
		total += len(data)
		files = append(files, keySetFile{key: key, data: data})
		if total > maxKeySecretBytes {
			wipeKeySet(files)
			return nil, fmt.Errorf("the key files add up to more than %d bytes; this is not a key set", maxKeySecretBytes)
		}
	}
	slices.SortFunc(files, func(a, b keySetFile) int { return strings.Compare(a.key, b.key) })
	return files, nil
}

// openKeySet reads the key set under baseDir after proving it opens: the DEK
// unwraps with this configuration's KEK. It returns the files and the DEK
// fingerprint. The files are read while the key-directory lock is held shared,
// so a key operation cannot rewrite them in between.
func openKeySet(cfg *config.Config, baseDir, passphrase string, create bool) ([]keySetFile, string, error) {
	enc := &cfg.Storage.Encryption
	if !create {
		// Every file must be there before Initialize, which would otherwise
		// generate a missing salt.
		files, err := readKeySet(enc, baseDir)
		if err != nil {
			return nil, "", err
		}
		wipeKeySet(files)
	}
	service, err := InitLocalKeyOpService(cfg, baseDir, passphrase, create)
	if err != nil {
		return nil, "", err
	}
	defer service.Shutdown()
	fp, err := service.DEKFingerprint()
	if err != nil {
		return nil, "", err
	}
	files, err := readKeySet(enc, baseDir)
	if err != nil {
		return nil, "", err
	}
	return files, fp, nil
}

// GenerateKeySecret creates a new key set and writes it as a Secret manifest.
// The key files are generated in a private temporary directory, named after
// cfg's key paths, and removed afterwards: the manifest is the only copy.
func GenerateKeySecret(cfg *config.Config, opts KeySecretOpts, passSrc crypto.PassphraseSource, msg io.Writer) error {
	if err := opts.validate(); err != nil {
		return err
	}
	if !cfg.Storage.Encryption.Enabled {
		return errors.New("encryption is disabled in configuration")
	}
	if err := refuseUnsupportedProviders(&cfg.Storage.Encryption); err != nil {
		return err
	}
	gen, err := keySetInDir(cfg)
	if err != nil {
		return err
	}
	passphrase, err := MasterPassphrase(cfg, passSrc)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "keyorix-key-secret-")
	if err != nil {
		return err
	}
	defer removeKeyDir(tmp)

	say(msg, "Generating a new key set (no database is contacted)...")
	files, fp, err := openKeySet(gen, tmp, passphrase, true)
	if err != nil {
		return err
	}
	defer wipeKeySet(files)
	if err := writeKeySecret(opts, files, fp, "generate"); err != nil {
		return err
	}
	reportKeySecret(msg, opts, files, fp)
	say(msg, "This is a NEW key set, for a new installation only: a server whose database is already encrypted under another DEK refuses to start with it (DEK epoch).")
	return nil
}

// ExportKeySecret writes the key set in the configured key directory (paths
// resolved against the current directory) as a Secret manifest.
func ExportKeySecret(cfg *config.Config, opts KeySecretOpts, passSrc crypto.PassphraseSource, msg io.Writer) error {
	if err := opts.validate(); err != nil {
		return err
	}
	if !cfg.Storage.Encryption.Enabled {
		return errors.New("encryption is disabled in configuration")
	}
	if err := refuseUnsupportedProviders(&cfg.Storage.Encryption); err != nil {
		return err
	}
	baseDir, err := os.Getwd()
	if err != nil {
		return err
	}
	passphrase, err := MasterPassphrase(cfg, passSrc)
	if err != nil {
		return err
	}
	files, fp, err := openKeySet(cfg, baseDir, passphrase, false)
	if err != nil {
		return err
	}
	defer wipeKeySet(files)
	if err := writeKeySecret(opts, files, fp, "export"); err != nil {
		return err
	}
	reportKeySecret(msg, opts, files, fp)
	return nil
}

// keySetInDir returns a copy of cfg whose key files are plain names (the base
// names of cfg's paths), for generation in a directory of their own. The base
// names are what the Secret's keys, and so the mounted file names, will be.
func keySetInDir(cfg *config.Config) (*config.Config, error) {
	gen := *cfg
	enc := &gen.Storage.Encryption
	enc.KeyDirLock = "" // a private directory: the plain flock is right
	base := func(field, p string) (string, error) {
		if p == "" {
			return "", nil
		}
		b := filepath.Base(p)
		if !secretKeyRE.MatchString(b) || b == "." || b == ".." {
			return "", fmt.Errorf("%s %q: its file name is not a valid Secret key", field, p)
		}
		return b, nil
	}
	var err error
	if enc.DEKPath, err = base("dek_path", enc.DEKPath); err != nil {
		return nil, err
	}
	if enc.DEKPath == "" {
		return nil, errors.New("storage.encryption.dek_path is not set")
	}
	if enc.SaltPath, err = base("salt_path", enc.SaltPath); err != nil {
		return nil, err
	}
	if enc.KeyProvider.WrappedKeyPath, err = base("key_provider.wrapped_key_path", enc.KeyProvider.WrappedKeyPath); err != nil {
		return nil, err
	}
	enc.KeyProvider.Fallbacks = slices.Clone(enc.KeyProvider.Fallbacks)
	for i := range enc.KeyProvider.Fallbacks {
		fb := &enc.KeyProvider.Fallbacks[i]
		if fb.WrappedKeyPath, err = base("key_provider.fallbacks.wrapped_key_path", fb.WrappedKeyPath); err != nil {
			return nil, err
		}
	}
	return &gen, nil
}

// removeKeyDir overwrites and removes every file of a temporary key directory.
func removeKeyDir(dir string) {
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.Type().IsRegular() {
				_ = securefiles.SecureDeleteFile(filepath.Join(dir, e.Name()))
			}
		}
	}
	_ = os.RemoveAll(dir)
}

// renderKeySecret returns the Secret manifest. Values are quoted: an unquoted
// base64 string of digits would be read back as a YAML number.
func renderKeySecret(opts KeySecretOpts, files []keySetFile, fingerprint, how string) []byte {
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = f.key
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Keyorix key set (%s), DEK fingerprint %s.\n", strings.Join(names, ", "), fingerprint)
	b.WriteString("# KEY MATERIAL. Store this file with your key backups, separately from database\n")
	b.WriteString("# backups, and delete every other copy once the Secret exists.\n")
	b.WriteString("# Create it with: kubectl create -f <this file>   (docs/multi-replica-keys.md)\n")
	b.WriteString("apiVersion: v1\nkind: Secret\nmetadata:\n")
	fmt.Fprintf(&b, "  name: %q\n", opts.Name)
	if opts.Namespace != "" {
		fmt.Fprintf(&b, "  namespace: %q\n", opts.Namespace)
	}
	b.WriteString("  labels:\n    app.kubernetes.io/name: \"keyorix\"\n    keyorix.io/key-set: \"true\"\n")
	b.WriteString("  annotations:\n")
	fmt.Fprintf(&b, "    %s: %q\n", KeySecretFingerprintAnnotation, fingerprint)
	fmt.Fprintf(&b, "    keyorix.io/key-files: %q\n", strings.Join(names, ","))
	fmt.Fprintf(&b, "    keyorix.io/created-by: %q\n", "keyorix-server admin encryption key-secret "+how)
	// Immutable: a key Secret is never edited in place. A rotation creates a new
	// Secret and points the release at it, so the previous key set stays intact
	// until the new one is verified.
	b.WriteString("type: Opaque\nimmutable: true\ndata:\n")
	for _, f := range files {
		fmt.Fprintf(&b, "  %s: %q\n", f.key, base64.StdEncoding.EncodeToString(f.data))
	}
	return b.Bytes()
}

func writeKeySecret(opts KeySecretOpts, files []keySetFile, fingerprint, how string) error {
	manifest := renderKeySecret(opts, files, fingerprint, how)
	defer crypto.WipeBytes(manifest)
	if opts.Out == "-" {
		_, err := opts.Stdout.Write(manifest)
		return err
	}
	dir, name := filepath.Split(opts.Out)
	if dir == "" {
		dir = "."
	}
	if err := securefiles.SecureCreateFileSync(dir, name, manifest, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", opts.Out, err)
	}
	return securefiles.SyncDir(dir)
}

func reportKeySecret(msg io.Writer, opts KeySecretOpts, files []keySetFile, fingerprint string) {
	parts := make([]string, len(files))
	for i, f := range files {
		parts[i] = fmt.Sprintf("%s (%d bytes)", f.key, len(f.data))
	}
	dest := opts.Out
	if dest == "-" {
		dest = "stdout"
	}
	sayf(msg, "Wrote Secret %q (%s), DEK fingerprint %s, to %s.\n", opts.Name, strings.Join(parts, ", "), fingerprint, dest)
	say(msg, "It holds key material: keep it with your key backups, separately from database backups.")
}

// say and sayf write a progress line; a failed write to the message stream
// (stderr) changes nothing about the operation.
func say(w io.Writer, a ...any)                 { _, _ = fmt.Fprintln(w, a...) }
func sayf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

// keySecretManifest is the part of a Secret manifest UnpackKeySecret reads.
type keySecretManifest struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name        string            `yaml:"name"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Data       map[string]string `yaml:"data"`
	StringData map[string]string `yaml:"stringData"`
}

// UnpackKeySecret writes the key files of a Secret manifest (in: a path, or "-"
// for stdin) into dir, which must be empty or not exist yet. On any failure the
// files it wrote are removed again: dir ends up empty or holding the whole set.
func UnpackKeySecret(in, dir string, stdin io.Reader, msg io.Writer) error {
	if in == "" || dir == "" {
		return errors.New("--in and --dir are required")
	}
	raw, err := readManifestInput(in, stdin)
	if err != nil {
		return err
	}
	defer crypto.WipeBytes(raw)
	var m keySecretManifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("--in %s: not a Secret manifest: %w", in, err)
	}
	if m.Kind != "Secret" {
		return fmt.Errorf("--in %s: kind %q, want Secret", in, m.Kind)
	}
	if len(m.StringData) > 0 {
		return fmt.Errorf("--in %s: stringData is not supported (key files are binary); use data", in)
	}
	if len(m.Data) == 0 {
		return fmt.Errorf("--in %s: the Secret has no data", in)
	}
	keys := make([]string, 0, len(m.Data))
	for k := range m.Data {
		if !secretKeyRE.MatchString(k) || k == "." || k == ".." {
			return fmt.Errorf("--in %s: data key %q is not a plain file name", in, k)
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	files := make([]keySetFile, 0, len(keys))
	defer func() { wipeKeySet(files) }()
	for _, k := range keys {
		data, err := base64.StdEncoding.DecodeString(m.Data[k])
		if err != nil {
			return fmt.Errorf("--in %s: data key %q is not base64", in, k)
		}
		files = append(files, keySetFile{key: k, data: data})
	}

	if err := prepareEmptyDir(dir); err != nil {
		return err
	}
	var written []string
	for _, f := range files {
		if err := securefiles.SecureCreateFileSync(dir, f.key, f.data, 0o600); err != nil {
			for _, w := range written {
				_ = securefiles.SecureDeleteFile(filepath.Join(dir, w))
			}
			return fmt.Errorf("write %s: %w", filepath.Join(dir, f.key), err)
		}
		written = append(written, f.key)
	}
	if err := securefiles.SyncDir(dir); err != nil {
		return err
	}
	sayf(msg, "Unpacked Secret %q (%s) into %s", m.Metadata.Name, strings.Join(keys, ", "), dir)
	if fp := m.Metadata.Annotations[KeySecretFingerprintAnnotation]; fp != "" {
		sayf(msg, ", DEK fingerprint %s", fp)
	}
	say(msg, ".")
	say(msg, "Run the admin command from that directory with a config whose dek_path and salt_path name these files.")
	return nil
}

func readManifestInput(in string, stdin io.Reader) ([]byte, error) {
	r := stdin
	if in != "-" {
		f, err := secretenv.OpenRegularNamed("--in manifest", in) // the operator's own manifest file; refuses a FIFO/device
		if err != nil {
			return nil, err
		}
		defer f.Close() //nolint:errcheck
		r = f
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxKeySecretManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxKeySecretManifestBytes {
		crypto.WipeBytes(raw)
		return nil, fmt.Errorf("--in %s is larger than %d bytes; not a key Secret", in, maxKeySecretManifestBytes)
	}
	return raw, nil
}

// prepareEmptyDir creates dir (0700) or accepts an existing empty directory.
// A non-empty one is refused: it may hold a workspace with an interrupted
// rotation, whose staging file is the only copy of the new DEK.
func prepareEmptyDir(dir string) error {
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return os.Mkdir(dir, 0o700)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("--dir %s is not a directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("--dir %s is not empty: refusing to write a key set over another one (an interrupted rotation's workspace holds the only copy of its new DEK)", dir)
	}
	return nil
}
