// encryption_key_secret.go implements `keyorix-server admin encryption
// key-secret generate|export|unpack` (HA-SECRET-KEYS-1): moving a key set
// between a key directory and a Kubernetes Secret manifest for the Helm
// chart's Secret mode (docs/multi-replica-keys.md). The logic lives in
// internal/encryptionops/key_secret.go.
//
// None of these commands opens the database or takes this tree's presence
// lock: generate writes a new key set to a private temporary directory, export
// reads a key directory under the shared key-directory lock, and unpack writes
// only into an empty directory. Every progress line goes to stderr, so stdout
// carries nothing but the manifest when --out is -.
package admin

import (
	"os"

	"github.com/keyorixhq/keyorix/internal/encryptionops"
	"github.com/spf13/cobra"
)

var (
	keySecretName      string
	keySecretNamespace string
	keySecretOut       string
	keySecretIn        string
	keySecretDir       string
)

var encKeySecretCmd = &cobra.Command{
	Use:   "key-secret",
	Short: "Move a key set between a key directory and a Kubernetes Secret manifest",
	Long: `Secret mode of the Helm chart (server.keysSecret, docs/multi-replica-keys.md):
every server replica reads the key files read-only from one Kubernetes Secret,
and no replica ever generates keys. These commands produce and consume that
Secret's manifest:

  generate  a new key set for a new install, straight into a manifest
  export    the key set of the configured key directory (after a rotation)
  unpack    a manifest back into key files, as a rotation workspace

The manifest holds key material. It is written to a new 0600 file, or to stdout
only when stdout is a pipe (never a terminal, a Kubernetes pod log or the
systemd journal). None of these commands contacts the database.`,
}

var encKeySecretGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new key set as a Secret manifest (new installs only)",
	Long: `Generate a new wrapped DEK (and KEK salt, for the password provider) in a
private temporary directory, write them as a Secret manifest and remove the
temporary files. The key file names are the base names of the configured
dek_path/salt_path (the Helm chart uses data.key and kek.salt).

For a NEW installation only: a server whose database is already encrypted under
another DEK refuses to start with this key set (DEK epoch).`,
	RunE: runKeySecretGenerate,
}

func runKeySecretGenerate(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	stdout := redirectStdoutToStderr()
	defer func() { os.Stdout = stdout }()
	return encryptionops.GenerateKeySecret(cfg, keySecretOpts(stdout), encPassphraseSource, os.Stderr)
}

var encKeySecretExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Write the configured key directory's key set as a Secret manifest",
	Long: `Write the key set the configuration names (dek_path, salt_path or the
provider's wrapped KEK, plus the key-set manifest when present; relative paths
resolve against the current directory) as a Secret manifest. The DEK must
unwrap with this configuration's KEK first, and the export is refused while a
key operation is half done in the directory (a .pending staging file). The
Secret is labelled with the DEK fingerprint, the value of the database's
dek.epoch row this key set opens.`,
	RunE: runKeySecretExport,
}

func runKeySecretExport(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	stdout := redirectStdoutToStderr()
	defer func() { os.Stdout = stdout }()
	return encryptionops.ExportKeySecret(cfg, keySecretOpts(stdout), encPassphraseSource, os.Stderr)
}

var encKeySecretUnpackCmd = &cobra.Command{
	Use:   "unpack",
	Short: "Write a key Secret manifest's files into an empty directory",
	Long: `Write every data key of a Secret manifest (this tool's output, or
'kubectl get secret <name> -o yaml') as a 0600 file into --dir, which must be
empty or not exist yet. That directory is the writable workspace in which the
key rotation commands run against a Secret-mode install.`,
	RunE: runKeySecretUnpack,
}

func runKeySecretUnpack(cmd *cobra.Command, args []string) error {
	return encryptionops.UnpackKeySecret(keySecretIn, keySecretDir, os.Stdin, os.Stderr)
}

func init() {
	encryptionCmd.AddCommand(encKeySecretCmd)
	encKeySecretCmd.AddCommand(encKeySecretGenerateCmd, encKeySecretExportCmd, encKeySecretUnpackCmd)
	for _, c := range []*cobra.Command{encKeySecretGenerateCmd, encKeySecretExportCmd} {
		f := c.Flags()
		f.StringVar(&keySecretName, "name", "", "name of the Secret (the Helm value server.keysSecret.name)")
		f.StringVar(&keySecretNamespace, "namespace", "", "namespace of the Secret (optional)")
		f.StringVar(&keySecretOut, "out", "", "new file for the manifest (0600, never overwritten), or - for stdout when it is a pipe")
		_ = c.MarkFlagRequired("name")
		_ = c.MarkFlagRequired("out")
	}
	f := encKeySecretUnpackCmd.Flags()
	f.StringVar(&keySecretIn, "in", "", "the Secret manifest (YAML or JSON), or - for stdin")
	f.StringVar(&keySecretDir, "dir", "", "empty or new directory for the key files")
	_ = encKeySecretUnpackCmd.MarkFlagRequired("in")
	_ = encKeySecretUnpackCmd.MarkFlagRequired("dir")
}

func keySecretOpts(stdout *os.File) encryptionops.KeySecretOpts {
	return encryptionops.KeySecretOpts{Name: keySecretName, Namespace: keySecretNamespace, Out: keySecretOut, Stdout: stdout}
}

// redirectStdoutToStderr points os.Stdout at stderr while the key operations
// run (key generation prints its progress with fmt.Printf) and returns the real
// stdout, which then carries only the manifest.
func redirectStdoutToStderr() *os.File {
	stdout := os.Stdout
	os.Stdout = os.Stderr
	return stdout
}
