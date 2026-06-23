// Package bundle provides `keyorix bundle` — air-gap update-bundle tooling (ADR-064,
// ADR-062 Phase 1a). `build` assembles and signs a bundle from a directory of release
// artifacts (the Keyorix/issuance side, with the offline signing key); `verify` checks a
// bundle offline against the embedded, pinned public key and every component's digest (the
// air-gapped operator side). `import` (registry/chart staging) is a later phase.
package bundle

import (
	"fmt"
	"os"
	"time"

	ibundle "github.com/keyorixhq/keyorix/internal/bundle"
	"github.com/keyorixhq/keyorix/internal/trust"
	"github.com/spf13/cobra"
)

// BundleCmd is the `keyorix bundle` command group.
var BundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Air-gap update bundles: build (signed) and verify offline",
	Long: `Build and verify Keyorix air-gap update bundles (ADR-062 Phase 1).

A bundle is a single signed tarball carrying a release's artifacts, pinned by sha256 in a
manifest that is signed with an offline ed25519 key. An air-gapped operator carries the
file across the gap and verifies it offline against the public key embedded in this binary
at build time — trust follows a pinned chain, never a key shipped inside the bundle.`,
}

var (
	buildSrc        string
	buildOut        string
	buildVersion    string
	buildKeyID      string
	buildSignKey    string
	buildMinFrom    string
	buildReleased   string
	verifyInstalled string
)

var buildCmd = &cobra.Command{
	Use:          "build",
	Short:        "Assemble and sign an update bundle from a directory of release artifacts",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if buildSrc == "" || buildOut == "" {
			return fmt.Errorf("--src and --out are required")
		}
		releasedAt := time.Now().UTC()
		if buildReleased != "" {
			t, err := time.Parse(time.RFC3339, buildReleased)
			if err != nil {
				return fmt.Errorf("--released-at must be RFC3339: %w", err)
			}
			releasedAt = t.UTC()
		}

		keyPEM, err := os.ReadFile(buildSignKey) // #nosec G304 -- operator-supplied key path
		if err != nil {
			return fmt.Errorf("read signing key: %w", err)
		}
		priv, err := ibundle.ParsePrivateKeyPEM(keyPEM)
		if err != nil {
			return err
		}

		m, err := ibundle.BuildManifest(buildSrc, buildVersion, buildKeyID, buildMinFrom, releasedAt)
		if err != nil {
			return err
		}
		sig, err := ibundle.Sign(m, priv)
		if err != nil {
			return err
		}

		out, err := os.Create(buildOut) // #nosec G304 -- operator-supplied output path
		if err != nil {
			return fmt.Errorf("create bundle: %w", err)
		}
		if err := ibundle.WriteBundle(out, buildSrc, m, sig); err != nil {
			_ = out.Close()
			return fmt.Errorf("write bundle: %w", err)
		}
		if err := out.Close(); err != nil {
			return err
		}
		fmt.Printf("Built %s (%s, %d components, key-id %s) → %s\n",
			buildOut, m.Version, len(m.Components), m.KeyID, buildOut)
		return nil
	},
}

var verifyCmd = &cobra.Command{
	Use:          "verify <bundle>",
	Short:        "Verify a bundle offline against the embedded pinned key and component digests",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		reg, err := trust.DefaultRegistry()
		if err != nil {
			return fmt.Errorf("load trusted keys: %w", err)
		}

		f, err := os.Open(args[0]) // #nosec G304 -- operator-supplied bundle path
		if err != nil {
			return fmt.Errorf("open bundle: %w", err)
		}
		defer func() { _ = f.Close() }()

		m, err := ibundle.Verify(f, reg)
		if err != nil {
			return fmt.Errorf("verification failed (fail-closed): %w", err)
		}
		if err := m.CheckUpgrade(verifyInstalled); err != nil {
			return err
		}

		fmt.Printf("Bundle verified ✓\n")
		fmt.Printf("  version:    %s\n", m.Version)
		fmt.Printf("  signed by:  key-id %s (trusted, embedded)\n", m.KeyID)
		fmt.Printf("  released:   %s\n", m.ReleasedAt.Format(time.RFC3339))
		if m.MinUpgradeFrom != "" {
			fmt.Printf("  min from:   %s\n", m.MinUpgradeFrom)
		}
		fmt.Printf("  components: %d (all digests match)\n", len(m.Components))
		for _, c := range m.Components {
			fmt.Printf("    - %s\n", c.Path)
		}
		return nil
	},
}

func init() {
	buildCmd.Flags().StringVar(&buildSrc, "src", "", "directory of release artifacts to bundle (required)")
	buildCmd.Flags().StringVar(&buildOut, "out", "", "output bundle file (required)")
	buildCmd.Flags().StringVar(&buildVersion, "version", "", "bundle version, e.g. v0.82.0 (required)")
	buildCmd.Flags().StringVar(&buildKeyID, "key-id", "", "signing key-id, must match the embedded trusted key (required)")
	buildCmd.Flags().StringVar(&buildSignKey, "sign-key", "", "PKCS#8 PEM ed25519 private signing key (required; keep offline)")
	buildCmd.Flags().StringVar(&buildMinFrom, "min-upgrade-from", "", "minimum installed version this bundle may upgrade from (anti-skip)")
	buildCmd.Flags().StringVar(&buildReleased, "released-at", "", "release timestamp (RFC3339; default now)")
	_ = buildCmd.MarkFlagRequired("src")
	_ = buildCmd.MarkFlagRequired("out")
	_ = buildCmd.MarkFlagRequired("version")
	_ = buildCmd.MarkFlagRequired("key-id")
	_ = buildCmd.MarkFlagRequired("sign-key")

	verifyCmd.Flags().StringVar(&verifyInstalled, "installed-version", "", "currently-installed version, to enforce no-downgrade / min-upgrade-from")

	BundleCmd.AddCommand(buildCmd)
	BundleCmd.AddCommand(verifyCmd)
}
