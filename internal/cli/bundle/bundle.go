// Package bundle provides `keyorix bundle` — air-gap update-bundle tooling (ADR-064).
// `build` assembles and signs a bundle from a directory of release artifacts (the
// Keyorix/issuance side, with the offline signing key); `verify` checks a bundle offline
// against the embedded, pinned public key and every component's digest; `import` verifies
// and stages the artifacts for an air-gapped rollout. `verify` is free; `import` is the
// first license-gated commercial feature (ADR-065 Phase 2c, the airgap_updates feature).
package bundle

import (
	"fmt"
	"os"
	"strings"
	"time"

	ibundle "github.com/keyorixhq/keyorix/internal/bundle"
	"github.com/keyorixhq/keyorix/internal/config"
	ilicense "github.com/keyorixhq/keyorix/internal/license"
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
	importDest      string
	importInstalled string
	importLicense   string
)

// defaultRegistryFn is the function used to load the trusted key registry for
// verify and import commands. It defaults to trust.DefaultRegistry, which reads
// the keys embedded at build time via -ldflags. Tests may override it to inject
// a registry with known keys so the full command path can be exercised without
// a release build.
var defaultRegistryFn = trust.DefaultRegistry

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
		reg, err := defaultRegistryFn()
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

var importCmd = &cobra.Command{
	Use:          "import <bundle>",
	Short:        "Verify a bundle offline and stage its artifacts into a directory",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		if importDest == "" {
			return fmt.Errorf("--dest is required")
		}
		reg, err := defaultRegistryFn()
		if err != nil {
			return fmt.Errorf("load trusted keys: %w", err)
		}

		// Commercial gate (ADR-065 Phase 2c): `bundle import` — staging an update for an
		// air-gapped rollout — is the first license-gated feature. `bundle verify` stays
		// free. Fail-safe: a missing/expired/invalid license simply means the feature is
		// off, so import is refused with a clear message (it never affects a running
		// deployment). Gating strips nothing from community source builds, which can't
		// import anyway (no embedded update key).
		if err := requireAirgapUpdates(reg); err != nil {
			return err
		}

		f, err := os.Open(args[0]) // #nosec G304 -- operator-supplied bundle path
		if err != nil {
			return fmt.Errorf("open bundle: %w", err)
		}
		defer func() { _ = f.Close() }()

		// Extract verifies the signature and the no-downgrade gate BEFORE writing anything,
		// then stages each verified component atomically. It fails closed.
		m, err := ibundle.Extract(f, reg, importDest, importInstalled)
		if err != nil {
			return fmt.Errorf("import failed (fail-closed, nothing staged on a verify failure): %w", err)
		}

		fmt.Printf("Imported %s ✓ — staged %d verified components under %s\n", m.Version, len(m.Components), importDest)
		fmt.Printf("  signed by: key-id %s (trusted, embedded)\n", m.KeyID)
		for _, c := range m.Components {
			fmt.Printf("    - %s\n", c.Path)
		}
		fmt.Printf("\nNext (operator-controlled rollout — Keyorix never pushes to your registry):\n")
		fmt.Printf("  1. Load images into your internal registry, e.g.:\n")
		fmt.Printf("       for img in %s/images/*; do docker load -i \"$img\"; done\n", importDest)
		fmt.Printf("  2. Apply CRDs and run the Helm upgrade from the staged charts:\n")
		fmt.Printf("       kubectl apply -f %s/crds/   # if present\n", importDest)
		fmt.Printf("       helm upgrade keyorix %s/charts/keyorix-*.tgz\n", importDest)
		return nil
	},
}

// requireAirgapUpdates enforces the commercial license gate for `bundle import`. It reads
// the installed license token (if --license was given), evaluates it offline against the
// embedded license key, and requires the airgap_updates feature. Fail-safe: any
// missing/degraded license means the feature is simply off, and import is refused with a
// clear, actionable message — it never affects a running deployment.
func requireAirgapUpdates(reg *trust.KeyRegistry) error {
	var token string
	if importLicense != "" {
		b, err := os.ReadFile(importLicense) // #nosec G304 -- operator-supplied license path
		if err != nil {
			return fmt.Errorf("read license: %w", err)
		}
		token = strings.TrimSpace(string(b))
	}
	st := ilicense.Evaluate(token, reg, configuredDeploymentID(), time.Now(), 14*24*time.Hour)
	if st.HasFeature(ilicense.FeatureAirgapUpdates) {
		return nil
	}
	return fmt.Errorf("`bundle import` is a commercial feature (%q) and requires a valid license "+
		"(current state: %s). Install one with `keyorix license install` and pass it via --license, "+
		"or check `keyorix license status`. `bundle verify` remains available without a license",
		ilicense.FeatureAirgapUpdates, st.State)
}

// configuredDeploymentID best-effort loads the local server config and returns the
// operator's configured license.deployment_id, so `bundle import` honors an anti-copy
// deployment binding the operator has already set — the same value the server itself
// passes to license.NewGate (server/main.go) and that `keyorix license install/status`
// accept via --deployment-id. If no config file is found (or it can't be read), this
// returns "", matching the previous hardcoded default: an operator who has never
// configured license.deployment_id sees no change in behavior.
func configuredDeploymentID() string {
	cfg, err := config.Load("")
	if err != nil {
		return ""
	}
	return cfg.License.DeploymentID
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

	importCmd.Flags().StringVar(&importDest, "dest", "", "directory to stage verified artifacts into (required)")
	importCmd.Flags().StringVar(&importInstalled, "installed-version", "", "currently-installed version, to enforce no-downgrade / min-upgrade-from")
	importCmd.Flags().StringVar(&importLicense, "license", "", "path to the installed license token (bundle import is a commercial feature)")
	_ = importCmd.MarkFlagRequired("dest")

	BundleCmd.AddCommand(buildCmd)
	BundleCmd.AddCommand(verifyCmd)
	BundleCmd.AddCommand(importCmd)
}
