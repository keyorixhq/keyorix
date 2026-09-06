// Package bundle provides `keyorix bundle` — air-gap update-bundle tooling (ADR-064).
// `build` assembles and signs a bundle from a directory of release artifacts (the
// Keyorix/issuance side, with the offline signing key); `verify` checks a bundle offline
// against the embedded, pinned public key and every component's digest; `import` verifies
// and stages the artifacts for an air-gapped rollout. `verify` is free; `import` is the
// first license-gated commercial feature (ADR-065 Phase 2c, the airgap_updates feature).
package bundle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	ibundle "github.com/keyorixhq/keyorix/internal/bundle"
	"github.com/keyorixhq/keyorix/internal/config"
	ilicense "github.com/keyorixhq/keyorix/internal/license"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"github.com/keyorixhq/keyorix/internal/trust"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
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
	buildSrc         string
	buildOut         string
	buildVersion     string
	buildKeyID       string
	buildSignKey     string
	buildMinFrom     string
	buildReleased    string
	verifyInstalled  string
	verifyForce      bool
	importDest       string
	importInstalled  string
	importForce      bool
	importLicense    string
	importResetState bool
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

		// SecureOpenBeneath, not os.Create: a bundle is rebuilt to the same --out path on
		// every CI run by design (a repeatable release-pipeline workflow, unlike a secret
		// export whose output is generated once), so this intentionally does NOT use
		// O_EXCL — but it still gets the full per-path-component O_NOFOLLOW walk, which a
		// bare os.Create never had at all (not even the final-component protection an
		// explicit O_NOFOLLOW would add), closing a real symlink-redirect gap in a build
		// pipeline that runs unattended.
		out, err := securefiles.SecureOpenBeneath(filepath.Dir(buildOut), filepath.Base(buildOut),
			unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, 0o600) // #nosec G304 -- operator-supplied output path, walked via SecureOpenBeneath
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
		if err := requireVerifyInstalledVersion(); err != nil {
			return err
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

		if err := requireImportInstalledVersion(); err != nil {
			return err
		}

		f, err := os.Open(args[0]) // #nosec G304 -- operator-supplied bundle path
		if err != nil {
			return fmt.Errorf("open bundle: %w", err)
		}
		defer func() { _ = f.Close() }()

		// Extract verifies the signature and the no-downgrade gate BEFORE writing anything,
		// then stages each verified component atomically. It fails closed.
		//
		// ExtractAllowingStateReset also reconciles importDest's internal marker against
		// the external install-state record kept outside importDest (see
		// ibundle.ErrInstallStateReset): a destination that looks like a fresh/first
		// install while the external record still remembers a previously-installed
		// version is refused unless --reset-install-state explicitly acknowledges it —
		// closing the gap where deleting the WHOLE --dest (not just its marker file)
		// would otherwise reset the no-downgrade gate with zero signal.
		m, err := ibundle.ExtractAllowingStateReset(f, reg, importDest, importInstalled, importResetState)
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

// requireVerifyInstalledVersion enforces that `bundle verify` gets an operator-supplied
// --installed-version before the no-downgrade / anti-skip (min-upgrade-from) check runs.
// `verify` is fully offline and stateless — unlike `import`, there is no staging directory
// to persist a marker in, so the flag is the ONLY input the check has (cli-project-001: it
// was previously optional with an empty default, which made ibundle.Manifest.CheckUpgrade
// silently no-op — a substituted, older-but-validly-signed bundle would then verify clean
// with no indication it's a downgrade). Skipping the check is still possible, but only as an
// explicit, auditable --force, never as the silent default.
func requireVerifyInstalledVersion() error {
	verifyInstalled = strings.TrimSpace(verifyInstalled)
	if verifyInstalled != "" {
		return nil
	}
	if !verifyForce {
		return fmt.Errorf("--installed-version is required to check the no-downgrade / anti-skip " +
			"(min-upgrade-from) guarantees for this deployment: pass --installed-version " +
			"<currently-running-version> (recommended — a substituted, older-but-validly-signed bundle " +
			"would otherwise verify cleanly with no warning that it's a downgrade). Re-run with --force to " +
			"verify only the signature and component digests, with no downgrade check")
	}
	fmt.Fprintln(os.Stderr, "WARNING: --installed-version was not supplied — proceeding with --force means "+
		"the no-downgrade and anti-skip (min-upgrade-from) checks are SKIPPED for this verification.")
	return nil
}

// requireImportInstalledVersion enforces that `bundle import` has *something* to anchor the
// no-downgrade / anti-skip (min-upgrade-from) check against before it opens or extracts the
// bundle. Unlike verify, import already has a fail-closed auto-discovery mechanism (#111):
// ibundle.Extract persists a version marker at --dest on every successful import and treats
// it as authoritative over this flag on the next one, so a routine re-import needs no flag at
// all. That mechanism only protects a destination that has already been imported into at
// least once, though — cli-project-001 is the gap on a FIRST import into a fresh/empty
// --dest, where --installed-version was merely optional with an empty default. An empty
// default there means ibundle.Manifest.CheckUpgrade silently no-ops, so the routine `keyorix
// bundle import --dest /stage <bundle>` invocation from the command's own help text staged a
// substituted, older-but-validly-signed bundle with zero downgrade protection. This makes
// that gap an explicit, auditable operator choice (--force) instead of a silent default.
//
// The marker-at---dest mechanism has its own gap, closed separately: it lives inside --dest,
// so deleting the whole directory (not just the marker file) resets it to "first install"
// with no signal. ibundle.PersistedInstalledVersionAllowingReset also checks an external
// install-state record kept outside --dest; a mismatch there surfaces as
// ibundle.ErrInstallStateReset, requiring --reset-install-state to proceed instead of being
// silently treated as an ordinary first install.
func requireImportInstalledVersion() error {
	importInstalled = strings.TrimSpace(importInstalled)
	if importInstalled != "" {
		return nil
	}
	_, hasMarker, err := ibundle.PersistedInstalledVersionAllowingReset(importDest, importResetState)
	if err != nil {
		if errors.Is(err, ibundle.ErrInstallStateReset) {
			return fmt.Errorf("import failed (fail-closed): %w. If --dest's install state was "+
				"intentionally reset (e.g. you deliberately cleared it for a fresh start), re-run with "+
				"--reset-install-state to proceed; otherwise treat this as a possible downgrade attempt "+
				"and investigate before proceeding", err)
		}
		return fmt.Errorf("import failed (fail-closed, nothing staged on a verify failure): %w", err)
	}
	if hasMarker {
		// A prior import already anchors the gate at this destination; ibundle.Extract will
		// read and enforce against that marker regardless of this (empty) flag value.
		return nil
	}
	if !importForce {
		return fmt.Errorf("--installed-version is required: no prior import was recorded at %q, so there is "+
			"nothing to anchor the no-downgrade / anti-skip (min-upgrade-from) check against. Pass "+
			"--installed-version <currently-running-version> (recommended — an attacker, a compromised "+
			"internal mirror, or a compromised artifact-staging host could otherwise substitute an older, "+
			"still validly-signed bundle and silently downgrade this deployment). If this really is a first "+
			"install with nothing yet to protect, re-run with --force to proceed without a downgrade check",
			importDest)
	}
	fmt.Fprintf(os.Stderr, "WARNING: --installed-version was not supplied and no prior import was found at %s "+
		"— proceeding with --force means the no-downgrade and anti-skip (min-upgrade-from) checks are SKIPPED "+
		"for this import.\n", importDest)
	return nil
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

	verifyCmd.Flags().StringVar(&verifyInstalled, "installed-version", "",
		"currently-installed version, to enforce no-downgrade / min-upgrade-from (required unless --force)")
	verifyCmd.Flags().BoolVar(&verifyForce, "force", false,
		"proceed without --installed-version (dangerous — skips the no-downgrade / anti-skip check, verifies signature and digests only)")

	importCmd.Flags().StringVar(&importDest, "dest", "", "directory to stage verified artifacts into (required)")
	importCmd.Flags().StringVar(&importInstalled, "installed-version", "",
		"currently-installed version, to enforce no-downgrade / min-upgrade-from (required on a first import into --dest, unless --force)")
	importCmd.Flags().BoolVar(&importForce, "force", false,
		"proceed without --installed-version on a first import into --dest (dangerous — skips the no-downgrade / anti-skip check)")
	importCmd.Flags().StringVar(&importLicense, "license", "", "path to the installed license token (bundle import is a commercial feature)")
	importCmd.Flags().BoolVar(&importResetState, "reset-install-state", false,
		"acknowledge that --dest's install state was intentionally reset (e.g. --dest was deliberately "+
			"cleared or recreated): required when the external install-state record disagrees with --dest "+
			"itself, otherwise refused as a possible downgrade-reset attempt. Does not disable the "+
			"no-downgrade check itself — combine with --installed-version or --force as usual")
	_ = importCmd.MarkFlagRequired("dest")

	BundleCmd.AddCommand(buildCmd)
	BundleCmd.AddCommand(verifyCmd)
	BundleCmd.AddCommand(importCmd)
}
