package crypto

// ProviderTier ranks how resistant a key-provider TYPE is to a full compromise of
// the process/host it runs on — used to detect a MultiKeyProvider fallback chain
// that would silently trade a stronger KEK source for a weaker one. Higher value =
// stronger. This is an ORDERING for fallback-safety purposes, not an absolute
// security score: a "distributed" provider (Shamir) is harder to compromise than a
// single software secret because no ONE piece of key material suffices on its own,
// but it still doesn't isolate key material inside dedicated hardware the way
// TPM/HSM/cloud-KMS providers do.
type ProviderTier int

const (
	// TierUnknown is returned for a provider name/type this package has no
	// classification for. It sorts BELOW every known tier (weakest), not above, so
	// an unrecognized provider is conservatively treated as capable of being a
	// downgrade target — fail closed instead of silently exempting an unclassified
	// provider from the fallback-strength check.
	TierUnknown ProviderTier = iota
	// TierSoftware covers providers whose key material is a flat secret sitting in
	// local software state — a passphrase, a file, an env var, or whatever an
	// arbitrary exec resolver prints to stdout — extractable by anyone who can read
	// the process's environment, filesystem, or memory.
	TierSoftware
	// TierDistributed covers Shamir: the KEK is split across K-of-N shares, so
	// compromising any single share below the threshold reveals nothing about it.
	// Meaningfully harder to compromise than one flat software secret, but the
	// reconstructed KEK still passes through this process's memory like a software
	// provider's once the shares are combined.
	TierDistributed
	// TierHardware covers providers whose key material is sealed to a dedicated
	// hardware boundary (TPM 2.0) or wrapped by a cloud KMS key that never leaves
	// the provider's HSM (aws-kms/gcp-kms/azure-kms) — the strongest class of
	// provider this package supports.
	TierHardware
)

// String renders the tier for operator-facing error/log messages.
func (t ProviderTier) String() string {
	switch t {
	case TierHardware:
		return "hardware-backed"
	case TierDistributed:
		return "distributed"
	case TierSoftware:
		return "software-derivable"
	default:
		return "unknown"
	}
}

// providerTiers classifies every built-in provider TYPE by its Name()/config
// "type" string — the two are identical for every provider this package ships
// (see each provider's Name() method: NewKMSKeyProvider is constructed with
// "aws-kms"/"gcp-kms"/"azure-kms", TPMKeyProvider.Name() == "tpm",
// PasswordKeyProvider.Name() == "password", etc.), so this one table serves both
// the config-validation path (keyed by the config "type" string) and the
// KEK()-time runtime path (keyed by the constructed provider's Name()).
var providerTiers = map[string]ProviderTier{
	"password":  TierSoftware,
	"file":      TierSoftware,
	"env":       TierSoftware,
	"exec":      TierSoftware,
	"shamir":    TierDistributed,
	"tpm":       TierHardware,
	"aws-kms":   TierHardware,
	"gcp-kms":   TierHardware,
	"azure-kms": TierHardware,
}

// ProviderTierOf returns the strength tier for a provider type/name. Unrecognized
// names return TierUnknown (see its doc comment for why that is the weakest tier,
// not a neutral/exempt one).
func ProviderTierOf(name string) ProviderTier {
	if t, ok := providerTiers[name]; ok {
		return t
	}
	return TierUnknown
}

// FallbackDowngrade describes the first point in a provider chain (primary +
// fallbacks, in configured try-order) where the tier drops below the strongest
// tier seen so far in the chain.
type FallbackDowngrade struct {
	// Index is the position of the weaker provider in the FULL chain passed to
	// DetectFallbackDowngrade (0 = primary, matching providers[Index]).
	Index int
	// Provider is providers[Index].Name().
	Provider string
	// FromTier is the strongest tier seen among providers[0:Index].
	FromTier ProviderTier
	// ToTier is ProviderTierOf(providers[Index].Name()).
	ToTier ProviderTier
}

// DetectFallbackDowngrade scans a provider chain (as passed to
// NewMultiKeyProvider: providers[0] is the primary, providers[1:] are fallbacks in
// try-order) and reports the FIRST provider whose tier is weaker than the
// strongest tier seen among every provider before it in the chain. Returns
// ok=false if the chain never weakens — this includes empty/single-provider
// chains, and chains that only stay flat or get stronger (e.g. a KMS primary with
// a KMS-in-a-different-region fallback, or a password primary with a
// stronger-tier fallback added on top).
func DetectFallbackDowngrade(providers []KeyProvider) (downgrade FallbackDowngrade, ok bool) {
	if len(providers) < 2 {
		return FallbackDowngrade{}, false
	}
	maxTier := ProviderTierOf(providers[0].Name())
	for i := 1; i < len(providers); i++ {
		t := ProviderTierOf(providers[i].Name())
		if t < maxTier {
			return FallbackDowngrade{Index: i, Provider: providers[i].Name(), FromTier: maxTier, ToTier: t}, true
		}
		if t > maxTier {
			maxTier = t
		}
	}
	return FallbackDowngrade{}, false
}
