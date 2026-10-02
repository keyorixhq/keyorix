// insecure_settings_registry.go -- ADR-112 opt-out rule (secure-by-default
// baseline, item 2): the single registry of every security-weakening
// setting this codebase knows about. Three things read this registry:
//   - server/main.go logs a start-up warning for every entry currently
//     InEffect.
//   - server/main.go computes a SecurityPostureSnapshot and hands it to
//     internal/core's ReconcileSecurityPostureSnapshot, which diffs it
//     against the previous start's snapshot and audits any change.
//   - The future posture report (item 4) lists every InEffect entry as a
//     deviation.
//
// Each entry's Name always carries the insecure_ prefix, whether or not the
// underlying YAML key has actually been renamed yet (DeprecatedAlias is ""
// for a setting not yet renamed -- see insecure_settings_aliases.go for the
// ones that have been, and this PR's own description for the settings
// deliberately left un-renamed: NEEDS ANDREI because the rename would need
// either a polarity inversion of a load-bearing flag, or restructuring a
// non-boolean field (an enum string, an empty-string sentinel, a negative-
// number sentinel) into a real boolean, not a case this file's own renamer
// can resolve by itself without a product decision).
package config

// InsecureSetting is one entry in the ADR-112 opt-out-rule registry.
type InsecureSetting struct {
	// Name is this setting's canonical insecure_-prefixed dotted path --
	// used in the registry's own structural test, the start-up warning, and
	// the posture snapshot's keys. Stable across a future literal YAML
	// rename (DeprecatedAlias going from "" to a real old path never
	// changes Name), so the audit trail's setting identifiers never churn.
	Name string
	// DeprecatedAlias is the old dotted YAML path this setting was renamed
	// from, or "" when it was already compliant (ships with an insecure_
	// name already) or hasn't been renamed yet (see the package doc above).
	DeprecatedAlias string
	// Describe is a one-line, human-readable explanation of what being in
	// effect actually weakens, for the start-up warning and (eventually)
	// the posture report.
	Describe string
	// InEffect reports whether the weak state is active right now.
	InEffect func(*Config) bool
	// Value returns a short string form of the setting's current value, for
	// the start-to-start settings diff. Boolean-shaped for every entry here
	// ("true"/"false") since this item is explicitly scoped to boolean
	// settings; a future numeric/enum entry would still fit this shape.
	Value func(*Config) string
}

// boolStr renders a bool the same way for every registry entry's Value, so
// the settings-diff snapshot's string values are consistent across entries.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// keyProviderChain returns enc's primary key provider followed by its
// Fallbacks, in try-order -- the same list buildKeyProvider (internal/
// encryption/service.go) actually constructs a provider for. Settings on
// KeyProviderConfig (insecure_allow_kms_context_fallback,
// insecure_allow_weaker_kek_fallback, the Shamir commitment check) can be
// set on ANY entry in this chain, not just the primary, so "in effect" must
// check all of them -- one level of Fallbacks only, matching
// internal/keyfiles.Registry's identical, already-established choice (that
// package's own doc comment: "Fallbacks' own nested Fallbacks field is never
// read by buildSingleProvider either, so it is not a live configuration
// shape").
func keyProviderChain(enc *EncryptionConfig) []KeyProviderConfig {
	chain := make([]KeyProviderConfig, 0, 1+len(enc.KeyProvider.Fallbacks))
	chain = append(chain, enc.KeyProvider)
	chain = append(chain, enc.KeyProvider.Fallbacks...)
	return chain
}

// anyKeyProviderInEffect reports whether pred holds for any provider in cfg's
// key-provider chain.
func anyKeyProviderInEffect(cfg *Config, pred func(KeyProviderConfig) bool) bool {
	for _, kp := range keyProviderChain(&cfg.Storage.Encryption) {
		if pred(kp) {
			return true
		}
	}
	return false
}

// anySSOProviderInEffect reports whether pred holds for any configured SSO
// provider -- "in effect" for a per-provider setting means at least one
// provider actually has the weak state active, the same way a single
// insecure listener among several makes checkTransportTLSPosture's overall
// cleartext warning fire.
func anySSOProviderInEffect(cfg *Config, pred func(SSOProviderConfig) bool) bool {
	for _, p := range cfg.SSO.Providers {
		if pred(p) {
			return true
		}
	}
	return false
}

// InsecureSettingsRegistry is the single, shared enumeration every ADR-112
// opt-out-rule consumer (start-up warnings, the settings-diff audit, the
// future posture report) reads instead of hand-rolling its own list.
var InsecureSettingsRegistry = []InsecureSetting{
	// -- Renamed in this PR (DeprecatedAlias set) --
	{
		Name: "security.insecure_allow_unsafe_file_permissions", DeprecatedAlias: "security.allow_unsafe_file_permissions",
		Describe: "lets group/other-readable key material pass enforceKeyFilePermissions/ValidateStartup instead of failing closed",
		InEffect: func(c *Config) bool { return c.Security.AllowUnsafeFilePermissions },
		Value:    func(c *Config) string { return boolStr(c.Security.AllowUnsafeFilePermissions) },
	},
	{
		Name: "security.login_lockout.insecure_disable_login_lockout", DeprecatedAlias: "security.login_lockout.disabled",
		Describe: "removes per-account brute-force lockout protection",
		InEffect: func(c *Config) bool { return c.Security.LoginLockout.Disabled },
		Value:    func(c *Config) string { return boolStr(c.Security.LoginLockout.Disabled) },
	},
	{
		Name: "security.recover_admin.insecure_keyless_admin_recovery", DeprecatedAlias: "security.recover_admin.keyless_mode",
		Describe: "lets `recover-admin` restore any admin on host access alone, with no recovery key",
		InEffect: func(c *Config) bool { return c.Security.RecoverAdmin.KeylessMode },
		Value:    func(c *Config) string { return boolStr(c.Security.RecoverAdmin.KeylessMode) },
	},
	{
		Name: "audit.siem.insecure_allow_private_network_siem_target", DeprecatedAlias: "audit.siem.allow_private_network_target",
		Describe: "disables the SSRF guard on the SIEM forwarder's endpoint",
		InEffect: func(c *Config) bool { return c.Audit.SIEM.AllowPrivateNetworkTarget },
		Value:    func(c *Config) string { return boolStr(c.Audit.SIEM.AllowPrivateNetworkTarget) },
	},
	{
		Name: "audit.siem.insecure_allow_plaintext_siem_transport", DeprecatedAlias: "audit.siem.allow_insecure_transport",
		Describe: "permits a plaintext (non-TLS) SIEM forwarder endpoint",
		InEffect: func(c *Config) bool { return c.Audit.SIEM.AllowInsecureTransport },
		Value:    func(c *Config) string { return boolStr(c.Audit.SIEM.AllowInsecureTransport) },
	},
	{
		Name: "evidence_delivery.webhook.insecure_allow_private_network_evidence_target", DeprecatedAlias: "evidence_delivery.webhook.allow_private_network_target",
		Describe: "disables the SSRF guard on the evidence-delivery webhook's endpoint",
		InEffect: func(c *Config) bool { return c.EvidenceDelivery.Webhook.AllowPrivateNetworkTarget },
		Value:    func(c *Config) string { return boolStr(c.EvidenceDelivery.Webhook.AllowPrivateNetworkTarget) },
	},
	{
		Name: "evidence_delivery.webhook.insecure_allow_plaintext_evidence_transport", DeprecatedAlias: "evidence_delivery.webhook.allow_insecure_transport",
		Describe: "permits a plaintext (non-TLS) evidence-delivery webhook endpoint",
		InEffect: func(c *Config) bool { return c.EvidenceDelivery.Webhook.AllowInsecureTransport },
		Value:    func(c *Config) string { return boolStr(c.EvidenceDelivery.Webhook.AllowInsecureTransport) },
	},
	{
		Name: "notifications.webhook.insecure_allow_private_network_notify_target", DeprecatedAlias: "notifications.webhook.allow_private_network_target",
		Describe: "disables the SSRF guard on the notification webhook's endpoint",
		InEffect: func(c *Config) bool { return c.Notifications.Webhook.AllowPrivateNetworkTarget },
		Value:    func(c *Config) string { return boolStr(c.Notifications.Webhook.AllowPrivateNetworkTarget) },
	},
	{
		Name: "notifications.webhook.insecure_allow_plaintext_notify_transport", DeprecatedAlias: "notifications.webhook.allow_insecure_transport",
		Describe: "permits a plaintext (non-TLS) notification webhook endpoint",
		InEffect: func(c *Config) bool { return c.Notifications.Webhook.AllowInsecureTransport },
		Value:    func(c *Config) string { return boolStr(c.Notifications.Webhook.AllowInsecureTransport) },
	},
	{
		Name: "dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets", DeprecatedAlias: "dynamic_secrets.allow_private_network_targets",
		Describe: "disables the SSRF guard on dynamic-secret backend DSNs (Postgres/MySQL/Mongo/Redis)",
		InEffect: func(c *Config) bool { return c.DynamicSecrets.AllowPrivateNetworkTargets },
		Value:    func(c *Config) string { return boolStr(c.DynamicSecrets.AllowPrivateNetworkTargets) },
	},
	{
		Name: "dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport", DeprecatedAlias: "dynamic_secrets.allow_insecure_transport",
		Describe: "disables the required-TLS guard for mongodb/redis dynamic-secret backends",
		InEffect: func(c *Config) bool { return c.DynamicSecrets.AllowInsecureTransport },
		Value:    func(c *Config) string { return boolStr(c.DynamicSecrets.AllowInsecureTransport) },
	},
	{
		Name: "storage.encryption.key_provider.insecure_allow_kms_context_fallback", DeprecatedAlias: "storage.encryption.key_provider.kms_allow_context_fallback",
		Describe: "lets a context-bound KMS-wrapped KEK fall back to decrypting with no context",
		InEffect: func(c *Config) bool {
			return anyKeyProviderInEffect(c, func(kp KeyProviderConfig) bool { return kp.KMSAllowContextFallback })
		},
		Value: func(c *Config) string {
			return boolStr(anyKeyProviderInEffect(c, func(kp KeyProviderConfig) bool { return kp.KMSAllowContextFallback }))
		},
	},
	{
		Name: "storage.encryption.key_provider.insecure_allow_weaker_kek_fallback", DeprecatedAlias: "storage.encryption.key_provider.allow_weaker_fallback",
		Describe: "permits a key-provider fallback chain that silently downgrades KEK-sourcing strength",
		InEffect: func(c *Config) bool {
			return anyKeyProviderInEffect(c, func(kp KeyProviderConfig) bool { return kp.AllowWeakerFallback })
		},
		Value: func(c *Config) string {
			return boolStr(anyKeyProviderInEffect(c, func(kp KeyProviderConfig) bool { return kp.AllowWeakerFallback }))
		},
	},
	{
		Name: "sso.providers.insecure_trust_saml_asserted_email", DeprecatedAlias: "sso.providers[].trust_asserted_email",
		Describe: "treats a SAML provider's self-asserted email as verified for account-linking (account-takeover risk)",
		InEffect: func(c *Config) bool {
			return anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.TrustAssertedEmail })
		},
		Value: func(c *Config) string {
			return boolStr(anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.TrustAssertedEmail }))
		},
	},
	{
		Name: "sso.providers.saml.insecure_allow_idp_initiated_saml", DeprecatedAlias: "sso.providers[].saml.allow_idp_initiated",
		Describe: "accepts SAML responses with no InResponseTo, losing CSRF/replay protection (validateSSOIDPInitiated already refuses this at boot -- see its own doc comment)",
		InEffect: func(c *Config) bool {
			return anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.SAML != nil && p.SAML.AllowIDPInitiated })
		},
		Value: func(c *Config) string {
			return boolStr(anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.SAML != nil && p.SAML.AllowIDPInitiated }))
		},
	},
	{
		Name: "audit_checkpoints.insecure_disable_audit_checkpoints", DeprecatedAlias: "audit_checkpoints.disabled",
		Describe: "leaves the audit trail only tamper-evident, not forgery-resistant (no signed checkpoints)",
		InEffect: func(c *Config) bool { return c.AuditCheckpoints.Disabled },
		Value:    func(c *Config) string { return boolStr(c.AuditCheckpoints.Disabled) },
	},

	// -- Already compliant: ships with an insecure_ name, nothing to rename --
	{
		Name:     "audit.siem.insecure_skip_verify",
		Describe: "disables TLS certificate verification to the SIEM endpoint",
		InEffect: func(c *Config) bool { return c.Audit.SIEM.InsecureSkipVerify },
		Value:    func(c *Config) string { return boolStr(c.Audit.SIEM.InsecureSkipVerify) },
	},
	{
		Name:     "evidence_delivery.webhook.insecure_skip_verify",
		Describe: "disables TLS certificate verification to the evidence-delivery webhook endpoint",
		InEffect: func(c *Config) bool { return c.EvidenceDelivery.Webhook.InsecureSkipVerify },
		Value:    func(c *Config) string { return boolStr(c.EvidenceDelivery.Webhook.InsecureSkipVerify) },
	},
	{
		Name:     "notifications.webhook.insecure_skip_verify",
		Describe: "disables TLS certificate verification to the notification webhook endpoint",
		InEffect: func(c *Config) bool { return c.Notifications.Webhook.InsecureSkipVerify },
		Value:    func(c *Config) string { return boolStr(c.Notifications.Webhook.InsecureSkipVerify) },
	},

	// -- NEEDS ANDREI: derived-only for now (see this PR's description for why
	//    each one isn't a mechanical rename). Still fully covered by the
	//    start-up warning and the settings-diff audit under its current name. --
	{
		Name:     "security.insecure_allow_cleartext_transport",
		Describe: "NEEDS ANDREI (polarity-inverted rename of security.require_transport_tls, a load-bearing flag item 1 also touches) -- allows bearer tokens/secret values over cleartext HTTP/gRPC",
		InEffect: func(c *Config) bool { return !c.Security.RequireTransportTLS },
		Value:    func(c *Config) string { return boolStr(!c.Security.RequireTransportTLS) },
	},
	{
		Name:     "security.insecure_skip_startup_validation",
		Describe: "NEEDS ANDREI (polarity-inverted rename of security.enable_file_permission_check, which item 1 just gave ADR-112 default-flip + grace-period machinery under its current name) -- skips the file-permission/DEK-salt-size/database-reachability startup checks",
		InEffect: func(c *Config) bool { return !c.Security.EnableFilePermissionCheck },
		Value:    func(c *Config) string { return boolStr(!c.Security.EnableFilePermissionCheck) },
	},
	{
		Name:     "storage.encryption.key_provider.insecure_omit_shamir_commitment_check",
		Describe: "NEEDS ANDREI (not a boolean today -- an empty storage.encryption.key_provider.shamir_commitment string) -- Shamir KEK reconstruction falls back to a forgeable magic-byte check only",
		InEffect: func(c *Config) bool {
			return anyKeyProviderInEffect(c, func(kp KeyProviderConfig) bool { return kp.Type == "shamir" && kp.ShamirCommitment == "" })
		},
		Value: func(c *Config) string {
			return boolStr(anyKeyProviderInEffect(c, func(kp KeyProviderConfig) bool { return kp.Type == "shamir" && kp.ShamirCommitment == "" }))
		},
	},
	{
		Name:     "storage.encryption.insecure_disable_encryption_at_rest",
		Describe: "NEEDS ANDREI (polarity-inverted rename of storage.encryption.enabled, a high-blast-radius architectural flag, not purely a weakening toggle) -- secrets stored unencrypted at rest",
		InEffect: func(c *Config) bool { return !c.Storage.Encryption.Enabled },
		Value:    func(c *Config) string { return boolStr(!c.Storage.Encryption.Enabled) },
	},
	{
		Name:     "membership.insecure_skip_membership_review",
		Describe: "NEEDS ANDREI (not a boolean today -- membership.validation_mode is a 2-value enum, \"allowlist\"/\"open\") -- new members become active immediately, skipping admin review",
		InEffect: func(c *Config) bool { return c.Membership.ValidationMode == "open" },
		Value:    func(c *Config) string { return boolStr(c.Membership.ValidationMode == "open") },
	},
	{
		Name:     "sso.providers.insecure_auto_provision_sso_users",
		Describe: "NEEDS ANDREI (the gap check itself flags this as borderline -- a legitimate feature flag as much as a weakening) -- JIT-creates an SSO account with no admin step",
		InEffect: func(c *Config) bool {
			return anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.AutoProvision })
		},
		Value: func(c *Config) string {
			return boolStr(anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.AutoProvision }))
		},
	},
	{
		Name:     "sso.providers.insecure_auto_sync_sso_groups",
		Describe: "NEEDS ANDREI (the gap check itself flags this as borderline -- delegated trust, not a pure weakening) -- IdP group claims silently change native role membership every login",
		InEffect: func(c *Config) bool {
			return anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.GroupSync })
		},
		Value: func(c *Config) string {
			return boolStr(anySSOProviderInEffect(c, func(p SSOProviderConfig) bool { return p.GroupSync }))
		},
	},
	{
		Name:     "server.insecure_allow_unauthenticated_metrics",
		Describe: "NEEDS ANDREI (not a boolean today -- an empty server.http/grpc.metrics_token string) -- /metrics served fully unauthenticated",
		InEffect: func(c *Config) bool { return c.Server.HTTP.MetricsToken == "" || c.Server.GRPC.MetricsToken == "" },
		Value: func(c *Config) string {
			return boolStr(c.Server.HTTP.MetricsToken == "" || c.Server.GRPC.MetricsToken == "")
		},
	},
	{
		Name:     "server.insecure_disable_max_request_body_cap",
		Describe: "NEEDS ANDREI (not a boolean today -- a negative server.http/grpc.max_request_body_bytes) -- removes the request-body size cap entirely (DoS)",
		InEffect: func(c *Config) bool {
			return c.Server.HTTP.MaxRequestBodyBytes < 0 || c.Server.GRPC.MaxRequestBodyBytes < 0
		},
		Value: func(c *Config) string {
			return boolStr(c.Server.HTTP.MaxRequestBodyBytes < 0 || c.Server.GRPC.MaxRequestBodyBytes < 0)
		},
	},
	{
		Name:     "storage.database.insecure_disable_database_tls",
		Describe: "NEEDS ANDREI (not a boolean today -- storage.database.ssl_mode is a 3-value enum) -- Postgres connection unencrypted",
		InEffect: func(c *Config) bool { return c.Storage.Database.SSLMode == "disable" },
		Value:    func(c *Config) string { return boolStr(c.Storage.Database.SSLMode == "disable") },
	},
	{
		Name:     "server.insecure_disable_api_ratelimit",
		Describe: "NEEDS ANDREI (polarity-inverted rename, AND already ships disabled by default -- the same inverted-default shape item 1 fixed for two other settings; this one needs the same product decision) -- removes per-principal API rate limiting",
		InEffect: func(c *Config) bool { return !c.Server.HTTP.RateLimit.Enabled || !c.Server.GRPC.RateLimit.Enabled },
		Value: func(c *Config) string {
			return boolStr(!c.Server.HTTP.RateLimit.Enabled || !c.Server.GRPC.RateLimit.Enabled)
		},
	},
	{
		Name:     "credential_delivery.insecure_allow_log_delivery",
		Describe: "NEEDS ANDREI (not a boolean today -- credential_delivery.mode is a 4-value enum, already double-gated by KEYORIX_ALLOW_INSECURE_LOG_DELIVERY) -- writes a usable account-setup link to the application log",
		InEffect: func(c *Config) bool { return c.CredentialDelivery.Mode == "log" },
		Value:    func(c *Config) string { return boolStr(c.CredentialDelivery.Mode == "log") },
	},
	{
		Name:     "credential_delivery.insecure_allow_plaintext_smtp",
		Describe: "NEEDS ANDREI (not a boolean today -- credential_delivery.smtp.tls / notifications.email.tls are 3-value enums, already double-gated by KEYORIX_ALLOW_INSECURE_SMTP) -- sends setup/notification mail over cleartext SMTP",
		InEffect: func(c *Config) bool {
			return c.CredentialDelivery.SMTP.TLS == "none" || c.Notifications.Email.TLS == "none"
		},
		Value: func(c *Config) string {
			return boolStr(c.CredentialDelivery.SMTP.TLS == "none" || c.Notifications.Email.TLS == "none")
		},
	},
}
