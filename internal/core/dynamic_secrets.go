// dynamic_secrets.go — on-demand database credentials (ADR-035): an operator
// registers a target (DynamicSecretConfig); callers issue short-lived leases that
// mint a role on the target; an auto-revoke sweep drops them at expiry. The admin
// DSN and each issued credential are encrypted at rest.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const defaultDynamicTTL = 1 * time.Hour

// defaultMaxLeaseTTL is the install-wide lease TTL ceiling used when
// KeyorixCore.dynamicMaxLeaseTTL is unset (mirrors config.DynamicSecretsConfig's
// own default so behaviour is identical whether or not the server wired
// SetDynamicMaxLeaseTTL, e.g. in tests that construct KeyorixCore directly).
const defaultMaxLeaseTTL = 90 * 24 * time.Hour

// CreateDynamicSecretConfigRequest registers a dynamic-secrets target.
type CreateDynamicSecretConfigRequest struct {
	Name              string
	ProjectID         uint
	EnvironmentID     uint
	BackendType       string
	AdminDSN          string
	CreationTemplate  string
	DefaultTTLSeconds int
	MaxTTLSeconds     int
	MaxActiveLeases   int
	CreatedBy         string
	// ActorID is the authenticated caller, used for the admin-authority check on
	// binding a backend (#162) — CreatedBy is a display username, not a resolvable
	// principal ID.
	ActorID uint
	// Classification is an optional data-sensitivity label (A.5.12) for the
	// credentials this config mints: "" or one of public|internal|confidential|restricted.
	Classification string
}

// IssuedLease is the credential returned to the caller once, on issue. Database
// backends populate Username/Password; cloud-IAM backends (AWS STS) leave those
// empty and populate Fields (access_key_id, secret_access_key, session_token, …).
type IssuedLease struct {
	LeaseID   string            `json:"lease_id"`
	Username  string            `json:"username,omitempty"`
	Password  string            `json:"password,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
	ExpiresAt time.Time         `json:"expires_at"`
}

// CreateDynamicSecretConfig validates the backend, encrypts the admin DSN, and
// stores the config.
func (c *KeyorixCore) CreateDynamicSecretConfig(ctx context.Context, req *CreateDynamicSecretConfigRequest) (*models.DynamicSecretConfig, error) {
	if req.Name == "" || req.ProjectID == 0 || req.AdminDSN == "" {
		return nil, fmt.Errorf("name, project_id and admin_dsn are required")
	}
	if _, err := c.dynamicEngine(req.BackendType); err != nil {
		return nil, err
	}
	// #162: binding a backend hands out standing access to mint live credentials
	// against it (a DB admin DSN or a cloud-IAM role) — the route only requires
	// secrets.write at the project/environment scope, which is too weak a gate for
	// that authority on its own (exact sibling of #90's rotation-backend check).
	ids, err := c.scopedRoleIDs(ctx, req.ActorID, Scope{ProjectID: req.ProjectID, EnvironmentID: req.EnvironmentID})
	if err != nil {
		return nil, fmt.Errorf("failed to resolve actor authority: %w", err)
	}
	if !c.roleSetContainsAdmin(ctx, ids) {
		return nil, fmt.Errorf("binding a dynamic-secret backend requires admin authority on this project")
	}
	if req.MaxTTLSeconds > 0 && req.DefaultTTLSeconds > req.MaxTTLSeconds {
		return nil, fmt.Errorf("default_ttl_seconds (%d) cannot exceed max_ttl_seconds (%d)", req.DefaultTTLSeconds, req.MaxTTLSeconds)
	}
	if !IsValidClassification(req.Classification) {
		return nil, fmt.Errorf("classification must be one of public, internal, confidential, restricted (or empty)")
	}
	// #94: the admin DSN is encrypted bound to DynamicSecretConfigAAD(cfg.ID, ...), so
	// it must be encrypted AFTER the row exists (cfg.ID is an auto-increment PK, not
	// known beforehand) — insert first with the DSN columns empty, then encrypt and
	// persist them in a second write. The gap between the two writes is invisible to
	// any other caller: cfg.ID isn't returned to the requester until this function
	// returns, so nothing else can observe or race the momentarily-DSN-less row.
	cfg, err := c.storage.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name:              req.Name,
		ProjectID:         req.ProjectID,
		EnvironmentID:     req.EnvironmentID,
		BackendType:       req.BackendType,
		CreationTemplate:  req.CreationTemplate,
		DefaultTTLSeconds: req.DefaultTTLSeconds,
		MaxTTLSeconds:     req.MaxTTLSeconds,
		MaxActiveLeases:   req.MaxActiveLeases,
		Classification:    req.Classification,
		CreatedBy:         req.CreatedBy,
		CreatedAt:         c.now(),
		UpdatedAt:         c.now(),
	})
	if err != nil {
		return nil, err
	}
	dsnEnc, dsnMeta, err := c.encryptAuthSecret(req.AdminDSN, encryption.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt admin DSN: %w", err)
	}
	cfg.AdminDSNEnc = dsnEnc
	cfg.AdminDSNMeta = dsnMeta
	if err := c.storage.UpdateDynamicSecretConfig(ctx, cfg); err != nil {
		return nil, fmt.Errorf("failed to persist encrypted admin DSN: %w", err)
	}
	pid := cfg.ProjectID
	c.writeAuditEventFull(ctx, "dynamic_secret.config_created", nil, nil, &pid, "",
		fmt.Sprintf("dynamic-secret config %q (%s) created in project %d", cfg.Name, cfg.BackendType, cfg.ProjectID))
	return cfg, nil
}

func (c *KeyorixCore) GetDynamicSecretConfig(ctx context.Context, id uint) (*models.DynamicSecretConfig, error) {
	return c.storage.GetDynamicSecretConfig(ctx, id)
}

func (c *KeyorixCore) ListDynamicSecretConfigs(ctx context.Context, projectID, environmentID uint) ([]*models.DynamicSecretConfig, error) {
	return c.storage.ListDynamicSecretConfigs(ctx, projectID, environmentID)
}

// ClassifyDynamicSecretConfig sets (or clears, with "") the data-classification
// label on a dynamic-secret config and audits the change with a before/after diff.
func (c *KeyorixCore) ClassifyDynamicSecretConfig(ctx context.Context, actorID uint, configID uint, level string) (*models.DynamicSecretConfig, error) {
	if configID == 0 {
		return nil, fmt.Errorf("config id is required")
	}
	if !IsValidClassification(level) {
		return nil, fmt.Errorf("classification must be one of public, internal, confidential, restricted (or empty to clear)")
	}
	cfg, err := c.storage.GetDynamicSecretConfig(ctx, configID)
	if err != nil {
		return nil, fmt.Errorf("dynamic-secret config not found: %w", err)
	}
	if cfg.Classification == level {
		return cfg, nil // no-op
	}
	old := cfg.Classification
	cfg.Classification = level
	cfg.UpdatedAt = c.now()
	if err := c.storage.UpdateDynamicSecretConfig(ctx, cfg); err != nil {
		return nil, err
	}
	aid := actorID
	pid := cfg.ProjectID
	diff := fmt.Sprintf(`{"classification":{"before":%q,"after":%q}}`, old, level)
	c.writeAuditEventDiff(ctx, "dynamic_secret.config_classified", &aid, nil, &pid, "",
		fmt.Sprintf("dynamic-secret config %q classification set to %q", cfg.Name, level), diff)
	return cfg, nil
}

func (c *KeyorixCore) ListDynamicSecretLeases(ctx context.Context, configID uint) ([]*models.DynamicSecretLease, error) {
	return c.storage.ListDynamicSecretLeases(ctx, configID)
}

func (c *KeyorixCore) GetDynamicSecretLease(ctx context.Context, leaseID string) (*models.DynamicSecretLease, error) {
	return c.storage.GetDynamicSecretLease(ctx, leaseID)
}

// IssueLease mints a short-lived credential on the target and persists the lease.
// The plaintext credential is returned ONCE; only its encrypted form is stored.
// ttlSeconds<=0 uses the config default (or 1h).
//
// LOW (#97): a genuine process crash (SIGKILL/OOM/panic bypassing defers) between
// engine.Issue minting the credential on the target and this function persisting the
// lease row leaves an orphan invisible to every list/revoke/sweep path (all keyed off
// the lease table) — cleanupOrphanedRole only covers synchronous Go-level errors
// returned by the steps AFTER Issue, not a hard crash. Fully closing this needs
// crash-safe two-phase persistence (write a pre-mint marker, reconcile it against the
// target on restart) across all 8 backend engines — out of proportion for a LOW
// finding. The log line below is a partial mitigation: it gives an operator a
// searchable breadcrumb (config, backend, target-ish role hint) to correlate against
// server logs during incident response if a mint never resulted in a lease row.
func (c *KeyorixCore) IssueLease(ctx context.Context, configID uint, ttlSeconds int, userID uint) (*IssuedLease, error) {
	cfg, err := c.storage.GetDynamicSecretConfig(ctx, configID)
	if err != nil {
		return nil, fmt.Errorf("dynamic-secret config not found")
	}
	engine, err := c.dynamicEngine(cfg.BackendType)
	if err != nil {
		return nil, err
	}
	// A backend with no DB-level expiry (MySQL/MongoDB) relies entirely on the
	// auto-revoke sweeper to enforce the lease TTL. Issuing from it while the
	// sweeper is disabled would mint a credential whose advertised expiry is never
	// enforced — a false promise — so refuse and point the operator at the fix.
	if !engine.SupportsNativeExpiry() && !c.dynamicSweepEnabled {
		return nil, fmt.Errorf("cannot issue from the %s backend while the auto-revoke sweeper is disabled: its lease TTL is enforced only by the sweeper, so the credential would never expire — enable dynamic_secrets.sweep_enabled", cfg.BackendType)
	}
	// Enforce the config's active-lease ceiling so a caller can't mint unbounded real DB
	// roles/users (resource exhaustion on the target). A small race under concurrency is
	// acceptable for a soft resource cap.
	if cfg.MaxActiveLeases > 0 {
		active, cerr := c.storage.CountActiveLeases(ctx, configID)
		if cerr != nil {
			return nil, fmt.Errorf("failed to check active lease count: %w", cerr)
		}
		if active >= int64(cfg.MaxActiveLeases) {
			return nil, fmt.Errorf("active-lease limit reached for this config (%d); revoke a lease before issuing another", cfg.MaxActiveLeases)
		}
	}
	adminDSN, err := c.decryptAuthSecret(cfg.AdminDSNEnc, cfg.AdminDSNMeta, encryption.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt admin DSN: %w", err)
	}
	ttl := c.dynamicTTL(cfg, ttlSeconds)

	// Logged BEFORE the mint (not after) so the breadcrumb survives a crash during or
	// immediately after engine.Issue — see the crash-orphan note on IssueLease's doc
	// comment (#97).
	log.Printf("dynamic-secrets: issuing a %s credential (config=%q id=%d project=%d ttl=%s)", cfg.BackendType, cfg.Name, cfg.ID, cfg.ProjectID, ttl)
	cred, roleName, err := engine.Issue(ctx, adminDSN, cfg.CreationTemplate, ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to issue credential: %w", err)
	}
	// leaseID is generated BEFORE encryption (not after, as in the pre-#94 order) so
	// DynamicSecretLeaseAAD can bind the credential's ciphertext to it — leaseID is a
	// random token assigned by us, not an auto-increment PK, so it's available without
	// a two-phase insert-then-update (contrast CreateDynamicSecretConfig above).
	leaseID, err := generateSecureToken()
	if err != nil {
		c.cleanupOrphanedRole(ctx, cfg, engine, adminDSN, roleName, userID)
		return nil, err
	}
	credJSON, _ := json.Marshal(cred) // #nosec G117 -- intentional: serialized only to be immediately encrypted at rest below, never persisted or logged in cleartext
	credEnc, credMeta, err := c.encryptAuthSecret(string(credJSON), encryption.DynamicSecretLeaseAAD(leaseID, cfg.ID))
	if err != nil {
		// The role exists on the target — revoke it so we don't leak it.
		c.cleanupOrphanedRole(ctx, cfg, engine, adminDSN, roleName, userID)
		return nil, fmt.Errorf("failed to encrypt credential: %w", err)
	}
	// #97: cloud-IAM engines (AWS STS, Kubernetes) floor the REQUESTED ttl up to their
	// own provider minimum (900s/600s) when minting, so the credential returned is
	// valid for longer than a short-ttl caller asked for — but ExpiresAt computed from
	// the requested ttl alone would understate that, making Keyorix believe (and the
	// auto-revoke sweep act on) an earlier expiry than the credential's true,
	// provider-enforced one. Both engines surface the actual granted expiry in
	// cred.Fields["expiration"] (RFC3339); trust it over the requested-ttl computation
	// whenever the engine provides it.
	expiresAt := c.now().Add(ttl)
	if raw := cred.Fields["expiration"]; raw != "" {
		if actual, perr := time.Parse(time.RFC3339, raw); perr == nil {
			expiresAt = actual
		}
	}
	lease, err := c.storage.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		ConfigID:       cfg.ID,
		LeaseID:        leaseID,
		ProjectID:      cfg.ProjectID,
		EnvironmentID:  cfg.EnvironmentID,
		RoleName:       roleName,
		CredentialEnc:  credEnc,
		CredentialMeta: credMeta,
		Status:         "active",
		IssuedAt:       c.now(),
		ExpiresAt:      expiresAt,
	})
	if err != nil {
		c.cleanupOrphanedRole(ctx, cfg, engine, adminDSN, roleName, userID)
		return nil, fmt.Errorf("failed to persist lease: %w", err)
	}
	uid := userID
	pid := cfg.ProjectID
	c.writeAuditEventFull(ctx, "dynamic_lease.issued", &uid, nil, &pid, "",
		fmt.Sprintf("issued dynamic credential (lease=%s, config=%q, ttl=%s)", lease.LeaseID, cfg.Name, ttl))
	return &IssuedLease{LeaseID: lease.LeaseID, Username: cred.Username, Password: cred.Password, Fields: cred.Fields, ExpiresAt: expiresAt}, nil
}

// cleanupOrphanedRole drops a just-minted role after a post-mint failure aborts the
// issue (encryption / token-gen / lease-persist failed). If the drop itself fails,
// the role would otherwise be a LIVE credential with no lease row — invisible to
// every list/sweep/revoke path (all keyed off the lease table) and therefore
// permanent and undrop-able. To keep it visible, we record a revoke_failed lease
// capturing the role name and audit it, mirroring RevokeLease's failure handling.
func (c *KeyorixCore) cleanupOrphanedRole(ctx context.Context, cfg *models.DynamicSecretConfig, engine dynamic.CredentialEngine, adminDSN, roleName string, userID uint) {
	if err := engine.Revoke(ctx, adminDSN, roleName); err == nil {
		return // role dropped cleanly — nothing to track
	} else {
		now := c.now()
		leaseID, gerr := generateSecureToken()
		if gerr != nil {
			leaseID = "orphan-" + roleName // last-resort id so the row still persists
		}
		// No credential is stored — the issue was aborted; only the role name
		// matters so an operator can drop it. CredentialEnc is intentionally empty.
		_, _ = c.storage.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
			ConfigID:      cfg.ID,
			LeaseID:       leaseID,
			ProjectID:     cfg.ProjectID,
			EnvironmentID: cfg.EnvironmentID,
			RoleName:      roleName,
			Status:        "revoke_failed",
			RevokeError:   "orphaned on aborted issue: " + err.Error(),
			IssuedAt:      now,
			ExpiresAt:     now,
			RevokedAt:     &now,
		})
		var uidPtr *uint
		if userID != 0 {
			uidPtr = &userID
		}
		var pidPtr *uint
		if cfg.ProjectID != 0 {
			pid := cfg.ProjectID
			pidPtr = &pid
		}
		c.writeAuditEventFull(ctx, "dynamic_lease.revoke_failed", uidPtr, nil, pidPtr, "",
			fmt.Sprintf("FAILED to clean up orphaned dynamic role %s after an aborted issue (config=%q): %v — drop it manually", roleName, cfg.Name, err))
	}
}

// RevokeLease revokes a lease on the target and marks it revoked (or
// revoke_failed if the target drop fails, surfacing it to an operator).
func (c *KeyorixCore) RevokeLease(ctx context.Context, leaseID string, userID uint, reason string) error {
	lease, err := c.storage.GetDynamicSecretLease(ctx, leaseID)
	if err != nil {
		return fmt.Errorf("lease not found")
	}
	// Admit revoke_failed too: a prior revoke whose target drop failed left the underlying
	// credential LIVE, so it must remain retryable (manually or via the sweep). Only an
	// already-revoked/expired lease is a no-op.
	if lease.Status != "active" && lease.Status != "revoke_failed" {
		return fmt.Errorf("lease is not active (status %s)", lease.Status)
	}
	cfg, err := c.storage.GetDynamicSecretConfig(ctx, lease.ConfigID)
	if err != nil {
		return fmt.Errorf("config not found")
	}
	engine, err := c.dynamicEngine(cfg.BackendType)
	if err != nil {
		return err
	}
	adminDSN, err := c.decryptAuthSecret(cfg.AdminDSNEnc, cfg.AdminDSNMeta, encryption.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
	if err != nil {
		return fmt.Errorf("failed to decrypt admin DSN: %w", err)
	}
	now := c.now()
	var uidPtr *uint
	if userID != 0 {
		uidPtr = &userID
	}
	pid := lease.ProjectID
	if rerr := engine.Revoke(ctx, adminDSN, lease.RoleName); rerr != nil {
		lease.Status = "revoke_failed"
		lease.RevokeError = rerr.Error()
		// Deliberately NOT stamping RevokedAt here: the target drop failed, so the
		// credential is still live. Stamping it would make the audit trail / API
		// falsely claim the role was dropped at this time, even though it wasn't —
		// and it wasn't dropped at all yet, so there is no "revoked at" moment to
		// record. RevokedAt is set only on the success path below.
		_ = c.storage.UpdateDynamicSecretLease(ctx, lease)
		c.writeAuditEventFull(ctx, "dynamic_lease.revoke_failed", uidPtr, nil, &pid, "",
			fmt.Sprintf("FAILED to revoke dynamic lease %s (role %s): %v", lease.LeaseID, lease.RoleName, rerr))
		return fmt.Errorf("failed to revoke on target: %w", rerr)
	}
	lease.Status = "revoked"
	lease.RevokeReason = reason
	lease.RevokeError = "" // clear any error from a prior failed attempt — this retry succeeded
	lease.RevokedAt = &now
	if err := c.storage.UpdateDynamicSecretLease(ctx, lease); err != nil {
		return err
	}
	// #97: for an ephemeral backend (AWS STS, Kubernetes) engine.Revoke above is a
	// documented no-op — the credential cannot be invalidated early at the provider,
	// only marked dead in Keyorix's own bookkeeping. Saying "revoked" outright would
	// misleadingly imply the credential is dead; it remains live until its own
	// provider-enforced expiry (lease.ExpiresAt, corrected to the actual granted
	// expiry at issue — see IssueLease).
	msg := fmt.Sprintf("revoked dynamic lease %s (reason=%s)", lease.LeaseID, reason)
	if engine.IsEphemeralBackend() {
		msg = fmt.Sprintf("marked dynamic lease %s revoked locally (reason=%s); the %s credential cannot be invalidated early and remains live until its provider-enforced expiry at %s",
			lease.LeaseID, reason, cfg.BackendType, lease.ExpiresAt.UTC().Format(time.RFC3339))
	}
	c.writeAuditEventFull(ctx, "dynamic_lease.revoked", uidPtr, nil, &pid, "", msg)
	return nil
}

// RevokeExpiredLeases is the auto-revoke sweep: it revokes every active (or previously
// revoke_failed) lease past its expiry (system-actored). Returns the count revoked and a
// non-nil error if any revoke failed, so the scheduler records the partial failure rather
// than reporting a clean sweep while credentials remain live past their TTL.
func (c *KeyorixCore) RevokeExpiredLeases(ctx context.Context, before time.Time) (int, error) {
	expired, err := c.storage.ListExpiredActiveLeases(ctx, before)
	if err != nil {
		return 0, err
	}
	revoked, failed := 0, 0
	for _, l := range expired {
		if err := c.RevokeLease(ctx, l.LeaseID, 0, "expired"); err == nil {
			revoked++
		} else {
			failed++
		}
	}
	if failed > 0 {
		return revoked, fmt.Errorf("dynamic-secrets sweep: %d of %d expired lease(s) failed to revoke — those credentials remain live past their TTL", failed, len(expired))
	}
	return revoked, nil
}

// RevokeLeasesForConfig revokes every active lease issued from a config — an
// incident-response kill switch for a config's outstanding dynamic credentials
// (e.g. a compromised target DB or config). Returns the counts revoked and failed
// (each revoke is audited per-lease as well). Best-effort: one lease's revoke
// failure does not stop the others.
func (c *KeyorixCore) RevokeLeasesForConfig(ctx context.Context, configID, userID uint, reason string) (revoked, failed int, err error) {
	leases, err := c.storage.ListDynamicSecretLeases(ctx, configID)
	if err != nil {
		return 0, 0, err
	}
	for _, l := range leases {
		// Retry a previously-failed revoke too — its credential is still live.
		if l.Status != "active" && l.Status != "revoke_failed" {
			continue
		}
		if rerr := c.RevokeLease(ctx, l.LeaseID, userID, reason); rerr != nil {
			failed++
		} else {
			revoked++
		}
	}
	var uidPtr *uint
	if userID != 0 {
		uidPtr = &userID
	}
	pid := uint(0)
	if cfg, gerr := c.storage.GetDynamicSecretConfig(ctx, configID); gerr == nil {
		pid = cfg.ProjectID
	}
	var pidPtr *uint
	if pid != 0 {
		pidPtr = &pid
	}
	c.writeAuditEventFull(ctx, "dynamic_secret.bulk_revoke", uidPtr, nil, pidPtr, "",
		fmt.Sprintf("bulk-revoked dynamic leases for config %d (revoked=%d, failed=%d, reason=%s)", configID, revoked, failed, reason))
	return revoked, failed, nil
}

// dynamicTTL resolves the requested TTL (override, else config default, else 1h),
// clamps it to the config's MaxTTLSeconds ceiling when one is set, and always clamps
// it to the install-wide max-lease-TTL ceiling on top (#97) — the per-config ceiling
// is entirely operator-controlled and defaults to "unset = unbounded" (e.g. a config
// left with MaxTTLSeconds=0 combined with a caller-supplied override would otherwise
// mint a credential valid for however long the caller asked, with nothing to stop a
// 100-year lease).
func (c *KeyorixCore) dynamicTTL(cfg *models.DynamicSecretConfig, override int) time.Duration {
	ttl := defaultDynamicTTL
	switch {
	case override > 0:
		ttl = time.Duration(override) * time.Second
	case cfg.DefaultTTLSeconds > 0:
		ttl = time.Duration(cfg.DefaultTTLSeconds) * time.Second
	}
	if cfg.MaxTTLSeconds > 0 {
		if max := time.Duration(cfg.MaxTTLSeconds) * time.Second; ttl > max {
			ttl = max
		}
	}
	installMax := c.dynamicMaxLeaseTTL
	if installMax <= 0 {
		installMax = defaultMaxLeaseTTL
	}
	if ttl > installMax {
		ttl = installMax
	}
	return ttl
}

// RenewLease extends an active lease's expiry by ttlSeconds (or the config
// default), capped so the lease's total lifetime from issue never exceeds the
// config's MaxTTLSeconds. On backends with a DB-level expiry (PostgreSQL) it also
// pushes the role's VALID UNTIL forward. Returns the new expiry.
func (c *KeyorixCore) RenewLease(ctx context.Context, leaseID string, ttlSeconds int, userID uint) (time.Time, error) {
	lease, err := c.storage.GetDynamicSecretLease(ctx, leaseID)
	if err != nil {
		return time.Time{}, fmt.Errorf("lease not found")
	}
	if lease.Status != "active" {
		return time.Time{}, fmt.Errorf("lease is not active (status %s)", lease.Status)
	}
	// A lease whose expiry has already passed is logically dead even if the sweeper
	// has not yet flipped its status (sweep disabled, or not run yet). Renewing it
	// would push the backend credential's lifetime forward — resurrecting a
	// credential that should be gone, violating the promised TTL — and would race the
	// sweep that is about to revoke it. Refuse; the caller must issue a new lease.
	if !c.now().Before(lease.ExpiresAt) {
		return time.Time{}, fmt.Errorf("lease has expired; issue a new lease instead")
	}
	cfg, err := c.storage.GetDynamicSecretConfig(ctx, lease.ConfigID)
	if err != nil {
		return time.Time{}, fmt.Errorf("config not found")
	}
	// Cloud-IAM backends (AWS STS) mint self-expiring credentials whose lifetime is
	// fixed by the provider at issue — they cannot be renewed; issue a new lease.
	if eng, eerr := c.dynamicEngine(cfg.BackendType); eerr == nil && eng.IsEphemeralBackend() {
		return time.Time{}, fmt.Errorf("the %s backend mints self-expiring credentials that cannot be renewed; issue a new lease instead", cfg.BackendType)
	}
	newExpiry := c.now().Add(c.dynamicTTL(cfg, ttlSeconds))
	// Never let renewal push total lifetime past the config's max-TTL ceiling.
	if cfg.MaxTTLSeconds > 0 {
		if hardCap := lease.IssuedAt.Add(time.Duration(cfg.MaxTTLSeconds) * time.Second); newExpiry.After(hardCap) {
			newExpiry = hardCap
		}
	}
	// ...nor past the install-wide ceiling (#97) — same reasoning as dynamicTTL: the
	// per-config ceiling above is optional and defaults to unbounded, so a renewal
	// alone could otherwise stretch a lease's total lifetime arbitrarily far.
	installMax := c.dynamicMaxLeaseTTL
	if installMax <= 0 {
		installMax = defaultMaxLeaseTTL
	}
	if hardCap := lease.IssuedAt.Add(installMax); newExpiry.After(hardCap) {
		newExpiry = hardCap
	}
	if !newExpiry.After(lease.ExpiresAt) {
		return time.Time{}, fmt.Errorf("renewal would not extend the lease (max-TTL ceiling reached)")
	}
	engine, err := c.dynamicEngine(cfg.BackendType)
	if err != nil {
		return time.Time{}, err
	}
	// A backend with no DB-level expiry relies entirely on the sweeper to enforce a
	// lease's TTL. With the sweeper disabled, a renewal would extend a credential nothing
	// will ever revoke — mirror IssueLease's fail-closed refusal.
	if !engine.SupportsNativeExpiry() && !c.dynamicSweepEnabled {
		return time.Time{}, fmt.Errorf("renewal is unavailable for the %s backend while the lease sweeper is disabled (its TTL would be unenforced)", cfg.BackendType)
	}
	adminDSN, err := c.decryptAuthSecret(cfg.AdminDSNEnc, cfg.AdminDSNMeta, encryption.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to decrypt admin DSN: %w", err)
	}
	if err := engine.Renew(ctx, adminDSN, lease.RoleName, newExpiry); err != nil {
		return time.Time{}, fmt.Errorf("failed to renew on target: %w", err)
	}
	lease.ExpiresAt = newExpiry
	if err := c.storage.UpdateDynamicSecretLease(ctx, lease); err != nil {
		return time.Time{}, err
	}
	uid := userID
	var uidPtr *uint
	if userID != 0 {
		uidPtr = &uid
	}
	pid := lease.ProjectID
	c.writeAuditEventFull(ctx, "dynamic_lease.renewed", uidPtr, nil, &pid, "",
		fmt.Sprintf("renewed dynamic lease %s (new expiry %s)", lease.LeaseID, newExpiry.UTC().Format(time.RFC3339)))
	return newExpiry, nil
}
