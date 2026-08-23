// secrets.go — CreateSecretRequest, UpdateSecretRequest types, and core CRUD operations.
//
// For version storage and retrieval see secrets_versions.go.
// For request validation see secrets_validation.go.
package core

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// CreateSecretRequest represents a request to create a new secret.
type CreateSecretRequest struct {
	Name          string            `json:"name" validate:"required,min=1,max=255"`
	Value         []byte            `json:"value" validate:"required"`
	ProjectID     uint              `json:"project_id" validate:"required"`
	EnvironmentID uint              `json:"environment_id" validate:"required"`
	Type          string            `json:"type" validate:"required"`
	MaxReads      *int              `json:"max_reads,omitempty" validate:"omitempty,min=1"`
	Expiration    *time.Time        `json:"expiration,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Tags          []string          `json:"tags,omitempty"`
	CreatedBy     string            `json:"created_by" validate:"required"`
	OwnerID       uint              `json:"owner_id,omitempty"`
	// ParentID optionally places the new secret inside a folder node. When set,
	// the parent must exist, belong to the same project/environment, and be a
	// folder (IsSecret=false). A zero value means no parent (root level).
	ParentID *uint `json:"parent_id,omitempty"`
	// Classification is an optional data-sensitivity label (A.5.12): "" or one of
	// public|internal|confidential|restricted.
	Classification string `json:"classification,omitempty"`
	// Description is an optional free-text note (≤maxSecretDescriptionLen chars).
	Description string `json:"description,omitempty"`
}

// UpdateSecretRequest represents a request to update an existing secret.
type UpdateSecretRequest struct {
	ID    uint   `json:"id" validate:"required"`
	Value []byte `json:"value,omitempty"`
	// Type, when non-empty, replaces the secret's type (e.g. "password", "api_key",
	// "certificate", "generic"). An empty string means "leave unchanged".
	Type       string     `json:"type,omitempty"`
	MaxReads   *int       `json:"max_reads,omitempty" validate:"omitempty,min=1"`
	Expiration *time.Time `json:"expiration,omitempty"`
	// ClearExpiration removes an existing expiration. It is distinct from leaving
	// Expiration nil (which means "leave unchanged"): without this flag there is no
	// way to make an expiring secret non-expiring.
	ClearExpiration bool              `json:"clear_expiration,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	Tags            []string          `json:"tags,omitempty"`
	// Description, when non-nil, replaces the secret's description ("" clears it). A nil
	// pointer means "leave unchanged" — matching Metadata's nil-means-unchanged
	// convention, since "" is itself a meaningful value here (SetSecretDescription has
	// the same gate as the rest of this request; no separate authorization applies).
	Description *string `json:"description,omitempty"`
	UpdatedBy   string  `json:"updated_by" validate:"required"`
	UserID      uint    `json:"user_id,omitempty"`
}

// CreateSecret creates a new secret with business logic validation.
func (c *KeyorixCore) CreateSecret(ctx context.Context, req *CreateSecretRequest) (*models.SecretNode, error) { // NOSONAR -- cognitive complexity 27, suppress go:S3776
	if err := c.validateCreateSecretRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	if err := c.secretValuePolicy.Validate(req.Value); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	if err := c.validateSecretName(req.Name); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	if len(strings.TrimSpace(req.Description)) > maxSecretDescriptionLen {
		return nil, fmt.Errorf("%s: description exceeds %d characters", i18n.T("ErrorValidation", nil), maxSecretDescriptionLen)
	}

	// Verify the environment belongs to the stated project. RemoteStorage.GetEnvironment
	// is unimplemented (ErrUnsupportedByBackend, #499): it has no by-ID lookup route to
	// call without also knowing the project (which this pre-check exists to establish).
	// Rather than hard-failing every remote CreateSecret on a pre-check the backend can't
	// perform, skip it when unsupported — the upstream server's own CreateSecret handler
	// runs this identical ownership check against its own LocalStorage when it receives
	// the forwarded request, so the invariant is still enforced authoritatively, just on
	// the other side of the wire instead of redundantly on both.
	env, err := c.storage.GetEnvironment(ctx, req.EnvironmentID)
	if err != nil {
		if !errors.Is(err, storage.ErrUnsupportedByBackend) {
			return nil, fmt.Errorf("environment %d not found", req.EnvironmentID)
		}
	} else if env.ProjectID != req.ProjectID {
		return nil, fmt.Errorf("environment %d does not belong to project %d", req.EnvironmentID, req.ProjectID)
	}

	existing, err := c.storage.GetSecretByName(ctx, req.Name, req.ProjectID, req.EnvironmentID)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretAlreadyExists", nil))
	}

	// Validate parent folder when one is requested.
	if req.ParentID != nil && *req.ParentID != 0 {
		parent, perr := c.storage.GetSecret(ctx, *req.ParentID)
		if perr != nil {
			return nil, fmt.Errorf("%s: parent folder %d not found", i18n.T("ErrorValidation", nil), *req.ParentID)
		}
		if parent.IsSecret {
			return nil, fmt.Errorf("%s: parent %d is a secret, not a folder", i18n.T("ErrorValidation", nil), *req.ParentID)
		}
		if parent.ProjectID != req.ProjectID || parent.EnvironmentID != req.EnvironmentID {
			return nil, fmt.Errorf("%s: parent folder %d does not belong to the same project/environment", i18n.T("ErrorValidation", nil), *req.ParentID)
		}
	}

	if !IsValidClassification(req.Classification) {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "invalid classification")
	}

	// #390: normalize req.Tags UP FRONT, before creating anything, so a caller intending
	// an immediate "reviewed"/"exempt"-style tag at creation time gets a clear validation
	// error instead of a silently-dropped tag list — CreateSecret previously never read
	// req.Tags at all despite both the HTTP and gRPC handlers passing it through.
	var normalizedTags []string
	if len(req.Tags) > 0 {
		normalizedTags, err = normalizeTags(req.Tags)
		if err != nil {
			return nil, err
		}
	}

	secret := &models.SecretNode{
		Name:           req.Name,
		ProjectID:      req.ProjectID,
		EnvironmentID:  req.EnvironmentID,
		Type:           req.Type,
		Description:    strings.TrimSpace(req.Description),
		MaxReads:       req.MaxReads,
		Expiration:     req.Expiration,
		Classification: req.Classification,
		IsSecret:       true,
		Status:         "active",
		CreatedBy:      req.CreatedBy,
		OwnerID:        req.OwnerID,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	if req.ParentID != nil && *req.ParentID != 0 {
		secret.ParentID = req.ParentID
	}

	// req.Value is forwarded as the optional plaintext argument (#499): LocalStorage
	// ignores it (a no-op — the value still flows through the storeSecretVersion call
	// below, unchanged), while RemoteStorage forwards it over the wire so the real
	// upstream handler's required "value" field is satisfied and version 1 is created
	// atomically server-side. Never logged.
	createdSecret, err := c.storage.CreateSecret(ctx, secret, string(req.Value))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Skip the separate version-creation call when the backend already stored the value
	// atomically as part of CreateSecret itself (RemoteStorage, #499): calling
	// storeSecretVersion again here would try to mint a conflicting duplicate version 1
	// against a secret that already has one. LocalStorage never sets ValueStored, so this
	// call remains exactly as before for it.
	if !createdSecret.ValueStored {
		if err := c.storeSecretVersion(ctx, createdSecret, req.Value, 1); err != nil {
			if delErr := c.storage.DeleteSecret(ctx, createdSecret.ID); delErr != nil {
				log.Printf("warning: failed to cleanup orphaned secret %d after failed version creation: %v", createdSecret.ID, delErr)
			}
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
	}

	// Apply the create-time tags (#390) now that the secret and its first version both
	// exist. Calling the storage layer directly (not the core SetSecretTags wrapper)
	// is deliberate: SetSecretTags re-enforces write permission via
	// EnforceSecretWritePermission, which is redundant here (the caller already had
	// secrets.write on this scope to reach CreateSecret at all) and would require
	// resolving an actor ID that CreateSecretRequest doesn't carry uniformly across
	// every caller (HTTP/gRPC/CLI). Tags were already normalized/validated up front.
	if len(normalizedTags) > 0 {
		if err := c.storage.SetSecretTags(ctx, createdSecret.ID, normalizedTags); err != nil {
			if delErr := c.storage.DeleteSecret(ctx, createdSecret.ID); delErr != nil {
				log.Printf("warning: failed to cleanup orphaned secret %d after failed tag creation: %v", createdSecret.ID, delErr)
			}
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
	}

	return createdSecret, nil
}

// GetSecret retrieves a secret by ID, checking expiration.
//
// GetSecret intentionally performs NO authorization check of its own — it neither
// verifies ownership nor consults shares/RBAC. Every real HTTP/gRPC caller that
// serves a secret to an end user goes through GetSecretWithPermissionCheck instead,
// which enforces read permission (via EnforceSecretReadPermission) before delegating
// to this method. GetSecret exists as the unguarded primitive for internal callers
// that have already authorized the request some other way (or are working with
// metadata rather than exposing the value). Do not call GetSecret directly from a
// path that serves a secret to a caller without first checking permission — use
// GetSecretWithPermissionCheck for that.
func (c *KeyorixCore) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	if id == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if secret.Expiration != nil && time.Now().After(*secret.Expiration) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretExpired", nil))
	}
	return secret, nil
}

// GetSecretWithPermissionCheck retrieves a secret by ID with read permission enforcement.
func (c *KeyorixCore) GetSecretWithPermissionCheck(ctx context.Context, id, userID uint) (*models.SecretNode, error) {
	if _, err := c.EnforceSecretReadPermission(ctx, id, userID); err != nil {
		return nil, err
	}
	if err := c.checkSecretAccessSchedule(ctx, id); err != nil {
		return nil, err
	}
	return c.GetSecret(ctx, id)
}

// GetSecretByName resolves a secret by its name within a project/environment. Like
// GetSecret, it performs NO authorization check of its own — callers that serve the
// result to an end user must go through GetSecretByNameWithPermissionCheck instead.
func (c *KeyorixCore) GetSecretByName(ctx context.Context, name string, projectID, environmentID uint) (*models.SecretNode, error) {
	secret, err := c.storage.GetSecretByName(ctx, name, projectID, environmentID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if secret.Expiration != nil && time.Now().After(*secret.Expiration) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretExpired", nil))
	}
	return secret, nil
}

// GetSecretByNameWithPermissionCheck retrieves a secret by name/project/environment
// with read permission enforcement — the name-lookup counterpart to
// GetSecretWithPermissionCheck, mirroring the resolve-then-authorize-by-id pattern
// ResolveSecretRef/GetSecretValueByRef already use for the ref-based value read.
func (c *KeyorixCore) GetSecretByNameWithPermissionCheck(ctx context.Context, name string, projectID, environmentID, userID uint) (*models.SecretNode, error) {
	secret, err := c.storage.GetSecretByName(ctx, name, projectID, environmentID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if _, err := c.EnforceSecretReadPermission(ctx, secret.ID, userID); err != nil {
		return nil, err
	}
	if err := c.checkSecretAccessSchedule(ctx, secret.ID); err != nil {
		return nil, err
	}
	return c.GetSecret(ctx, secret.ID)
}

// UpdateSecret updates an existing secret.
func (c *KeyorixCore) UpdateSecret(ctx context.Context, req *UpdateSecretRequest) (*models.SecretNode, error) {
	if err := c.validateUpdateSecretRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	// An update that changes the value writes a new version, so it must clear the
	// value policy too (otherwise a weak value bypasses the create/rotate gate).
	if len(req.Value) > 0 {
		if err := c.secretValuePolicy.Validate(req.Value); err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
		}
	}
	secret, err := c.storage.GetSecret(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if err := applyUpdateSecretFields(secret, req); err != nil {
		return nil, err
	}
	secret.UpdatedAt = time.Now()

	if len(req.Value) > 0 {
		// #121 follow-up: two concurrent UpdateSecret calls on the same secret (or one
		// racing a RotateSecret) can both compute the same "next" version number from a
		// stale GetLatestSecretVersion read; the uniq_secret_versions_node_version index
		// (storage.ensureSecretVersionIndex) makes the loser's insert fail rather than
		// silently duplicate, but a plain storeSecretVersion call surfaced that as a hard
		// error to a caller doing nothing wrong. storeNextSecretVersion retries against a
		// freshly re-read version number instead, same as RotateSecret already does.
		if err := c.storeNextSecretVersion(ctx, secret, req.Value); err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
	}

	updatedSecret, err := c.storage.UpdateSecret(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return updatedSecret, nil
}

// applyUpdateSecretFields patches the non-value fields (max reads, expiration,
// metadata, description) from req onto secret in place.
func applyUpdateSecretFields(secret *models.SecretNode, req *UpdateSecretRequest) error {
	if req.Type != "" {
		secret.Type = req.Type
	}
	if req.Description != nil {
		secret.Description = *req.Description
	}
	if req.MaxReads != nil {
		secret.MaxReads = req.MaxReads
	}
	if req.ClearExpiration {
		secret.Expiration = nil
	} else if req.Expiration != nil {
		secret.Expiration = req.Expiration
	}
	if req.Metadata != nil {
		metadataJSON, err := json.Marshal(req.Metadata)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorInvalidMetadata", nil), err)
		}
		secret.Metadata = metadataJSON
	}
	return nil
}

// UpdateSecretWithPermissionCheck updates a secret with write permission enforcement.
func (c *KeyorixCore) UpdateSecretWithPermissionCheck(ctx context.Context, req *UpdateSecretRequest) (*models.SecretNode, error) {
	if req.UserID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.EnforceSecretWritePermission(ctx, req.ID, req.UserID); err != nil {
		return nil, err
	}
	return c.UpdateSecret(ctx, req)
}

// EventSecretRotateNoop is audited when RotateSecret is invoked with a value that is
// byte-identical to the secret's current version (#408). Left unaddressed, resubmitting
// an unchanged credential (a stale automation script, or an operator running `rotate`
// without actually changing anything) resets LastRotatedAt to "just now" with zero
// actual credential change, so risk-scoring/dashboards see "recently rotated, low risk"
// while the underlying secret has genuinely never changed. A new version row is still
// stored for audit-trail completeness, but LastRotatedAt is deliberately withheld.
const EventSecretRotateNoop = "secret.rotate_noop"

// RotateSecret creates a new version with a new value and updates LastRotatedAt.
//
// #408: if newValue is byte-identical to the CURRENT version's decrypted value, the
// rotation is treated as a no-op FOR TIMESTAMP PURPOSES ONLY: a new version row is
// still written (so the attempt is visible in version history / for audit trail
// completeness — someone did call rotate), but LastRotatedAt is deliberately left
// untouched so a false "recently rotated, low risk" signal never reaches
// dashboards/auditors/risk-scoring for material that hasn't actually changed. This
// silently-skip-the-timestamp behavior (rather than refusing/erroring outright) is
// deliberate: RotateSecret is also invoked by the auto-rotation scheduler
// (rotateOneSecret, "system:auto-rotation") and by RollbackSecret, neither of which
// expects — or gracefully handles — a hard error for what they consider a successful
// rotation call; erroring here would turn an edge case (a misbehaving rotation
// backend, or a rollback landing on a value the current version already holds) into an
// automation-breaking failure. The event is still recorded via EventSecretRotateNoop
// so the no-op is auditable rather than fully silent.
// actorID is the acting principal for the read-guard check the no-op
// comparison below requires (#G09) — 0 for system-triggered callers
// (auto-rotation), which is the same "no identifiable user" sentinel
// enforceSecretReadGuards' classification gate already denies restricted
// reads for.
func (c *KeyorixCore) RotateSecret(ctx context.Context, id uint, newValue []byte, actorID uint, rotatedBy string) (*models.SecretNode, error) {
	if err := c.secretValuePolicy.Validate(newValue); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}

	// Compare against the CURRENT version's decrypted value, mirroring the existing
	// decrypt-on-read path used by RollbackSecret (direct c.encryption.RetrieveSecret /
	// raw EncryptedValue) rather than routing through readVersionValue — that helper
	// also enforces max-reads by incrementing the read counter, which this internal
	// comparison must NOT do (it would silently burn from a burn-after-N-reads
	// secret's budget on every rotation attempt). subtle.ConstantTimeCompare matches
	// this codebase's convention for comparing genuine secret material (see mfa.go,
	// auth_bootstrap.go, encryption/auth_encryption.go).
	//
	// #G09: this decrypt-and-compare is itself a value disclosure — its RESULT
	// (whether EventSecretRotateNoop fires, and whether LastRotatedAt moves) is
	// an oracle for "does the caller's guess equal the current secret value."
	// Gate it on the SAME read guards (classification-restricted step-up/
	// approval, access-schedule) a real value read of this secret would
	// require; if the actor couldn't pass them, skip the comparison entirely
	// rather than decrypt-to-compare without authorization — this only
	// degrades the no-op-detection optimization (the rotation itself still
	// proceeds and always records a real rotation), it never blocks the
	// rotation outright, so auto-rotation (actorID 0, only relevant for
	// "restricted"-classified secrets with a gate enabled) keeps working.
	valueUnchanged := false
	if c.enforceSecretReadGuards(ctx, secret, actorID) == nil {
		if latestVersion, verr := c.storage.GetLatestSecretVersion(ctx, id); verr == nil && latestVersion != nil {
			currentValue, rerr := c.decryptVersionValue(secret, latestVersion)
			if rerr == nil && subtle.ConstantTimeCompare(currentValue, newValue) == 1 {
				valueUnchanged = true
			}
		}
	}

	if err := c.storeNextSecretVersion(ctx, secret, newValue); err != nil {
		return nil, fmt.Errorf("failed to store rotated secret: %w", err)
	}
	now := time.Now()
	if valueUnchanged {
		log.Printf("rotate secret %d: new value identical to the current version; version stored but last_rotated_at was NOT updated", id)
		sid := id
		c.writeAuditEvent(ctx, EventSecretRotateNoop, nil, &sid,
			fmt.Sprintf("rotation of secret %q by %s submitted a value identical to the current version: a new version was stored for audit-trail completeness, but last_rotated_at was not updated", secret.Name, rotatedBy))
	} else {
		secret.LastRotatedAt = &now
	}
	secret.UpdatedAt = now
	updatedSecret, err := c.storage.UpdateSecret(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to update rotation timestamp: %w", err)
	}
	// Refresh the cached certificate expiry immediately for a certificate-typed secret
	// (ADR-056) so the certificate-hygiene posture reflects the rotated certificate
	// without waiting for the next expiry scan. The plaintext is already in hand, so no
	// re-decryption is needed; a no-op for non-certificate secrets.
	c.refreshCertNotAfterCache(ctx, secret, newValue)
	return updatedSecret, nil
}

// DeleteSecret soft-deletes a secret by ID.
func (c *KeyorixCore) DeleteSecret(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if err := c.storage.DeleteSecret(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	// Emit an audit event for every dependency edge incident to this secret so
	// operators know which rotation plans are affected (best-effort; the delete
	// already succeeded). actorID 0 here because DeleteSecret itself has no actor
	// context — the HTTP handler's LogSecretDeleted carries the authenticated user.
	c.emitDependencyLifecycleEvents(ctx, EventSecretDependencyInvalidated, 0, id, secret.ProjectID, secret.Name)
	return nil
}

// DeleteSecretWithPermissionCheck deletes a secret with owner permission enforcement.
func (c *KeyorixCore) DeleteSecretWithPermissionCheck(ctx context.Context, id, userID uint) error {
	if userID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.EnforceSecretOwnerPermission(ctx, id, userID); err != nil {
		return err
	}
	return c.DeleteSecret(ctx, id)
}

// RestoreSecret clears a soft-deleted secret's deleted_at (ADR-033), bringing it
// back within the retention window. actorID is the admin performing it (0 = no
// authenticated principal). Audited as secret.restored — the inverse of the
// secret.deleted event, so a deleted secret reappearing leaves a trail.
func (c *KeyorixCore) RestoreSecret(ctx context.Context, actorID, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	// Fetch before restoring so we have name + projectID even though the row is
	// still soft-deleted at this point (GetSecretIncludingDeleted ignores deleted_at).
	secret, err := c.storage.GetSecretIncludingDeleted(ctx, id)
	if err != nil {
		// Fall back gracefully: the storage.RestoreSecret call will re-validate the
		// row and return a proper error if the id is unknown.
		secret = nil
	}
	if err := c.storage.RestoreSecret(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	sid := id
	c.writeAuditEvent(ctx, "secret.restored", actorPtr(actorID), &sid, fmt.Sprintf("secret %d restored", id))
	// Emit an audit event for every dependency edge that is now re-active so
	// operators know which rotation plans are unblocked (best-effort).
	if secret != nil {
		c.emitDependencyLifecycleEvents(ctx, EventSecretDependencyRestored, actorID, id, secret.ProjectID, secret.Name)
	}
	return nil
}

// ListSecrets lists secrets with filtering and pagination.
func (c *KeyorixCore) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	if filter == nil {
		filter = &storage.SecretFilter{}
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}
	if filter.PageSize <= 0 {
		filter.PageSize = 20
	}
	if filter.PageSize > 100 {
		filter.PageSize = 100
	}
	secrets, total, err := c.storage.ListSecrets(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return secrets, total, nil
}

// CreateFolder creates a SecretNode with IsSecret=false (a folder container).
// name must be non-empty. If parentID is provided the referenced node must
// exist and must itself be a folder (IsSecret=false).
func (c *KeyorixCore) CreateFolder(
	ctx context.Context,
	actorID uint,
	name string,
	projectID, envID uint,
	parentID *uint,
) (*models.SecretNode, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("%s: folder name is required", i18n.T("ErrorValidation", nil))
	}
	if projectID == 0 {
		return nil, fmt.Errorf("%s: project_id is required", i18n.T("ErrorValidation", nil))
	}
	if envID == 0 {
		return nil, fmt.Errorf("%s: environment_id is required", i18n.T("ErrorValidation", nil))
	}

	// Validate that the parent exists and is itself a folder node.
	if parentID != nil {
		parent, err := c.storage.GetSecret(ctx, *parentID)
		if err != nil {
			return nil, fmt.Errorf("parent folder %d not found: %w", *parentID, err)
		}
		if parent.IsSecret {
			return nil, fmt.Errorf("%s: parent node %d is a secret, not a folder", i18n.T("ErrorValidation", nil), *parentID)
		}
		// The destination parent was loaded with a bare, unauthorized GetSecret:
		// the caller's write authorization was only ever checked against
		// (projectID, envID) — the NEW folder's own claimed scope — and says
		// nothing about the target parent's actual scope. Mirror CreateSecret's
		// own parent-folder validation (above in this file) and MoveSecret's
		// (secret_move.go): require the destination to live in the SAME
		// project/environment the caller was authorized for, otherwise a caller
		// could nest a folder under a parent in a project/environment they have
		// no access to, and folder-inheriting ACL/sharing resolution (see
		// HasSecretACL's ancestor walk in secret_acl.go) would then apply that
		// other project's grants to it.
		if parent.ProjectID != projectID || parent.EnvironmentID != envID {
			return nil, fmt.Errorf("%s: parent folder %d does not belong to the same project/environment", i18n.T("ErrorValidation", nil), *parentID)
		}
	}

	node := &models.SecretNode{
		Name:          name,
		ProjectID:     projectID,
		EnvironmentID: envID,
		ParentID:      parentID,
		IsSecret:      false,
		Type:          "folder",
		Status:        "active",
		CreatedBy:     fmt.Sprintf("%d", actorID),
		OwnerID:       actorID,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	created, err := c.storage.CreateSecret(ctx, node, "")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return created, nil
}

// ListFolders returns all folder nodes (IsSecret=false) for a project/environment.
// If parentID is non-nil, only children of that parent are returned.
func (c *KeyorixCore) ListFolders(ctx context.Context, projectID uint, parentID *uint, page, pageSize int) ([]*models.SecretNode, int64, error) {
	isFalse := false
	filter := &storage.SecretFilter{
		IsSecret: &isFalse,
		Page:     page,
		PageSize: pageSize,
	}
	if projectID != 0 {
		filter.ProjectID = &projectID
	}
	if parentID != nil {
		filter.ParentID = parentID
	}
	return c.ListSecrets(ctx, filter)
}
