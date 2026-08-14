// secret_read_aggregation.go — per-secret top-reader report.
//
// GetSecretReadSummary aggregates "secret.read" audit events for one secret
// into a ranked list of actors (users or machine identities), letting
// security investigators quickly see who has read a sensitive secret the most
// often over a configurable time window.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

const (
	secretReadSummaryDefaultLimit = 10
	secretReadSummaryMaxLimit     = 50
	secretReadSummaryDefaultDays  = 30
)

// SecretReadSummaryRequest carries the parameters for GetSecretReadSummary.
type SecretReadSummaryRequest struct {
	SecretID uint
	Since    time.Time // zero → 30 days ago
	Until    time.Time // zero → now
	Limit    int       // 0 → default 10, capped at 50
}

// SecretReadEntry re-exports the storage type so callers only need to import core.
type SecretReadEntry = storage.SecretReadEntry

// SecretReadSummary is the full aggregated report for one secret.
type SecretReadSummary struct {
	SecretID   uint              `json:"secret_id"`
	Since      time.Time         `json:"since"`
	Until      time.Time         `json:"until"`
	Entries    []SecretReadEntry `json:"entries"`
	TotalReads int64             `json:"total_reads"`
}

// GetSecretReadSummary returns the top readers of a secret in the time window.
//
// Defaults applied when zero/unset:
//   - Since → 30 days ago
//   - Until → now
//   - Limit → 10, capped at 50
//
// Returns ErrInvalidInput when Since >= Until after defaults are applied.
//
// #G10: this used to perform zero authorization of its own, trusting the HTTP router's
// RequireScopedSecretPermission(permSecretsManage, "id") gate to have already run. It now
// checks the same permission itself, so it's safe to call from any transport.
func (c *KeyorixCore) GetSecretReadSummary(ctx context.Context, actorKind string, actorID uint, req SecretReadSummaryRequest) (*SecretReadSummary, error) {
	now := c.now()

	since := req.Since
	if since.IsZero() {
		since = now.Add(-secretReadSummaryDefaultDays * 24 * time.Hour)
	}

	until := req.Until
	if until.IsZero() {
		until = now
	}

	if !since.Before(until) {
		return nil, fmt.Errorf("since must be before until: %w", ErrInvalidInput)
	}

	if allowed, err := c.AuthorizeSecretPrincipal(ctx, actorKind, actorID, req.SecretID, permSecretsManage); err != nil {
		return nil, fmt.Errorf("GetSecretReadSummary: %w", err)
	} else if !allowed {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "insufficient permissions")
	}

	limit := req.Limit
	if limit <= 0 {
		limit = secretReadSummaryDefaultLimit
	}
	if limit > secretReadSummaryMaxLimit {
		limit = secretReadSummaryMaxLimit
	}

	entries, err := c.storage.GetSecretReadCounts(ctx, req.SecretID, since, until, limit)
	if err != nil {
		return nil, fmt.Errorf("GetSecretReadSummary: %w", err)
	}
	if entries == nil {
		entries = []SecretReadEntry{}
	}

	var total int64
	for _, e := range entries {
		total += e.ReadCount
	}

	return &SecretReadSummary{
		SecretID:   req.SecretID,
		Since:      since,
		Until:      until,
		Entries:    entries,
		TotalReads: total,
	}, nil
}
