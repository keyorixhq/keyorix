package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
)

// applySecretFilters honors ExpiresBefore: only secrets with a non-null expiration
// before the cutoff pass (already expired or expiring within the window); secrets
// expiring at/after the cutoff and never-expiring secrets are dropped. This backs
// GET /api/v1/secrets?expires_before=… across the combined owned+shared list.
func TestApplySecretFilters_ExpiresBefore(t *testing.T) {
	c := &KeyorixCore{}
	now := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	cutoff := now.Add(30 * 24 * time.Hour)
	soon := now.Add(10 * 24 * time.Hour)
	expired := now.Add(-24 * time.Hour)
	atCutoff := cutoff
	far := now.Add(60 * 24 * time.Hour)

	sec := func(name string, exp *time.Time) *models.SecretWithSharingInfo {
		return &models.SecretWithSharingInfo{SecretNode: &models.SecretNode{Name: name, Expiration: exp}}
	}
	in := []*models.SecretWithSharingInfo{
		sec("soon", &soon),
		sec("expired", &expired),
		sec("at-cutoff", &atCutoff),
		sec("far", &far),
		sec("never", nil),
	}

	out := c.applySecretFilters(context.Background(), in, &models.SecretListFilter{ExpiresBefore: &cutoff})

	names := make([]string, 0, len(out))
	for _, s := range out {
		names = append(names, s.Name)
	}
	assert.ElementsMatch(t, []string{"soon", "expired"}, names,
		"only secrets strictly before the cutoff pass; at-cutoff, far-future and never-expiring are excluded")

	// Without the filter, everything passes (no behavior change for existing callers).
	all := c.applySecretFilters(context.Background(), in, &models.SecretListFilter{})
	assert.Len(t, all, 5)
}
