package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
)

func swi(name, classification string) *models.SecretWithSharingInfo {
	return &models.SecretWithSharingInfo{
		SecretNode: &models.SecretNode{Name: name, Classification: classification},
	}
}

func TestApplySecretFilters_Classification(t *testing.T) {
	c := &KeyorixCore{}
	in := []*models.SecretWithSharingInfo{
		swi("r1", "restricted"), swi("c1", "confidential"), swi("u1", ""),
	}

	restricted := "restricted"
	got := c.applySecretFilters(context.Background(), in, &models.SecretListFilter{Classification: &restricted})
	assert.Len(t, got, 1)
	assert.Equal(t, "r1", got[0].Name)

	unclassified := "unclassified"
	got = c.applySecretFilters(context.Background(), in, &models.SecretListFilter{Classification: &unclassified})
	assert.Len(t, got, 1)
	assert.Equal(t, "u1", got[0].Name, "'unclassified' matches the empty label")

	// No classification filter → all pass through.
	got = c.applySecretFilters(context.Background(), in, &models.SecretListFilter{})
	assert.Len(t, got, 3)
}
