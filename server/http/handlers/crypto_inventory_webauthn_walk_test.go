package handlers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// pagedUsers serves ListUsers from fixed pages (page number -> user IDs) with a
// total per call, and no credentials.
type pagedUsers struct {
	pages  map[int][]uint
	totals []int64 // total reported on call i; the last one repeats
	calls  int
}

func (p *pagedUsers) ListUsers(_ context.Context, f *storage.UserFilter) ([]*models.User, int64, error) {
	total := p.totals[min(p.calls, len(p.totals)-1)]
	p.calls++
	var out []*models.User
	for _, id := range p.pages[f.Page] {
		out = append(out, &models.User{ID: id})
	}
	return out, total, nil
}

func (p *pagedUsers) ListWebAuthnCredentials(context.Context, uint) ([]*models.WebAuthnCredential, error) {
	return nil, nil
}

func userIDs(from, to uint) []uint {
	var ids []uint
	for i := from; i <= to; i++ {
		ids = append(ids, i)
	}
	return ids
}

// Review finding (#3754): ListUsers pages by OFFSET with no guaranteed order, so
// a page can repeat a user and skip another. The walk must not then claim it saw
// every user.
func TestWebAuthnInventoryCredentials_UnstablePagingIsIncomplete(t *testing.T) {
	ctx := context.Background()

	stable := &pagedUsers{pages: map[int][]uint{1: userIDs(1, 200), 2: userIDs(201, 300)}, totals: []int64{300}}
	_, complete, warn := webAuthnInventoryCredentials(ctx, stable)
	assert.True(t, complete, "disjoint pages covering the total are complete")
	assert.Empty(t, warn)

	overlap := &pagedUsers{pages: map[int][]uint{1: userIDs(1, 200), 2: userIDs(200, 299)}, totals: []int64{300}}
	creds, complete, warn := webAuthnInventoryCredentials(ctx, overlap)
	assert.False(t, complete, "user 300 was skipped (user 200 came twice)")
	assert.Nil(t, creds)
	assert.Contains(t, warn, "not stable")

	shifted := &pagedUsers{pages: map[int][]uint{1: userIDs(1, 200), 2: userIDs(201, 301)}, totals: []int64{300, 301}}
	_, complete, warn = webAuthnInventoryCredentials(ctx, shifted)
	assert.False(t, complete, "a user added during the walk shifts the pages")
	assert.Contains(t, warn, "added or removed")
}
