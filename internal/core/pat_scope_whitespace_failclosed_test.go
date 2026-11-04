package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidatePATToken_WhitespaceOnlyScopesColumnIsNotOwnerEquivalent drives the
// PAT authentication path (ValidatePATToken, and the per-request re-read
// CurrentPATRestriction) with a stored scopes column of "   ". EncodePATScopes never
// writes that, so it is a corrupted or hand-edited row. Before PAT-SCOPE-TAILS-1 the
// codec trimmed it to "" and the token resolved to a nil restriction: full owner
// rights. It must instead carry the deny-everything restriction.
//
// The control case pins the legitimate rule: an exact empty column (what
// CreateOwnPAT stores for "no allowlist", and what a pre-ADR-042 NULL reads as)
// stays unscoped by design.
func TestValidatePATToken_WhitespaceOnlyScopesColumnIsNotOwnerEquivalent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	raw := patPrefix + "whitespacescopes0001"
	hash := sha256Hex(raw)

	validate := func(t *testing.T, scopes string) (*PATRestriction, *PATRestriction) {
		t.Helper()
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetPersonalAccessTokenByHash", ctx, hash).Return(&models.PersonalAccessToken{ID: 9, UserID: 1, Scopes: scopes}, nil)
		ms.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: acctTestUser, IsActive: true, AccountState: AccountActive}, nil)
		ms.On("GetUserRoles", ctx, uint(1)).Return([]*models.Role{{Name: "super_admin"}}, nil)

		user, _, restriction, _, err := c.ValidatePATToken(ctx, raw)
		require.NoError(t, err)
		require.Equal(t, uint(1), user.ID)
		current, err := c.CurrentPATRestriction(ctx, raw)
		require.NoError(t, err)
		return restriction, current
	}

	t.Run("whitespace_only_scopes_column_denies_everything", func(t *testing.T) {
		t.Parallel()
		for _, scopes := range []string{" ", "   ", "\n", "\t \r\n"} {
			restriction, current := validate(t, scopes)
			for name, r := range map[string]*PATRestriction{"ValidatePATToken": restriction, "CurrentPATRestriction": current} {
				require.NotNil(t, r, "%s: scopes %q resolved to no restriction, i.e. the owner's full rights", name, scopes)
				assert.Equal(t, patScopeCorrupted, r.Permissions, "%s: scopes %q", name, scopes)
				for _, perm := range []string{"secrets.read", "secrets.write", "users.write", "roles.assign", "system.write"} {
					assert.False(t, r.Allows(perm, Scope{}), "%s: scopes %q must not allow %s", name, scopes, perm)
				}
			}
		}
	})

	t.Run("exact_empty_scopes_column_is_unscoped_by_design", func(t *testing.T) {
		t.Parallel()
		restriction, current := validate(t, "")
		assert.Nil(t, restriction, "an exact empty column is the legitimate unscoped PAT (inherits the owner)")
		assert.Nil(t, current)
	})
}
