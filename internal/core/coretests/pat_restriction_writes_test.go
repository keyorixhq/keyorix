package coretests

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/core"
)

// TestRestrictedPATUngatedWrites_DenyByDefault pins the table's shape (PAT-GUARD-3):
// the zero entry refuses with ErrRestrictedPATSelfServiceWrite, an allowed entry
// carries a reason, and a key the table does not list (a gated route) is not refused
// here. Which routes are ungated is checked by the transport guards.
func TestRestrictedPATUngatedWrites_DenyByDefault(t *testing.T) {
	assert.Equal(t, core.ErrRestrictedPATSelfServiceWrite, core.RestrictedPATWritePolicy{}.RefusalError())
	assert.Equal(t, core.ErrRestrictedPATSelfServiceWrite, core.RestrictedPATWriteRefusal("POST /api/v1/auth/change-password"))
	assert.Equal(t, core.ErrRestrictedPATCannotMintPAT, core.RestrictedPATWriteRefusal("POST /api/v1/auth/tokens"))
	assert.Equal(t, core.ErrRestrictedPATCannotBreakGlass, core.RestrictedPATWriteRefusal("POST /api/v1/projects/{id}/break-glass"))
	assert.NoError(t, core.RestrictedPATWriteRefusal("DELETE /api/v1/auth/tokens/{id}"))
	assert.NoError(t, core.RestrictedPATWriteRefusal("POST /api/v1/projects"), "a gated route is Authorize's")

	refused, allowed := 0, 0
	for key, p := range core.RestrictedPATUngatedWrites() {
		if p.Allowed {
			allowed++
			assert.NotEmpty(t, strings.TrimSpace(p.Reason), "allowed entry %q needs a reason", key)
			assert.Nil(t, p.Refusal, "allowed entry %q has a refusal", key)
		} else {
			refused++
		}
	}
	assert.Positive(t, refused)
	assert.Positive(t, allowed)

	// The copy is a copy.
	c := core.RestrictedPATUngatedWrites()
	c["POST /api/v1/auth/change-password"] = core.RestrictedPATWritePolicy{Allowed: true, Reason: "x"}
	assert.Error(t, core.RestrictedPATWriteRefusal("POST /api/v1/auth/change-password"))
}
