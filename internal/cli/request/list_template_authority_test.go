// list_template_authority_test.go — regression coverage for #G72: the --by
// actor for `keyorix request list` and the rejection-reason-template
// add/list/delete commands must actually hold the authority the equivalent
// HTTP route requires (roles.assign), not merely resolve to SOME user
// record. Mirrors review_authority_test.go's TestRequireReviewAuthority_*
// shape, reusing this package's existing newTestRequestCore/seedUserWithRole
// helpers.
package request

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
)

// #G72: an actor holding only a read-only project role (no roles.assign)
// must be refused — the CLI must not let --by attribute a project's
// access-request list read to an unprivileged account.
func TestRequireListAuthority_UnprivilegedActorRejected(t *testing.T) {
	c, st := newTestRequestCore(t)
	ctx := context.Background()
	actor := seedUserWithRole(t, st, "list-viewer", "project_viewer", core.Scope{ProjectID: 1})

	err := requireListAuthority(ctx, c, actor, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles.assign")
}

// #G72 positive control: an actor holding roles.assign at the project (the
// equivalent HTTP route's requirement) must be allowed through.
func TestRequireListAuthority_AuthorizedActorAllowed(t *testing.T) {
	c, st := newTestRequestCore(t)
	ctx := context.Background()
	actor := seedUserWithRole(t, st, "list-admin", "project_admin", core.Scope{ProjectID: 1})

	require.NoError(t, requireListAuthority(ctx, c, actor, 1))
}

// #G72 positive control: the bootstrap admin created by BootstrapSystem
// itself (the realistic legitimate --by actor for this command) must pass
// too.
func TestRequireListAuthority_BootstrapAdminAllowed(t *testing.T) {
	c, st := newTestRequestCore(t)
	ctx := context.Background()
	bootstrapAdmin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)

	require.NoError(t, requireListAuthority(ctx, c, bootstrapAdmin.ID, 1))
}

// #G72: rejection-reason templates are not project-scoped (unlike the review/
// list checks above), so an actor holding roles.assign at a PROJECT scope —
// not globally — must still be refused: the equivalent HTTP routes gate on a
// global roles.assign.
func TestRequireTemplateAuthority_ProjectScopedActorRejected(t *testing.T) {
	c, st := newTestRequestCore(t)
	ctx := context.Background()
	actor := seedUserWithRole(t, st, "tmpl-project-admin", "project_admin", core.Scope{ProjectID: 1})

	err := requireTemplateAuthority(ctx, c, actor)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles.assign")
}

// #G72: an actor holding only a read-only role must also be refused.
func TestRequireTemplateAuthority_UnprivilegedActorRejected(t *testing.T) {
	c, st := newTestRequestCore(t)
	ctx := context.Background()
	actor := seedUserWithRole(t, st, "tmpl-viewer", "project_viewer", core.Scope{ProjectID: 1})

	err := requireTemplateAuthority(ctx, c, actor)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles.assign")
}

// #G72 positive control: an actor holding roles.assign at global scope (the
// equivalent HTTP routes' requirement) must be allowed through.
func TestRequireTemplateAuthority_GlobalActorAllowed(t *testing.T) {
	c, st := newTestRequestCore(t)
	ctx := context.Background()
	actor := seedUserWithRole(t, st, "tmpl-admin", "system_admin", core.Scope{})

	require.NoError(t, requireTemplateAuthority(ctx, c, actor))
}

// #G72 positive control: the bootstrap admin created by BootstrapSystem
// itself must pass too.
func TestRequireTemplateAuthority_BootstrapAdminAllowed(t *testing.T) {
	c, st := newTestRequestCore(t)
	ctx := context.Background()
	bootstrapAdmin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)

	require.NoError(t, requireTemplateAuthority(ctx, c, bootstrapAdmin.ID))
}
