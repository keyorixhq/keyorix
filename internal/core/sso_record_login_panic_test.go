// sso_record_login_panic_test.go — found by the #2910 fault sweep
// (UpdateLastLogin#1/panic on both SSO ops). CompleteSAML and CompleteSSO
// stamped the last login inline (`_ = c.RecordLogin(...)`) AFTER mintSession.
// The `_ =` swallows an error but not a panic. A panic there unwound past an
// already-committed session, so the transport reported the login as failed
// (500, no cookie) and left an orphan session row behind. Every other login
// path already runs the same stamp panic-safe (goSafe in the handlers), and
// mintSession's own best-effort step uses besteffort.Run, which was #2416's fix
// for exactly this class.
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/ports"
)

// RED before the fix: the panic escapes CompleteSAML.
func TestCompleteSAML_RecordLoginPanicDoesNotMaskTheLogin(t *testing.T) {
	f := newSAMLReconcileFixture(t, &ports.SAMLAssertion{Subject: "corp|123"}, nil)
	f.fault.panicUpdateLastLogin = true

	var err error
	require.NotPanics(t, func() { _, err = f.login() },
		"a best-effort last-login stamp must not unwind past an already-minted session")
	require.NoError(t, err)
	assert.EqualValues(t, 1, f.sessions())
	assert.Len(t, f.events(EventSSOLogin), 1, "the login completed and is audited as such")
}

// RED before the fix: the panic escapes CompleteSSO.
func TestCompleteSSO_RecordLoginPanicDoesNotMaskTheLogin(t *testing.T) {
	f := newOIDCReconcileFixture(t, nil, nil)
	f.fault.panicUpdateLastLogin = true

	var err error
	require.NotPanics(t, func() { _, err = f.login() })
	require.NoError(t, err)
	assert.EqualValues(t, 1, f.sessions())
	assert.Len(t, f.events(EventSSOLogin), 1)
}
