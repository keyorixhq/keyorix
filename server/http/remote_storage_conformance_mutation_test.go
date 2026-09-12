// remote_storage_conformance_mutation_test.go — issue #1808: validates that the
// differential conformance harness (remote_storage_conformance_test.go) actually
// detects what it claims to.
//
// Layer 1 (#1800, remote_proxy_correctness_audit_test.go) shipped after red/green
// and mutation-kill testing on its OWN checks, and a historical-positive replay
// still found it caught 0 of 9 real defects — the checks were validated against
// mutations of themselves, never against the actual historical bug shapes. This
// file exists so that mistake is not repeated here: for five of the seven defect
// classes (at least three were required), it faithfully reintroduces the exact
// historical bug shape and demonstrates the differential harness's assertions --
// not merely the same Go source, since that source lives in an unexported,
// different package (internal/storage/store) this test package cannot reach into
// without either modifying real production files (rejected: risky, and this repo's
// standing practice is never to leave a workaround in place of a real fix) or
// literally replaying the pre-fix git tree (rejected for all five: the checks this
// harness's assertions depend on — real router wiring, ADR-085's node-credential
// role-grant requirement — postdate several of these fixes, so an old tree would
// need its OWN period-accurate test scaffold, which is a materially different and
// much larger undertaking than reproducing the wire-level bug itself). Each test
// below performs the exact HTTP request (or exact cache-sharing call, or exact
// client-side context-handling shape) the pre-fix RemoteStorage method used to
// perform — using rs's own auth token, against the SAME real server the seed
// tests use — and shows the outcome differs from the real, fixed proxy method,
// in the specific way the historical defect did.
//
// Every class demonstrated: 1 (Health envelope), 3 (AllowedCIDRs field drop), 4
// (GetSecretByName wrong route), 6 (LockUserForUpdate cache staleness), 7
// (LogAuditEvent context lifetime — see that test's own doc comment for why
// this one was added after the other four and why it is the one class where a
// green check didn't just miss the defect, it certified it as correct).
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// doAuthedRequest performs a raw HTTP request directly against the harness's real
// server, independent of RemoteStorage's own client -- used only to construct a
// faithful reintroduction of a historical wire-shape bug (see package doc). It
// deliberately does NOT go through package store (whose RemoteStorage internals
// are unexported and unreachable from this package), so it cannot silently drift
// from what it claims to send -- the JSON body below IS the request.
func doAuthedRequest(t *testing.T, method, rawURL, token string, body interface{}) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, rawURL, reader)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, respBody
}

type mutationEnvelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
}

// --- Class 1: Health envelope mismatch ---

func TestMutation_Health_EnvelopeMismatch_Class1(t *testing.T) {
	h := newConformanceHarness(t)

	require.NoError(t, h.rs.Health(context.Background()),
		"sanity: the real (fixed) RemoteStorage.Health must report healthy against a real, healthy server")

	// Faithful reintroduction of the historical class-1 bug: /health returns a
	// bare {"status":"healthy",...} body with no {success,data} envelope at all,
	// so unmarshaling it into an APIResponse-shaped struct leaves Success at its
	// Go zero value (false) -- this is exactly what the pre-fix Health() checked.
	resp, body := doAuthedRequest(t, http.MethodGet, h.server.URL+"/health", h.nodeToken, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "the server itself is genuinely healthy (2xx)")
	var envelope mutationEnvelope
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.False(t, envelope.Success,
		"faithful reintroduction of the historical class-1 bug: /health's response has no success field, so "+
			"decoding it as an enveloped response leaves Success false even though the server just answered "+
			"200 OK -- the pre-fix RemoteStorage.Health() checked exactly this field and so reported every "+
			"genuinely healthy server as unhealthy, which is what the real (fixed) rs.Health(ctx) call above "+
			"proves it no longer does")
}

// --- Class 3: CreateMachineIdentityCredential — AllowedCIDRs field drop ---

// brokenMachineIdentityCredentialWire mirrors the pre-fix
// machineIdentityCredentialWire (internal/storage/store/remote_machine_identities.go)
// field-for-field, MINUS allowed_cidrs -- the actual historical omission.
type brokenMachineIdentityCredentialWire struct {
	MachineIdentityID uint       `json:"machine_identity_id"`
	Name              string     `json:"name"`
	TokenHash         string     `json:"token_hash"`
	TokenPrefix       string     `json:"token_prefix"`
	LastUsedAt        *time.Time `json:"last_used_at"`
	ExpiresAt         *time.Time `json:"expires_at"`
	Revoked           bool       `json:"revoked"`
	Classification    string     `json:"classification"`
}

func TestMutation_CreateMachineIdentityCredential_AllowedCIDRsDropped_Class3(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "mutation-mic", core.MachineTypeNode, "mutation test node", "", h.adminUserID, 0)
	require.NoError(t, err)

	const wantCIDRs = "10.0.0.0/8,192.168.1.0/24"

	// Sanity: the real (fixed) proxy round-trips AllowedCIDRs.
	fixedOut, err := h.rs.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
		MachineIdentityID: mi.ID, Name: "mutation-cred-fixed", TokenHash: "mutation-hash-fixed",
		TokenPrefix: "kxm_fix", AllowedCIDRs: wantCIDRs, Classification: "internal",
	})
	require.NoError(t, err)
	require.Equal(t, wantCIDRs, fixedOut.AllowedCIDRs, "sanity: the real (fixed) proxy must round-trip AllowedCIDRs")

	// Faithful reintroduction: hand-send the pre-fix wire payload (no
	// allowed_cidrs field present at all) to the real, unmodified server. The
	// server doesn't care who constructed the request -- only whether the field
	// is in the JSON, which is exactly what the historical bug got wrong client-side.
	resp, body := doAuthedRequest(t, http.MethodPost, h.server.URL+"/api/v1/system/machine-credentials", h.nodeToken,
		brokenMachineIdentityCredentialWire{
			MachineIdentityID: mi.ID, Name: "mutation-cred-broken", TokenHash: "mutation-hash-broken",
			TokenPrefix: "kxm_brk", Classification: "internal",
		})
	require.Equal(t, http.StatusOK, resp.StatusCode, "the broken request must still nominally succeed -- the bug is silent field loss, not an error")
	var envelope mutationEnvelope
	require.NoError(t, json.Unmarshal(body, &envelope))
	var decoded struct {
		AllowedCIDRs string `json:"allowed_cidrs"`
	}
	require.NoError(t, json.Unmarshal(envelope.Data, &decoded))

	assert.Empty(t, decoded.AllowedCIDRs,
		"faithful reintroduction of the historical class-3 bug: a wire payload that omits allowed_cidrs "+
			"entirely must persist an empty IP allowlist server-side regardless of what the real caller "+
			"intended -- this is exactly the field-exhaustive comparison in "+
			"TestConformance_CreateMachineIdentityCredential would have failed against, and exactly what the "+
			"real (fixed) proxy call above (wantCIDRs round-tripping intact) proves does not happen today")
}

// --- Class 4: GetSecretByName — wrong route ---

func TestMutation_GetSecretByName_WrongRoute_Class4(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	secret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "mutation-gsbn-secret", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password",
	})
	require.NoError(t, err)

	// Sanity: the real (fixed) proxy finds it via the real, registered route.
	_, err = h.rs.GetSecretByName(ctx, secret.Name, h.projectID, h.environmentID)
	require.NoError(t, err, "sanity: the real (fixed) RemoteStorage.GetSecretByName must find a secret that exists")

	// Faithful reintroduction of the historical class-4 bug: request the
	// PATH-SEGMENT form (/api/v1/secrets/by-name/{name}) the pre-fix code sent,
	// instead of the real, registered query-parameter form (?name=...).
	brokenURL := fmt.Sprintf("%s/api/v1/secrets/by-name/%s", h.server.URL, url.PathEscape(secret.Name))
	resp, _ := doAuthedRequest(t, http.MethodGet, brokenURL, h.nodeToken, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"faithful reintroduction of the historical class-4 bug: the pre-fix path-segment route was never "+
			"registered server-side (server/http/router.go), so a request against it 404s regardless of "+
			"whether the secret exists -- exactly what the real (fixed) rs.GetSecretByName call above, "+
			"which found the secret via the query-parameter form, proves does not happen today")
}

// --- Class 6: LockUserForUpdate — cache staleness ---

func TestMutation_LockUserForUpdate_CacheStaleness_Class6(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	user, err := h.ls.CreateUser(ctx, &models.User{
		Username: "mutation-lufu", Email: "mutation-lufu@example.com",
		DisplayName: "Mutation LockUserForUpdate", IsActive: true,
	})
	require.NoError(t, err)

	// Warm RemoteStorage's 5-minute response cache -- same warming step the
	// class-6 seed test uses.
	cached, err := h.rs.GetUser(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, 0, cached.FailedLoginAttempts)

	// A concurrent writer lands in the window between the cache-warming GetUser
	// and the lock -- e.g. another replica's own failed-login accounting.
	fresh, err := h.ls.GetUser(ctx, user.ID)
	require.NoError(t, err)
	const wantAttempts = 9
	fresh.FailedLoginAttempts = wantAttempts
	_, err = h.ls.UpdateUser(ctx, fresh)
	require.NoError(t, err)

	// Sanity: the real (fixed) LockUserForUpdate bypasses the cache and sees the fresh write.
	locked, err := h.rs.LockUserForUpdate(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, wantAttempts, locked.FailedLoginAttempts, "sanity: the real (fixed) LockUserForUpdate must observe the fresh value")

	// Faithful reintroduction of the historical class-6 bug: the pre-fix
	// LockUserForUpdate body WAS a call to GetUser (remote_users.go's own doc:
	// "Before this fix, LockUserForUpdate simply called GetUser"). rs.GetUser
	// itself is that exact cached path, unchanged -- calling it again here
	// reproduces precisely what the pre-fix LockUserForUpdate did.
	staleRead, err := h.rs.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.NotEqual(t, wantAttempts, staleRead.FailedLoginAttempts,
		"faithful reintroduction of the historical class-6 bug: GetUser's own 5-minute response cache still "+
			"holds the pre-write snapshot (FailedLoginAttempts=0) from the cache-warming call above, up to 5 "+
			"minutes stale -- exactly the staleness LockUserForUpdate exists to bypass, and exactly what the "+
			"real (fixed) rs.LockUserForUpdate call above does not exhibit. TestConformance_LockUserForUpdate's "+
			"assertion (locked.FailedLoginAttempts == the fresh value, not just err == nil) is precisely the "+
			"shape of check that catches this -- an err == nil check alone would pass on both the fixed and "+
			"the broken path")
}

// --- Class 7: LogAuditEvent — context lifetime, not identity ---

// This class is a different SHAPE of reintroduction than 1/3/4/6 above: the
// historical bug (#1650) is not a wire-payload or route difference an
// unmodified server can distinguish -- it is a CLIENT-SIDE behavioral defect.
// The real, fixed RemoteStorage.LogAuditEvent (remote_audit.go) detaches from
// the caller's own context via auditWriteContext before the outbound POST
// /api/v1/system/audit/event call; the pre-#1650 code forwarded the caller's
// context verbatim instead. Faithfully reintroducing that means replaying the
// exact request the fixed proxy sends (same route, same JSON body, same
// bearer token) but wiring the caller's own already-cancelled context
// directly into the outbound *http.Request -- exactly what "forward instead
// of detach" does at the net/http layer.
//
// This is also the specific class remote_proxy_correctness_audit_test.go's
// check 3 (context-substitution) does not merely miss -- it actively
// CERTIFIES this shape as correct, because check 3's own definition of
// "correct" is verbatim ctx forwarding (see that file's class-7 note).
// TestConformance_LogAuditEvent's cancelled-context subtest (#1650, class 7)
// demonstrates today's FIXED behavior; until this test existed, nothing had
// shown that same subtest's assertions would actually have gone red against
// the real pre-fix shape -- the exact gap this whole file exists to close
// for the other four classes, left open for class 7 until now.
func TestMutation_LogAuditEvent_ContextForwardedVerbatim_Class7(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	// Sanity: the real (fixed) proxy detaches and persists despite an
	// already-cancelled caller context -- TestConformance_LogAuditEvent's own
	// cancelled-context subtest, repeated here so this test carries its own
	// proof rather than depending on another test having run first.
	fixedEvent := &models.AuditEvent{
		EventType: "mutation.logauditevent.class7.fixed", IPAddress: "203.0.113.50",
		Description: fmt.Sprintf("mutation class7 fixed %d", time.Now().UnixNano()),
		EventTime:   time.Now().UTC(),
	}
	require.NoError(t, h.rs.LogAuditEvent(cancelledCtx, fixedEvent),
		"sanity: the real (fixed) RemoteStorage.LogAuditEvent must detach from an already-cancelled caller context")
	require.NotNil(t, findAuditEventByDescription(t, h.ls, ctx, fixedEvent.Description),
		"sanity: the fixed proxy's write must actually be persisted server-side, not just return a nil error")

	// Faithful reintroduction of the historical class-7 bug: the IDENTICAL
	// request the fixed rs.LogAuditEvent constructs, except the caller's own
	// already-cancelled context is wired straight into the *http.Request
	// instead of a detached one.
	brokenEvent := &models.AuditEvent{
		EventType: "mutation.logauditevent.class7.broken", IPAddress: "203.0.113.51",
		Description: fmt.Sprintf("mutation class7 broken %d", time.Now().UnixNano()),
		EventTime:   time.Now().UTC(),
	}
	body, err := json.Marshal(brokenEvent)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(cancelledCtx, http.MethodPost, h.server.URL+"/api/v1/system/audit/event", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+h.nodeToken)
	req.Header.Set("Content-Type", "application/json")

	_, doErr := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.Error(t, doErr,
		"faithful reintroduction of the historical class-7 bug: an *http.Request built from an already-cancelled "+
			"context must fail before a single byte reaches the wire -- exactly what RemoteStorage.LogAuditEvent "+
			"did pre-#1650, when it forwarded the caller's own context instead of detaching it via auditWriteContext")
	assert.ErrorIs(t, doErr, context.Canceled,
		"the failure must be attributable to context cancellation specifically, not some unrelated transport error "+
			"that would make this reintroduction unfaithful to the actual historical bug")

	assert.Nil(t, findAuditEventByDescription(t, h.ls, ctx, brokenEvent.Description),
		"the broken (pre-#1650-shaped) request must never have reached the server at all, so the event must NOT "+
			"be persisted -- this is exactly the shape TestConformance_LogAuditEvent's cancelled-context subtest "+
			"would go red against: its require.NoError(rs.LogAuditEvent(...)) assertion fails (an error IS "+
			"returned) and its require.NotNil(findAuditEventByDescription(...)) assertion fails (nothing was "+
			"persisted) -- the exact pair of failures a verbatim-ctx-forwarding LogAuditEvent would have produced, "+
			"and the reason check 3's 'ctx forwarded verbatim = correct' verdict is actively wrong on this path")
}
