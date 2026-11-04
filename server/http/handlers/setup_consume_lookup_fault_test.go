package handlers

// setup_consume_lookup_fault_test.go — AUTH-LANE-FOLDS-1 item 3 (ask
// auth-endpoint-outage-1-setup-consume-503, Andrei: "503 pre-verdict only").
//
// POST /auth/setup/consume first looks the token up by hash. A storage fault there
// evaluated nothing: it happens the same way for a valid and a dead token. It used to
// answer the dead-link 400; it now answers 503 + Retry-After (storage_unavailable) and
// hands the per-IP slot back. A fault AFTER the token was found valid keeps the
// dead-link 400 (TestConsumeSetup_PostVerdictPanicAnsweredLikeItsError), since a
// different answer there would confirm the link.

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestConsumeSetup_TokenLookupFaultIs503AndSaysNothingAboutTheToken(t *testing.T) {
	h, c, fs, st, adminID := newUndeliveredSetupFixture(t)
	valid := issueSetupTokenForUserS11(t, c, adminID, "splookup@example.com", "splookup")
	slots := func() int64 {
		var n int64
		require.NoError(t, st.DB().Model(&models.LoginAttempt{}).Count(&n).Error)
		return n
	}

	answers := map[string]string{}
	for name, token := range map[string]string{"valid": valid, "dead": "kx_setup_not-a-real-token"} {
		before := slots()
		fs.Arm(&faultstorage.FaultSpec{Method: setupConsumeVerdictMethod, NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected lookup fault")})
		body := fmt.Sprintf(`{"token":%q,"password":%q}`, token, undeliveredSetupPassword+"x")
		w := httptest.NewRecorder()
		h.ConsumeSetup(w, httptest.NewRequest(http.MethodPost, "/auth/setup/consume", strings.NewReader(body)))
		require.True(t, fs.Fired(), "%s: the lookup fault must be reached", name)
		fs.Arm(nil)

		assertStorageUnavailable503(t, w)
		assert.NotContains(t, w.Body.String(), "injected", "%s: no storage text in the body", name)
		assert.Equal(t, before, slots(), "%s: nothing was evaluated, so the slot goes back", name)
		answers[name] = fmt.Sprintf("%d %s %s", w.Code, w.Header().Get("Retry-After"), w.Body.String())
	}
	assert.Equal(t, answers["dead"], answers["valid"], "a lookup fault must not distinguish a valid token from a dead one")

	// The link still works once storage is back: nothing was consumed.
	ok := postSetupConsume(t, h, valid)
	assert.Equal(t, http.StatusOK, ok.status, ok.body)
}
