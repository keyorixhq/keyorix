// campaign_terminal_injection_test.go — #G69: the campaign show table printed
// attacker-controlled principal name/email/secret name/role name (and the
// campaign's own operator-chosen name, echoed back by the server) straight
// through fmt.Printf with no sanitization, letting the reviewed principal
// hide or spoof their own recertification row.
package accessreview

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCampaignShow_NeutralizesEscapeSequences(t *testing.T) {
	malicious := "\x1b[1A\x1b[2K  + spoofed clean row"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := struct {
			Campaign campaignView `json:"campaign"`
			Items    []itemView   `json:"items"`
			Progress progressView `json:"progress"`
		}{
			Campaign: campaignView{ID: 1, Name: malicious, State: "open"},
			Items: []itemView{{
				ID: 1, PrincipalType: "user", PrincipalName: malicious, Email: malicious,
				Source: "owner", SecretName: malicious, AccessLevel: "read", Decision: "pending",
			}},
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": body})
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origCampaign := cProject, cCampaign
	t.Cleanup(func() { cProject, cCampaign = origProject, origCampaign })
	cProject, cCampaign = 1, 1

	out, err := captureStdout(t, func() error { return campaignShowCmd.RunE(campaignShowCmd, nil) })
	require.NoError(t, err)
	assert.NotContains(t, out, "\x1b")
}
