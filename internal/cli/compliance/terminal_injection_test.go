// terminal_injection_test.go — #G69: the permission-change audit table printed
// attacker-controlled actor/target/role text straight through fmt.Printf with
// no sanitization in this auditor-facing evidence output.
package compliance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPermissionChanges_NeutralizesEscapeSequences(t *testing.T) {
	malicious := "\x1b[1A\x1b[2K  + spoofed clean row"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		report := permChangeReport{
			Since: time.Now(), Until: time.Now(), Total: 1,
			Changes: []permChangeEvent{{
				EventID: 1, Action: "role.assigned", ActorName: malicious, TargetUser: malicious,
				RoleName: malicious, Scope: malicious, ChangedAt: time.Now(),
			}},
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": report})
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	out := captureStdout(t, func() { require.NoError(t, permissionChangesCmd.RunE(permissionChangesCmd, nil)) })
	assert.NotContains(t, out, "\x1b")
}
