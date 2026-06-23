package rotation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchRotationPlan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects/1/rotation-plan" {
			_, _ = w.Write([]byte(`{"data":{"project_id":1,"total_secrets":2,"overdue_count":1,"due_soon_count":1,"waves":[
				{"index":0,"secrets":[{"secret_id":12,"secret_name":"root-ca","status":"overdue","days_overdue":110,"risk_band":"high","auto_rotate":false,"reasons":["110 days overdue","high risk (score 78)"]}]},
				{"index":1,"secrets":[{"secret_id":11,"secret_name":"app-token","status":"due_soon","days_overdue":-10,"risk_band":"low","auto_rotate":true,"reasons":["due in 10 days","rotate after root-ca"]}]}
			]}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	plan, err := fetchRotationPlan(context.Background(), rc, 1)
	require.NoError(t, err)
	assert.Equal(t, 2, plan.TotalSecrets)
	assert.Equal(t, 1, plan.OverdueCount)
	require.Len(t, plan.Waves, 2)
	assert.Equal(t, "root-ca", plan.Waves[0].Secrets[0].SecretName)
	assert.Equal(t, "overdue", plan.Waves[0].Secrets[0].Status)
	assert.Equal(t, 110, plan.Waves[0].Secrets[0].DaysOverdue)
	assert.True(t, plan.Waves[1].Secrets[0].AutoRotate)
	assert.Contains(t, plan.Waves[1].Secrets[0].Reasons, "rotate after root-ca")
}

func TestStatusAndRiskLabels(t *testing.T) {
	assert.Equal(t, "30d over", statusLabel(plannedRotation{Status: "overdue", DaysOverdue: 30}))
	assert.Equal(t, "10d left", statusLabel(plannedRotation{Status: "due_soon", DaysOverdue: -10}))
	assert.Equal(t, "high risk", riskLabel("high"))
	assert.Equal(t, "", riskLabel(""))
	assert.Equal(t, "  (self-rotating)", autoRotateLabel(true))
}
