// rotation_s2_test.go — sprint-2 coverage for printProjectPlan, printDeploymentPlan,
// autoRotateLabel false path, and order/plan print output not covered by existing tests.
package rotation

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureRotationOutput redirects os.Stdout for the duration of fn and returns
// the captured bytes. Named differently from other capture helpers to avoid
// redeclaration across files in this package.
func captureRotationOutput(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdout
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out)
}

// TestPrintProjectPlan_Empty verifies printProjectPlan prints a header even
// with zero waves.
func TestPrintProjectPlan_Empty(t *testing.T) {
	plan := &rotationPlanView{ProjectID: 7, TotalSecrets: 0, Waves: nil}
	out := captureRotationOutput(t, func() { printProjectPlan(plan, "") })
	assert.Contains(t, out, "project 7")
	assert.Contains(t, out, "0 to rotate")
}

// TestPrintProjectPlan_WithWaves verifies header and per-secret output for a
// multi-wave plan.
func TestPrintProjectPlan_WithWaves(t *testing.T) {
	plan := &rotationPlanView{
		ProjectID:    3,
		TotalSecrets: 2,
		OverdueCount: 1,
		DueSoonCount: 1,
		Waves: []rotationWave{
			{
				Index: 0,
				Secrets: []plannedRotation{
					{SecretID: 10, SecretName: "root-ca", Status: "overdue", DaysOverdue: 30, RiskBand: "high", AutoRotate: false, Reasons: []string{"30 days overdue"}},
				},
			},
			{
				Index: 1,
				Secrets: []plannedRotation{
					{SecretID: 11, SecretName: "app-cert", Status: "due_soon", DaysOverdue: -5, RiskBand: "", AutoRotate: true},
				},
			},
		},
	}
	out := captureRotationOutput(t, func() { printProjectPlan(plan, "") })
	assert.Contains(t, out, "project 3")
	assert.Contains(t, out, "2 to rotate")
	assert.Contains(t, out, "Wave 1")
	assert.Contains(t, out, "root-ca")
	assert.Contains(t, out, "high risk")
	assert.Contains(t, out, "30 days overdue")
	assert.Contains(t, out, "self-rotating")
}

// TestPrintProjectPlan_WithIndent verifies the indent prefix is applied.
func TestPrintProjectPlan_WithIndent(t *testing.T) {
	plan := &rotationPlanView{ProjectID: 1, Waves: nil}
	out := captureRotationOutput(t, func() { printProjectPlan(plan, "  ") })
	assert.Contains(t, out, "  Rotation plan")
}

// TestPrintDeploymentPlan_NoWork verifies the "nothing to rotate" fast-path.
func TestPrintDeploymentPlan_NoWork(t *testing.T) {
	plan := &deploymentPlanView{ProjectsScanned: 5, ProjectsWithWork: 0}
	out := captureRotationOutput(t, func() { printDeploymentPlan(plan) })
	assert.Contains(t, out, "Nothing to rotate")
	assert.Contains(t, out, "5 project")
}

// TestPrintDeploymentPlan_WithProjects verifies the multi-project roll-up header.
func TestPrintDeploymentPlan_WithProjects(t *testing.T) {
	plan := &deploymentPlanView{
		ProjectsScanned:  3,
		ProjectsWithWork: 2,
		TotalSecrets:     4,
		OverdueCount:     2,
		DueSoonCount:     2,
		Projects: []rotationPlanView{
			{ProjectID: 7, TotalSecrets: 2, OverdueCount: 2, Waves: []rotationWave{
				{Index: 0, Secrets: []plannedRotation{
					{SecretID: 1, SecretName: "cert-a", Status: "overdue", DaysOverdue: 10, AutoRotate: false},
				}},
			}},
			{ProjectID: 2, TotalSecrets: 2, DueSoonCount: 2, Waves: nil},
		},
	}
	out := captureRotationOutput(t, func() { printDeploymentPlan(plan) })
	assert.Contains(t, out, "Deployment rotation plan")
	assert.Contains(t, out, "4 to rotate")
	assert.Contains(t, out, "project 7")
	assert.Contains(t, out, "cert-a")
}

// TestAutoRotateLabel_False verifies that autoRotateLabel returns "" for false.
func TestAutoRotateLabel_False(t *testing.T) {
	assert.Equal(t, "", autoRotateLabel(false))
}

// TestOrderCmd_EmptyOrder verifies the "secrets can rotate in any order" branch.
func TestOrderCmd_EmptyOrder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"project_id":1,"order":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	out := captureRotationOutput(t, func() {
		require.NoError(t, orderCmd.RunE(orderCmd, []string{"1"}))
	})
	assert.Contains(t, out, "any order")
}

// TestOrderCmd_WithDeps verifies the numbered list output when dependencies exist.
func TestOrderCmd_WithDeps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"project_id":5,"order":[{"secret_id":1,"secret_name":"root-ca"},{"secret_id":2,"secret_name":"leaf-cert"}]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	out := captureRotationOutput(t, func() {
		require.NoError(t, orderCmd.RunE(orderCmd, []string{"5"}))
	})
	assert.Contains(t, out, "project 5")
	assert.Contains(t, out, "root-ca")
	assert.Contains(t, out, "leaf-cert")
}

// TestPlanCmd_WithWaves verifies that a non-empty plan prints wave output.
func TestPlanCmd_WithWaves(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"project_id":1,"total_secrets":1,"overdue_count":1,"due_soon_count":0,"waves":[{"index":0,"secrets":[{"secret_id":5,"secret_name":"api-key","status":"overdue","days_overdue":15,"risk_band":"low","auto_rotate":false,"reasons":["15 days overdue"]}]}]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	planAllProjects = false
	t.Cleanup(func() { planAllProjects = false })

	out := captureRotationOutput(t, func() {
		require.NoError(t, planCmd.RunE(planCmd, []string{"1"}))
	})
	assert.Contains(t, out, "api-key")
}

// TestPlanCmd_AllProjectsWithWork verifies the deployment-wide plan is printed
// when --all-projects is set and projects have work.
func TestPlanCmd_AllProjectsWithWork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects_scanned":2,"projects_with_work":1,"total_secrets":1,"overdue_count":1,"due_soon_count":0,"projects":[{"project_id":3,"total_secrets":1,"overdue_count":1,"due_soon_count":0,"waves":[{"index":0,"secrets":[{"secret_id":9,"secret_name":"db-pw","status":"overdue","days_overdue":5,"risk_band":"medium","auto_rotate":false,"reasons":["5 days overdue"]}]}]}]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	planAllProjects = true
	t.Cleanup(func() { planAllProjects = false })

	out := captureRotationOutput(t, func() {
		require.NoError(t, planCmd.RunE(planCmd, []string{}))
	})
	assert.Contains(t, out, "Deployment rotation plan")
	assert.Contains(t, out, "db-pw")
}
