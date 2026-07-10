package machine

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestPrintMachineTable_Empty(t *testing.T) {
	out := captureStdout(t, func() {
		printMachineTable(nil, "my-project")
	})
	assert.Contains(t, out, "No machine identities found")
	assert.Contains(t, out, "my-project")
}

func TestPrintMachineTable_Rows(t *testing.T) {
	m := &models.MachineIdentity{
		Name:         "ci-runner",
		IdentityType: "ci",
		State:        "active",
		Description:  "main pipeline runner",
	}
	m.ID = 7
	out := captureStdout(t, func() {
		printMachineTable([]*models.MachineIdentity{m}, "dev")
	})
	assert.Contains(t, out, "ci-runner")
	assert.Contains(t, out, "active")
	assert.Contains(t, out, fmt.Sprintf("%d", m.ID))
}

func TestPrintMachineTable_LongDescriptionTruncated(t *testing.T) {
	long := "A" + string(make([]byte, 50))
	m := &models.MachineIdentity{Name: "x", IdentityType: "other", State: "active", Description: long}
	out := captureStdout(t, func() {
		printMachineTable([]*models.MachineIdentity{m}, "proj")
	})
	assert.Contains(t, out, "...")
}

func TestCreateCmd_NameRequired(t *testing.T) {
	orig := createName
	defer func() { createName = orig }()
	createName = ""
	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--name is required")
}

func TestBindingAddCmd_IssuerAndSubjectRequired(t *testing.T) {
	origI, origS := bindingIssuer, bindingSubject
	defer func() { bindingIssuer = origI; bindingSubject = origS }()

	bindingIssuer = ""
	bindingSubject = ""
	err := runBindingAdd(nil, []string{"ci-runner"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--issuer and --subject are required")

	bindingIssuer = "https://accounts.google.com"
	bindingSubject = ""
	err = runBindingAdd(nil, []string{"ci-runner"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--issuer and --subject are required")
}

func TestBindingRmCmd_InvalidBindingID(t *testing.T) {
	err := runBindingRm(nil, []string{"ci-runner", "not-a-number"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid binding ID")
}

func TestTokenHygieneCmd_Registered(t *testing.T) {
	cmd, _, err := MachineCmd.Find([]string{"token-hygiene"})
	require.NoError(t, err)
	assert.NotNil(t, cmd.Flags().Lookup("days"))
}
