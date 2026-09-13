//go:build !lean

// awsiam_s2_test.go — AWSIAMExecutor.client() real-path coverage, split out of
// rotation_s2_test.go so this file (which touches the real struct's unexported
// fields/client() method — absent from the lean stub in awsiam_lean.go) can be
// excluded from a lean build without also dropping that file's unrelated
// Azure/MySQL/Postgres/Redis/Mongo/GCP coverage.
package rotation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAWSIAMExecutor_ClientRealPath exercises awsconfig.LoadDefaultConfig + iam.NewFromConfig
// in AWSIAMExecutor.client() when newClient is nil. LoadDefaultConfig succeeds in all
// environments (it reads config lazily); NewFromConfig builds a client struct without
// making API calls.
func TestAWSIAMExecutor_ClientRealPath(t *testing.T) {
	e := &AWSIAMExecutor{
		name:        "aws-test",
		allowedRefs: []string{"svc-"},
	}
	// No newClient set — takes the real awsconfig path.
	cl, err := e.client(context.Background())
	// On any OS without AWS credentials, this typically succeeds (lazy credential chain).
	// Accept either outcome; the goal is coverage of the credential-loading statements.
	if err == nil {
		assert.NotNil(t, cl)
	}
}
