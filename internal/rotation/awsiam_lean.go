//go:build lean

// awsiam_lean.go — lean-build stand-in for awsiam.go. Keeps the same exported
// surface (NewAWSIAMExecutor, AWSIAMExecutor.Name/Type/Rotate/GenerateUpstream)
// so server/main.go's unconditional `case "aws-iam":` wiring compiles either
// way, but drops the aws-sdk-go-v2/service/iam import entirely. A config that
// still names an "aws-iam" rotation backend fails LOUDLY at rotation time with
// a clear "not built into this binary" error — never a silent no-op — so an
// operator who deploys the lean binary against a config written for the full
// one finds out immediately, not the first time a scheduled rotation silently
// does nothing.
package rotation

import (
	"context"
	"fmt"
)

// AWSIAMExecutor is the lean-build stand-in for the real executor in awsiam.go.
type AWSIAMExecutor struct {
	name string
}

// NewAWSIAMExecutor builds a lean-build stand-in with the same signature as the
// real constructor; region and allowedRefs are accepted (so callers need no
// build-tag-specific code) but unused.
func NewAWSIAMExecutor(name, _ string, _ []string) *AWSIAMExecutor {
	return &AWSIAMExecutor{name: name}
}

func (e *AWSIAMExecutor) Name() string { return e.name }
func (e *AWSIAMExecutor) Type() string { return "aws-iam" }

func (e *AWSIAMExecutor) Rotate(_ context.Context, _, _ string) error {
	return fmt.Errorf("aws-iam: not available in this lean build (compiled with -tags lean); rebuild without the lean tag to use this backend")
}

func (e *AWSIAMExecutor) GenerateUpstream(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("aws-iam: not available in this lean build (compiled with -tags lean); rebuild without the lean tag to use this backend")
}
