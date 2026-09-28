// azure_sdk.go — the ONLY file in this package that imports azure-sdk-for-go
// (ADR-109 step 6). It supplies the real, azidentity-backed azureTokenSource
// (see azure.go's doc comment for why that seam exists) and registers the
// azure-app rotation executor. A noazure build excludes this file entirely
// (see azure_noazure.go's stub) and its `go list -deps` therefore carries no
// azure-sdk-for-go package.
//
//go:build !noazure

package rotation

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// realAzureTokenSource adapts azidentity.DefaultAzureCredential to azureTokenSource.
type realAzureTokenSource struct {
	cred *azidentity.DefaultAzureCredential
}

func (r *realAzureTokenSource) Token(ctx context.Context) (string, error) {
	tok, err := r.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureGraphScope}})
	if err != nil {
		return "", fmt.Errorf("acquire graph token: %w", err)
	}
	return tok.Token, nil
}

func init() {
	newAzureTokenSource = func() (azureTokenSource, error) {
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("default credential: %w", err)
		}
		return &realAzureTokenSource{cred: cred}, nil
	}
	registerCloudExecutor("azure-app", func(p CloudExecutorParams) Executor {
		return NewAzureAppSecretExecutor(p.Name, p.AllowedRefs)
	})
}
