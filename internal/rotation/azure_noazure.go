// azure_noazure.go — noazure-build sibling of azure_sdk.go (ADR-109 step 6).
// Registers nothing: the azure-app rotation backend is not available in a
// build tagged noazure, so rotation.LookupCloudExecutor("azure-app") reports
// not-found. Unlike the other no<x> siblings in this package, azure.go itself
// (the type, business logic and net/http Graph client) stays compiled even
// here — see its doc comment — so this file only needs to supply the
// always-erroring azureTokenSource, keeping newAzureTokenSource non-nil and
// AzureAppSecretExecutor.client() failing closed with a clear message if it
// is ever reached (e.g. constructed directly rather than through the
// registry) instead of a nil-func panic.
//
//go:build noazure

package rotation

import "fmt"

func init() {
	newAzureTokenSource = func() (azureTokenSource, error) {
		return nil, fmt.Errorf("azure SDK not available in this build (compiled with -tags noazure); rebuild without that tag to use this backend")
	}
}
