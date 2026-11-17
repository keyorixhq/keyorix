//go:build !noazure

package main

// boot_exit_azure.go -- the Azure half of the boot-exit classification
// (EDGE-STARTUP-NOV-1). It lives in its own file so that an air-gapped build
// (-tags noazure) does not link the Azure SDK just to classify an error;
// boot_exit_azure_stub.go is the counterpart that never matches.

import (
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// isAzureServiceUnavailable reports whether err is an Azure response that says
// "not now" (5xx or 429) rather than "no".
func isAzureServiceUnavailable(err error) bool {
	re, ok := errors.AsType[*azcore.ResponseError](err)
	return ok && transientHTTP(re.StatusCode)
}

// isTokenRequestUnanswered reports whether err is an Azure token request
// (azure-kms authenticates to Entra ID before it calls the vault) that got no
// answer or a "not now" answer. azidentity's *AuthenticationFailedError keeps
// the cause of a request that failed (a refused dial, a DNS failure, a
// timeout) only as message text, with no Unwrap, so isNetworkFailure cannot
// see it; its RawResponse is nil exactly when Entra ID did not answer. An
// answer of 5xx or 429 may come back too. Any other answer (400 invalid_client,
// 401: a wrong secret or application) is a refusal. No credential configured
// at all is azidentity's credentialUnavailableError, a different type, and
// stays a refusal.
//
// What this does not tell apart: a nil RawResponse also covers a local failure
// inside azidentity before the request (a client assertion that could not be
// read). That is retried rather than stopped, the direction that fails soft.
func isTokenRequestUnanswered(err error) bool {
	afe, ok := errors.AsType[*azidentity.AuthenticationFailedError](err)
	if !ok {
		return false
	}
	if afe.RawResponse == nil {
		return true
	}
	return transientHTTP(afe.RawResponse.StatusCode)
}
