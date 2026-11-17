//go:build noazure

package main

// boot_exit_azure_stub.go -- the noazure counterpart of boot_exit_azure.go:
// no Azure SDK is linked, so no error is an Azure error.

func isAzureServiceUnavailable(error) bool { return false }

func isTokenRequestUnanswered(error) bool { return false }
