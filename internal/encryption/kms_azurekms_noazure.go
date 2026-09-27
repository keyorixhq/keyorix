// kms_azurekms_noazure.go — noazure-build sibling of kms_azurekms.go
// (ADR-109 step 6). Registers nothing: the azure-kms key provider is not
// available in a build tagged noazure, and buildSingleProvider's "azure-kms"
// case fails closed with a clear "not available in this build" error instead
// of the Azure SDK ever being linked in.
//
//go:build noazure

package encryption
