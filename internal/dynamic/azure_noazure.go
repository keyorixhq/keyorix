// azure_noazure.go — noazure-build sibling of azure.go (ADR-109 step 6).
// Registers nothing: the azure dynamic-secret backend is not available in a
// build tagged noazure, and New("azure") falls through to cloudEngines' "not
// available in this build" error instead of the Azure SDK ever being linked in.
//
//go:build noazure

package dynamic
