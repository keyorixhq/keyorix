// azurekv_noazure.go — noazure-build sibling of azurekv.go (ADR-109 step 6).
// Registers nothing: the azure-key-vault connector is not available in a
// build tagged noazure, and connect.NewCloudConnector("azure-key-vault")
// reports not-found so server/main.go's wireConnect fails closed instead of
// the Azure SDK ever being linked in.
//
//go:build noazure

package connect
