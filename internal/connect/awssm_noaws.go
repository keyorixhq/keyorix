// awssm_noaws.go — noaws-build sibling of awssm.go (ADR-109 step 6). Registers
// nothing: the aws-secrets-manager connector is not available in a build
// tagged noaws, and connect.NewCloudConnector("aws-secrets-manager") reports
// not-found so server/main.go's wireConnect fails closed instead of the AWS
// SDK ever being linked in.
//
//go:build noaws

package connect
