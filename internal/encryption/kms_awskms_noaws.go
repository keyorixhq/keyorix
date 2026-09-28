// kms_awskms_noaws.go — noaws-build sibling of kms_awskms.go (ADR-109 step 6).
// Registers nothing: the aws-kms key provider is not available in a build
// tagged noaws, and buildSingleProvider's "aws-kms" case fails closed with a
// clear "not available in this build" error instead of the AWS SDK ever
// being linked in.
//
//go:build noaws

package encryption
