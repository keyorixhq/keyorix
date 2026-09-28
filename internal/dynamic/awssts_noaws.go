// awssts_noaws.go — noaws-build sibling of awssts.go (ADR-109 step 6). Registers
// nothing: the aws-sts dynamic-secret backend is not available in a build tagged
// noaws, and New("aws-sts") falls through to cloudEngines' "not available in this
// build" error instead of the AWS SDK ever being linked in.
//
//go:build noaws

package dynamic
