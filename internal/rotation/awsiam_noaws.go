// awsiam_noaws.go — noaws-build sibling of awsiam.go (ADR-109 step 6). Registers
// nothing: the aws-iam rotation backend is not available in a build tagged
// noaws (and not also lean, which has its own stand-in registration in
// awsiam_lean.go), so LookupCloudExecutor("aws-iam") reports not-found and
// server/main.go's wireBackendRotation fails closed (refuses to start)
// instead of the AWS SDK ever being linked in.
//
//go:build noaws && !lean

package rotation
