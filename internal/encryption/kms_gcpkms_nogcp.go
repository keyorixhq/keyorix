// kms_gcpkms_nogcp.go — nogcp-build sibling of kms_gcpkms.go (ADR-109 step 6).
// Registers nothing: the gcp-kms key provider is not available in a build
// tagged nogcp, and buildSingleProvider's "gcp-kms" case fails closed with a
// clear "not available in this build" error instead of the GCP SDK ever
// being linked in. wireGCPKMSAuditSinkFn stays nil (its zero value), making
// Service.wireKMSAuditSink a no-op — there is no gcp-kms client to wire in
// this build.
//
//go:build nogcp

package encryption
