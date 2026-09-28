// gcpsa_nogcp.go — nogcp-build sibling of gcpsa.go (ADR-109 step 6). Registers
// nothing: the gcp-service-account rotation backend is not available in a
// build tagged nogcp, and LookupCloudExecutor("gcp-service-account") reports
// not-found so server/main.go's wireBackendRotation fails closed (refuses to
// start) instead of the GCP SDK ever being linked in.
//
//go:build nogcp

package rotation
