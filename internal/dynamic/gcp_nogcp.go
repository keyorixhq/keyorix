// gcp_nogcp.go — nogcp-build sibling of gcp.go (ADR-109 step 6). Registers
// nothing: the gcp dynamic-secret backend is not available in a build tagged
// nogcp, and New("gcp") falls through to cloudEngines' "not available in this
// build" error instead of the GCP SDK ever being linked in.
//
//go:build nogcp

package dynamic
