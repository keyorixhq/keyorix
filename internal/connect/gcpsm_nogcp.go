// gcpsm_nogcp.go — nogcp-build sibling of gcpsm.go (ADR-109 step 6). Registers
// nothing: the gcp-secret-manager connector is not available in a build
// tagged nogcp, and connect.NewCloudConnector("gcp-secret-manager") reports
// not-found so server/main.go's wireConnect fails closed instead of the GCP
// SDK ever being linked in.
//
//go:build nogcp

package connect
