//go:build !noaws

package connect

import (
	"net/http"
	"time"
)

// awsTransportParityCase returns the "aws" case for
// TestConnectHardenedTransport_ParityWithBackendDefaults (transport_parity_test.go).
// Split into its own !noaws file (ADR-109 step 6, B1/S2) since awsBaseTransport
// itself lives in hardened_client_aws.go, tagged !noaws — vault/azure's base
// transports need no such split (see hardened_client.go's doc comment: neither
// actually depends on a cloud SDK, only the AWS one does).
func awsTransportParityCase() *transportParityCase {
	return &transportParityCase{"aws", awsBaseTransport(), true, 10 * time.Second, 90 * time.Second, 100, 10}
}

// awsBaseTransportOrNil is TestConnectBaseTransports_NoCustomCAConfiguredToday's
// equivalent seam: nil in a noaws build (see the sibling _noaws.go file), the
// real awsBaseTransport() otherwise.
func awsBaseTransportOrNil() *http.Transport { return awsBaseTransport() }
