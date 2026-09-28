//go:build noaws

package connect

import "net/http"

// awsTransportParityCase and awsBaseTransportOrNil: noaws-build siblings of
// transport_parity_aws_test.go (ADR-109 step 6, B1/S2). awsBaseTransport
// itself is excluded in this build (hardened_client_aws.go, tagged !noaws),
// so there is no "aws" case/entry to test — nil signals the two callers in
// transport_parity_test.go to skip it.
func awsTransportParityCase() *transportParityCase { return nil }

func awsBaseTransportOrNil() *http.Transport { return nil }
