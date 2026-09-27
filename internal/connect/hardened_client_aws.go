// hardened_client_aws.go — the one piece of the shared hardened-client
// tooling (hardened_client.go) that needs the AWS SDK: awsBaseTransport,
// called only from awssm.go's client() (itself gated !noaws, ADR-109 step 6).
// Split into its own !noaws-gated file so a noaws build never links
// aws-sdk-go-v2/aws/transport/http.
//
//go:build !noaws

package connect

import (
	"net/http"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
)

// awsBaseTransport returns a REAL clone of aws-sdk-go-v2's own default
// transport, via the SDK's own exported constructor
// (awshttp.NewBuildableClient().GetTransport(), which returns
// defaultHTTPTransport() when no transport has been set) — not a hand-copied
// literal, so it tracks the SDK's actual defaults automatically across version
// bumps, including its FIPS-140-mode TLS curve-preference restriction
// (DefaultHTTPTransportTLSCurvePreferencesFIPS) that a hand-copy would risk
// silently drifting out of sync with.
func awsBaseTransport() *http.Transport {
	return awshttp.NewBuildableClient().GetTransport()
}
