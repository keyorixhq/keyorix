package awssource

// aws_hostile_fuzz_test.go: FuzzAWSSourceHostileEndpoint is the hostile-backend
// record-and-mutate target for the AWS Secrets Manager importer. It drives the REAL
// aws-sdk-go-v2 secretsmanager client (via BaseEndpoint pointed at a fake server and the
// production httpsafe.Client transport) through awssource.Client.List, with the AWS-JSON
// ListSecrets / GetSecretValue responses mutated by the fuzz program. This is the "HTTP
// base-URL seam the code really exposes" (the client() builder injects the HTTPClient and
// the SDK accepts BaseEndpoint) — no production code is patched; the test only sets the
// package-private newClient hook to a real SDK client aimed at the harness.
//
// Oracles (what each does NOT verify):
//   - O1 NO-PANIC / O2 NO-HANG / O4 BOUNDED-WORK via hostile.Harness.Run around List.
//   - O6 LIVENESS: a pristine run returns exactly the one planted secret (value = canary).
//   - VALUE-LEAK / CRED-LEAK (b): a DISTINCT secret-value canary (awsValueCanary, planted only
//     as GetSecretValue.SecretString) and the signing secret key must never appear in List's
//     error text or captured slog. These are tagged separately from the harness's generic O7
//     ON PURPOSE: the generic O7 checks hostile.Canary, which the mutation program also injects
//     into arbitrary response FIELDS — the AWS SDK's awsjson decoder echoes an unpareseable
//     body (including such an injected value) into its deserialization error, and that is the
//     "echo" class (attacker-controlled RESPONSE text in an error), NOT a secret-VALUE leak,
//     per the task's own rule. So the campaign runs with KX_HOSTILE_ALLOW=O7 (field-echo
//     suppressed, still printed HOSTILE-KNOWN) while these explicit checks keep the real
//     secret-value and credential leak signals live. Does NOT capture the SDK's own internal
//     logger (off by default) — only slog + the returned error.
//   - O9 SSRF-ISH: the sentinel internal-address server receives zero requests (httpsafe
//     refuses redirects). Loopback sentinel: redirect policy, not address filtering.
//   - FAIL-CLOSED (e) is delegated to the SDK's strict awsjson decoder: a truncated/corrupt
//     body makes the SDK's Deserialize step error, which List surfaces — not separately
//     asserted here because the single shared "/" route serves both operations, so a
//     per-request Delivery mapping would be ambiguous. Stated, not silently skipped.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/keyorixhq/keyorix/migrate/internal/hostile"
	"github.com/keyorixhq/keyorix/migrate/internal/httpsafe"
)

// staticCreds is a minimal aws.CredentialsProvider so the SDK can sign requests to the fake
// endpoint without pulling in the credentials package (keeping go.mod's require set unchanged).
type staticCreds struct{}

func (staticCreds) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "AKIDTEST", SecretAccessKey: awsSigningSecret, Source: "hostile-test"}, nil
}

// awsValueCanary is the secret VALUE (must never leak into an error/log). It is DISTINCT from
// hostile.Canary so a mutation-injected hostile.Canary echoed by the SDK decoder (echo class)
// is not conflated with a real secret-value leak. awsSigningSecret is the SigV4 secret key —
// a credential that likewise must never surface.
const (
	awsValueCanary   = "kx-aws-value-canary-9d1f2a"
	awsSigningSecret = "kx-aws-signing-secret-3c7e"
)

// awsHostileRoutes serves one AWS-JSON route (the SDK POSTs every operation to "/"), branching
// on the X-Amz-Target header: ListSecrets returns one secret with no NextToken (walk stops);
// GetSecretValue returns that secret's value = the canary.
func awsHostileRoutes() []hostile.Route {
	js := func(s string) hostile.Resp {
		return hostile.Resp{Status: 200, CT: "application/x-amz-json-1.1", Body: []byte(s)}
	}
	return []hostile.Route{
		{Name: "aws", Method: "POST", Prefix: "/", Valid: func(_ int, r *http.Request) hostile.Resp {
			target := r.Header.Get("X-Amz-Target")
			switch {
			case strings.HasSuffix(target, "ListSecrets"):
				return js(`{"SecretList":[{"Name":"team/db","ARN":"arn:aws:secretsmanager:us-east-1:1:secret:team/db"}]}`)
			case strings.HasSuffix(target, "GetSecretValue"):
				return js(`{"ARN":"arn:aws:secretsmanager:us-east-1:1:secret:team/db","Name":"team/db","VersionId":"v1","SecretString":"` + awsValueCanary + `"}`)
			default:
				return js(`{}`)
			}
		}},
	}
}

func awsHostileClient(h *hostile.Harness) smAPI {
	return secretsmanager.New(secretsmanager.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(h.URL()),
		Credentials:      staticCreds{},
		HTTPClient:       httpsafe.Client(),
		RetryMaxAttempts: 1, // deterministic request counting; no SDK retries
	})
}

func FuzzAWSSourceHostileEndpoint(f *testing.F) {
	f.Add([]byte{})
	for _, p := range []hostile.Program{
		{Occ: 1, Ops: []hostile.Op{{Code: 1, A: 1}}},       // delete a field
		{Occ: 1, Ops: []hostile.Op{{Code: 4, A: 2, B: 2}}}, // huge string value
		{Occ: 1, Ops: []hostile.Op{{Code: 7, A: 1, B: 0}}}, // oversized SecretList
		{Occ: 2, Ops: []hostile.Op{{Code: 12, A: 1}}},      // canary into GetSecretValue
		{Occ: 1, Frame: 3},   // truncated
		{Occ: 1, Fault: 2},   // rst mid-body
		{Occ: 1, Enc: 2},     // gzip bomb
		{Occ: 1, Status: 16}, // 500 on everything
	} {
		f.Add(hostile.Encode(p))
	}

	f.Fuzz(func(t *testing.T, prog []byte) {
		p := hostile.Decode(prog)
		h := hostile.New(hostile.Config{
			Routes: awsHostileRoutes(), Program: p,
			// Credentials intentionally NOT handed to the harness: the generic O7 check (which
			// also covers hostile.Canary field-echo) is suppressed for this target via
			// KX_HOSTILE_ALLOW=O7; the real credential/value leak signals are the explicit,
			// distinctly-tagged checks below.
			RequestCeiling: 2000,
			Retries:        true,
		})
		defer h.Close()

		c := New(Config{Region: "us-east-1"})
		c.newClient = func(context.Context) (smAPI, error) { return awsHostileClient(h), nil }

		var entries []cloudentryEntry
		errList := h.Run("awssource.List", func(ctx context.Context) error {
			es, _, err := c.List(ctx)
			for _, e := range es {
				entries = append(entries, cloudentryEntry{e.RawName, e.Value})
			}
			return err
		})

		// VALUE-LEAK / CRED-LEAK (b): the real secret value and the signing credential must
		// never appear in the error or captured logs (tagged non-O7 so KX_HOSTILE_ALLOW=O7
		// does not suppress them).
		scan := ""
		if errList != nil {
			scan = errList.Error()
		}
		scan += "\n" + h.Logs()
		if strings.Contains(scan, awsValueCanary) {
			h.Violate("VALUE-LEAK: the secret value appears in awssource.List's error or log output")
		}
		if strings.Contains(scan, awsSigningSecret) {
			h.Violate("CRED-LEAK: the SigV4 signing secret appears in awssource.List's error or log output")
		}

		if p.Pristine() {
			if errList != nil {
				h.Violate("O6 LIVENESS: pristine List errored: %v (unmatched: %v)", errList, h.Unmatched())
			} else if len(entries) != 1 || entries[0].name != "team/db" || entries[0].value != awsValueCanary {
				h.Violate("O6 LIVENESS: pristine List returned %#v (want one team/db=value-canary)", entries)
			}
		}
		if h.AttackerHits() > 0 {
			h.Violate("SSRF-CROSS-ORIGIN: awssource sent %d request(s) to the sentinel internal address", h.AttackerHits())
		}

		h.Finish(t.Fatalf)
	})
}

type cloudentryEntry struct{ name, value string }
