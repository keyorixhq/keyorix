//go:build !lean && !noaws

package rotation

import (
	"context"
	"net/http"
	"testing"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/hostile"
)

const (
	hostileIAMKeyID  = "AKIAHOSTILEIAM0001"
	hostileIAMSecret = "hostileIamSecretAccessKeyCanary0001"
)

// IAM's query protocol sends every action to POST /, and the harness discards the request
// body before a route sees it, so one route answers the three calls GenerateUpstream makes
// by their order: list (one prior key), create, delete. Occ=1 breaks every call, so a
// program meets the list step; Occ=2 leaves the list valid and breaks create. The delete
// step is reached only by the pristine control: once create is broken the call has ended.
// The iam client is the executor's own (iam.NewFromConfig over awsconfig.LoadDefaultConfig,
// default retryer).
func TestHostileAWSIAMGenerateUpstream(t *testing.T) {
	const ns = `xmlns="https://iam.amazonaws.com/doc/2010-05-08/"`
	meta := `<ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata>`
	bodies := []string{
		`<ListAccessKeysResponse ` + ns + `><ListAccessKeysResult><UserName>app_u</UserName><AccessKeyMetadata><member><UserName>app_u</UserName><AccessKeyId>AKIAOLD0000000000001</AccessKeyId><Status>Active</Status><CreateDate>2020-01-01T00:00:00Z</CreateDate></member></AccessKeyMetadata><IsTruncated>false</IsTruncated></ListAccessKeysResult>` + meta + `</ListAccessKeysResponse>`,
		`<CreateAccessKeyResponse ` + ns + `><CreateAccessKeyResult><AccessKey><UserName>app_u</UserName><AccessKeyId>AKIANEW00000000000001</AccessKeyId><Status>Active</Status><SecretAccessKey>hostile-new-secret-0001</SecretAccessKey><CreateDate>2031-01-02T03:04:05Z</CreateDate></AccessKey></CreateAccessKeyResult>` + meta + `</CreateAccessKeyResponse>`,
		`<DeleteAccessKeyResponse ` + ns + `>` + meta + `</DeleteAccessKeyResponse>`,
	}
	runCloudExecutorHostile(t, cloudExecutorTarget{
		name:      "aws-iam",
		sequenced: true,
		creds:     []string{hostileIAMKeyID, hostileIAMSecret},
		routes: []hostile.Route{{
			Name: "iam", Method: "POST", Prefix: "/",
			Valid: func(n int, _ *http.Request) hostile.Resp {
				return hostile.Resp{Status: 200, CT: "text/xml", Body: []byte(bodies[min(n, len(bodies))-1])}
			},
		}},
		build: func(_ context.Context, h *hostile.Harness) (Executor, string) {
			e := NewAWSIAMExecutor("iam", "us-east-1", []string{"app_"})
			e.newClient = func(ctx context.Context) (iamAPI, error) {
				cfg, err := awsconfig.LoadDefaultConfig(ctx,
					awsconfig.WithRegion("us-east-1"),
					awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(hostileIAMKeyID, hostileIAMSecret, "")),
					awsconfig.WithBaseEndpoint(h.URL()))
				if err != nil {
					return nil, err
				}
				return iam.NewFromConfig(cfg), nil
			}
			return e, "app_u"
		},
	})
}
