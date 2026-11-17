//go:build !noaws

package dynamic

import (
	"context"
	"net/http"
	"testing"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/hostile"
)

const (
	hostileSTSKeyID  = "AKIAHOSTILESTS0001"
	hostileSTSSecret = "hostileStsSecretAccessKeyCanary0001"
)

// The AWS client is built the way the engine builds it (awsconfig.LoadDefaultConfig, the
// SDK's default retryer, sts.NewFromConfig); only the credential source and the endpoint
// differ.
func TestHostileAWSSTSIssue(t *testing.T) {
	runCloudHostile(t, cloudHostileTarget{
		name:  "aws-sts",
		creds: []string{hostileSTSKeyID, hostileSTSSecret},
		routes: []hostile.Route{{
			Name: "assume", Method: "POST", Prefix: "/",
			Valid: func(int, *http.Request) hostile.Resp {
				return hostile.Resp{Status: 200, CT: "text/xml", Body: []byte(`<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>ASIAHOSTILE0001</AccessKeyId><SecretAccessKey>hostile-secret-0001</SecretAccessKey><SessionToken>hostile-session-0001</SessionToken><Expiration>2031-01-02T03:04:05Z</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>AROAX:s</AssumedRoleId><Arn>arn:aws:sts::123456789012:assumed-role/r/s</Arn></AssumedRoleUser></AssumeRoleResult><ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata></AssumeRoleResponse>`)}
			},
		}},
		issue: func(ctx context.Context, h *hostile.Harness) error {
			eng := Contain(&AWSSTSEngine{newClient: func(ctx context.Context, _ string) (stsRoleAssumer, error) {
				cfg, err := awsconfig.LoadDefaultConfig(ctx,
					awsconfig.WithRegion("us-east-1"),
					awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(hostileSTSKeyID, hostileSTSSecret, "")),
					awsconfig.WithBaseEndpoint(h.URL()))
				if err != nil {
					return nil, err
				}
				return sts.NewFromConfig(cfg), nil
			}})
			_, _, err := eng.Issue(ctx, `{"role_arn":"arn:aws:iam::123456789012:role/keyorix-dynamic","region":"us-east-1"}`, "", hostileIssueTTL)
			return err
		},
	})
}
