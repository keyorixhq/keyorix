package connect

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSM is an injected stand-in for the Secrets Manager client.
type fakeSM struct {
	out *secretsmanager.GetSecretValueOutput
	err error
	got string
}

func (f *fakeSM) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.got = aws.ToString(in.SecretId)
	return f.out, f.err
}

func connectorWith(name string, fake *fakeSM) *AWSSecretsManagerConnector {
	c := NewAWSSecretsManagerConnector(name, "eu-west-1", "", nil)
	c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) { return fake, nil }
	return c
}

func TestAWSSM_TypeAndName(t *testing.T) {
	c := NewAWSSecretsManagerConnector("prod-aws", "us-east-1", "", nil)
	assert.Equal(t, "prod-aws", c.Name())
	assert.Equal(t, "aws-secrets-manager", c.Type())
}

func TestAWSSM_AllowedRefsGuardrail(t *testing.T) {
	fake := &fakeSM{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("ok")}}
	c := NewAWSSecretsManagerConnector("aws", "eu-west-1", "", []string{"keyorix/", "shared/"})
	c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) { return fake, nil }

	// A ref matching an allowed prefix passes.
	val, err := c.GetSecret(context.Background(), "keyorix/prod/db")
	require.NoError(t, err)
	assert.Equal(t, "ok", val)

	// A ref outside the allowlist is rejected BEFORE any backend call.
	fake.got = ""
	_, err = c.GetSecret(context.Background(), "prod/root")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
	assert.Empty(t, fake.got, "a disallowed ref must not reach the backend")
}

func TestAWSSM_GetSecret_String(t *testing.T) {
	fake := &fakeSM{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("s3cr3t")}}
	val, err := connectorWith("aws", fake).GetSecret(context.Background(), "prod/db")
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t", val)
	assert.Equal(t, "prod/db", fake.got, "the ref is passed as the SecretId")
}

func TestAWSSM_GetSecret_Binary(t *testing.T) {
	fake := &fakeSM{out: &secretsmanager.GetSecretValueOutput{SecretBinary: []byte{0x00, 0x01, 0x02}}}
	val, err := connectorWith("aws", fake).GetSecret(context.Background(), "bin")
	require.NoError(t, err)
	assert.Equal(t, "AAEC", val, "binary secrets are returned base64-encoded")
}

func TestAWSSM_GetSecret_Errors(t *testing.T) {
	t.Run("empty ref", func(t *testing.T) {
		_, err := connectorWith("aws", &fakeSM{}).GetSecret(context.Background(), "")
		require.Error(t, err)
	})
	t.Run("backend error", func(t *testing.T) {
		fake := &fakeSM{err: errors.New("AccessDenied")}
		_, err := connectorWith("aws", fake).GetSecret(context.Background(), "x")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "AccessDenied")
	})
	t.Run("no value", func(t *testing.T) {
		fake := &fakeSM{out: &secretsmanager.GetSecretValueOutput{}}
		_, err := connectorWith("aws", fake).GetSecret(context.Background(), "x")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no value")
	})
}

// TestAWSSM_AccountPin covers the account_id confused-deputy guard: a pinned
// connector rejects an ARN-shaped ref naming a different AWS account, still works
// normally for its own account's ARNs, and — the scope boundary this connector's
// doc comment calls out explicitly — a bare secret-name ref is never checked
// against the pin at all, because it never carries a competing account to begin
// with (the AWS API itself always resolves it within the caller's own account).
func TestAWSSM_AccountPin(t *testing.T) {
	t.Run("pinned connector rejects an ARN targeting a different account", func(t *testing.T) {
		fake := &fakeSM{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("x")}}
		c := NewAWSSecretsManagerConnector("aws", "eu-west-1", "111111111111", nil)
		c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) { return fake, nil }

		ref := "arn:aws:secretsmanager:eu-west-1:222222222222:secret:db-AbCdEf"
		_, err := c.GetSecret(context.Background(), ref)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "222222222222")
		assert.Contains(t, err.Error(), "111111111111")
		assert.Empty(t, fake.got, "a cross-account ref must not reach the backend")
	})

	t.Run("pinned connector allows an ARN targeting its own account", func(t *testing.T) {
		fake := &fakeSM{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("s3cr3t")}}
		c := NewAWSSecretsManagerConnector("aws", "eu-west-1", "111111111111", nil)
		c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) { return fake, nil }

		ref := "arn:aws:secretsmanager:eu-west-1:111111111111:secret:db-AbCdEf"
		val, err := c.GetSecret(context.Background(), ref)
		require.NoError(t, err)
		assert.Equal(t, "s3cr3t", val)
	})

	t.Run("pinned connector does not check a bare secret name -- it never carries an account segment", func(t *testing.T) {
		fake := &fakeSM{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("s3cr3t")}}
		c := NewAWSSecretsManagerConnector("aws", "eu-west-1", "111111111111", nil)
		c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) { return fake, nil }

		val, err := c.GetSecret(context.Background(), "prod/db")
		require.NoError(t, err, "a bare-name ref cannot cross accounts, so the pin has nothing to check")
		assert.Equal(t, "s3cr3t", val)
	})

	t.Run("unpinned connector (account_id unset, the still-supported default) allows a cross-account ARN", func(t *testing.T) {
		// Documents the deliberate scope boundary: account_id is optional (unlike
		// GCP's project_id), so leaving it unset keeps today's behavior for ARN
		// refs -- no regression, and consistent with server/main.go's boot-time
		// warning (not a hard failure) for this case.
		fake := &fakeSM{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("g0ph3r")}}
		c := NewAWSSecretsManagerConnector("aws", "eu-west-1", "", nil) // accountID == "" -- the default
		c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) { return fake, nil }

		ref := "arn:aws:secretsmanager:eu-west-1:222222222222:secret:db-AbCdEf"
		val, err := c.GetSecret(context.Background(), ref)
		require.NoError(t, err)
		assert.Equal(t, "g0ph3r", val)
	})
}

func TestAWSRefAccountID(t *testing.T) {
	tests := []struct {
		name        string
		ref         string
		wantAccount string
		wantOK      bool
	}{
		{"full ARN", "arn:aws:secretsmanager:eu-west-1:123456789012:secret:db-AbCdEf", "123456789012", true},
		{"govcloud partition ARN", "arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:db-AbCdEf", "123456789012", true},
		{"bare secret name", "prod/db", "", false},
		{"empty ref", "", "", false},
		{"non-secretsmanager ARN", "arn:aws:iam:eu-west-1:123456789012:role:db-AbCdEf", "", false},
		{"malformed ARN, too few segments", "arn:aws:secretsmanager:eu-west-1:123456789012", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account, ok := awsRefAccountID(tt.ref)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantAccount, account)
		})
	}
}

func TestManager_GetAndNames(t *testing.T) {
	a := connectorWith("aws-a", &fakeSM{})
	b := connectorWith("aws-b", &fakeSM{})
	m := NewManager([]Connector{a, b, nil})

	got, ok := m.Get("aws-a")
	require.True(t, ok)
	assert.Equal(t, "aws-a", got.Name())

	_, ok = m.Get("missing")
	assert.False(t, ok)

	assert.ElementsMatch(t, []string{"aws-a", "aws-b"}, m.Names())

	// nil Manager is safe.
	var nilM *Manager
	_, ok = nilM.Get("x")
	assert.False(t, ok)
	assert.Nil(t, nilM.Names())
}
