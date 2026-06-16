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
	c := NewAWSSecretsManagerConnector(name, "eu-west-1")
	c.newClient = func(_ context.Context, _ string) (smGetAPI, error) { return fake, nil }
	return c
}

func TestAWSSM_TypeAndName(t *testing.T) {
	c := NewAWSSecretsManagerConnector("prod-aws", "us-east-1")
	assert.Equal(t, "prod-aws", c.Name())
	assert.Equal(t, "aws-secrets-manager", c.Type())
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
