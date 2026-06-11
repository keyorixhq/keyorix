package secret

import (
	"context"
	"sort"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAWS implements awsSecretsAPI over an in-memory name→value map, paginating
// one secret per page to exercise the NextToken loop.
type fakeAWS struct {
	names  []string
	values map[string]string // SecretString per name; "" means binary (no string)
}

func (f *fakeAWS) ListSecrets(ctx context.Context, in *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	start := 0
	if in.NextToken != nil {
		start, _ = strconv.Atoi(*in.NextToken) // token encodes the next index
	}
	if start >= len(f.names) {
		return &secretsmanager.ListSecretsOutput{}, nil
	}
	name := f.names[start]
	out := &secretsmanager.ListSecretsOutput{
		SecretList: []smtypes.SecretListEntry{{Name: aws.String(name)}},
	}
	if start+1 < len(f.names) {
		out.NextToken = aws.String(strconv.Itoa(start + 1))
	}
	return out, nil
}

func (f *fakeAWS) GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	name := aws.ToString(in.SecretId)
	v := f.values[name]
	out := &secretsmanager.GetSecretValueOutput{Name: aws.String(name)}
	if v == "" {
		out.SecretBinary = []byte{0x01} // simulate a binary secret
	} else {
		out.SecretString = aws.String(v)
	}
	return out, nil
}

func TestCollectAWS(t *testing.T) {
	awsPrefix = ""
	importNoExplode = false
	api := &fakeAWS{
		names: []string{"plain", "prod/db", "bin"},
		values: map[string]string{
			"plain":   "just-a-string",
			"prod/db": `{"username":"u","password":"p"}`,
			"bin":     "", // binary → skipped
		},
	}

	entries, err := collectAWS(context.Background(), api)
	require.NoError(t, err)

	got := map[string]string{}
	for _, e := range entries {
		got[e.Name] = e.Value
	}
	assert.Equal(t, "just-a-string", got["plain"])
	assert.Equal(t, "u", got["prod-db-username"])
	assert.Equal(t, "p", got["prod-db-password"])
	_, hasBin := got["bin"]
	assert.False(t, hasBin, "binary secrets should be skipped")
}

func TestCollectAWS_PrefixFilter(t *testing.T) {
	awsPrefix = "prod/"
	importNoExplode = true // keep names simple for this assertion
	api := &fakeAWS{
		names:  []string{"dev/x", "prod/y", "prod/z"},
		values: map[string]string{"dev/x": "1", "prod/y": "2", "prod/z": "3"},
	}

	entries, err := collectAWS(context.Background(), api)
	require.NoError(t, err)

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	assert.Equal(t, []string{"prod-y", "prod-z"}, names)
	awsPrefix = ""
}
