package rotation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeIAM struct {
	existing  []string // current access key ids for the user
	newID     string
	newSecret string
	createErr error
	deleted   []string
	createdAs string // username passed to CreateAccessKey
}

func (f *fakeIAM) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	md := make([]iamtypes.AccessKeyMetadata, 0, len(f.existing))
	for _, id := range f.existing {
		id := id
		md = append(md, iamtypes.AccessKeyMetadata{AccessKeyId: &id, UserName: in.UserName})
	}
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: md}, nil
}

func (f *fakeIAM) CreateAccessKey(_ context.Context, in *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.createdAs = aws.ToString(in.UserName)
	return &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{
		AccessKeyId: aws.String(f.newID), SecretAccessKey: aws.String(f.newSecret), UserName: in.UserName,
	}}, nil
}

func (f *fakeIAM) DeleteAccessKey(_ context.Context, in *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	f.deleted = append(f.deleted, aws.ToString(in.AccessKeyId))
	return &iam.DeleteAccessKeyOutput{}, nil
}

func iamWith(fake *fakeIAM, allowed ...string) *AWSIAMExecutor {
	e := NewAWSIAMExecutor("aws", "us-east-1", allowed)
	e.newClient = func(context.Context) (iamAPI, error) { return fake, nil }
	return e
}

func TestAWSIAM_TypeAndName(t *testing.T) {
	e := NewAWSIAMExecutor("prod-aws", "", nil)
	assert.Equal(t, "prod-aws", e.Name())
	assert.Equal(t, "aws-iam", e.Type())
}

func TestAWSIAM_RotateNotSupported(t *testing.T) {
	err := iamWith(&fakeIAM{}, "svc-").Rotate(context.Background(), "svc-app", "v")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GenerateUpstream")
}

func TestAWSIAM_GenerateUpstream_NoExistingKeys(t *testing.T) {
	fake := &fakeIAM{newID: "AKIANEW", newSecret: "s3cr3t"}
	v, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
	require.NoError(t, err)
	assert.Equal(t, "svc-app", fake.createdAs)
	assert.Empty(t, fake.deleted, "no prior keys to delete")

	var cred map[string]string
	require.NoError(t, json.Unmarshal([]byte(v), &cred))
	assert.Equal(t, "AKIANEW", cred["access_key_id"])
	assert.Equal(t, "s3cr3t", cred["secret_access_key"])
}

func TestAWSIAM_GenerateUpstream_DeletesPriorKeys(t *testing.T) {
	// One prior key → create new, then delete the prior.
	fake := &fakeIAM{existing: []string{"AKIAOLD"}, newID: "AKIANEW", newSecret: "x"}
	_, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
	require.NoError(t, err)
	assert.Equal(t, []string{"AKIAOLD"}, fake.deleted)
}

func TestAWSIAM_GenerateUpstream_TwoKeysFreesSlotFirst(t *testing.T) {
	// At the 2-key limit → delete oldest (to make room), create, delete the remaining prior.
	fake := &fakeIAM{existing: []string{"AKIA1", "AKIA2"}, newID: "AKIANEW", newSecret: "x"}
	_, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"AKIA1", "AKIA2"}, fake.deleted, "both prior keys removed; only the new one remains")
}

func TestAWSIAM_GenerateUpstream_Errors(t *testing.T) {
	t.Run("empty ref", func(t *testing.T) {
		_, err := iamWith(&fakeIAM{}, "svc-").GenerateUpstream(context.Background(), "")
		require.Error(t, err)
	})
	t.Run("fail-closed without allowed_refs", func(t *testing.T) {
		_, err := iamWith(&fakeIAM{}).GenerateUpstream(context.Background(), "svc-app")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no allowed_refs")
	})
	t.Run("allowed_refs guardrail", func(t *testing.T) {
		fake := &fakeIAM{newID: "x", newSecret: "y"}
		_, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "root")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted")
		assert.Empty(t, fake.createdAs, "a disallowed ref never reaches AWS")
	})
	t.Run("create error propagates", func(t *testing.T) {
		fake := &fakeIAM{createErr: errors.New("LimitExceeded")}
		_, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "LimitExceeded")
	})
}
