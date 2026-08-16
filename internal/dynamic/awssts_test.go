package dynamic

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSTS struct {
	in  *sts.AssumeRoleInput
	out *sts.AssumeRoleOutput
	err error
}

func (f *fakeSTS) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.in = in
	return f.out, f.err
}

func newFakeSTSEngine(fake *fakeSTS) *AWSSTSEngine {
	return &AWSSTSEngine{newClient: func(_ context.Context, _ string) (stsRoleAssumer, error) { return fake, nil }}
}

func TestAWSSTSEngine_Issue(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	fake := &fakeSTS{out: &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AKIAEXAMPLE"), SecretAccessKey: aws.String("sekret"),
		SessionToken: aws.String("tok"), Expiration: &exp,
	}}}
	eng := newFakeSTSEngine(fake)

	cfg := `{"role_arn":"arn:aws:iam::123456789012:role/keyorix-dyn","region":"eu-west-1"}`
	cred, role, err := eng.Issue(context.Background(), cfg, `{"Version":"2012-10-17"}`, time.Hour)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(role, "keyorix-dyn-"))
	assert.Equal(t, "AKIAEXAMPLE", cred.Fields["access_key_id"])
	assert.Equal(t, "sekret", cred.Fields["secret_access_key"])
	assert.Equal(t, "tok", cred.Fields["session_token"])
	assert.Equal(t, "eu-west-1", cred.Fields["region"])
	assert.Empty(t, cred.Username)
	assert.Empty(t, cred.Password)

	// The AssumeRole call carried role ARN, the session policy, and a >= ttl duration.
	require.NotNil(t, fake.in)
	assert.Equal(t, "arn:aws:iam::123456789012:role/keyorix-dyn", aws.ToString(fake.in.RoleArn))
	assert.Equal(t, `{"Version":"2012-10-17"}`, aws.ToString(fake.in.Policy))
	assert.Equal(t, int32(3600), aws.ToInt32(fake.in.DurationSeconds))

	// Engine semantics.
	assert.True(t, eng.IsEphemeralBackend())
	assert.True(t, eng.SupportsNativeExpiry())
	assert.Equal(t, "aws-sts", eng.BackendType())
	require.NoError(t, eng.Revoke(context.Background(), "", role)) // no-op
	require.Error(t, eng.Renew(context.Background(), "", role, time.Now()))
	assert.False(t, eng.RevokeInvalidatesCredential(""), "AWS has no per-session revoke API for AssumeRole credentials")
}

func TestAWSSTSEngine_DurationClampedToMin(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	fake := &fakeSTS{out: &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("a"), SecretAccessKey: aws.String("b"), SessionToken: aws.String("c"), Expiration: &exp,
	}}}
	eng := newFakeSTSEngine(fake)
	_, _, err := eng.Issue(context.Background(), `{"role_arn":"arn:aws:iam::1:role/r"}`, "", 60*time.Second)
	require.NoError(t, err)
	assert.Equal(t, int32(900), aws.ToInt32(fake.in.DurationSeconds)) // AWS 15-min minimum
}

func TestAWSSTSEngine_ConfigValidation(t *testing.T) {
	eng := newFakeSTSEngine(&fakeSTS{})
	// Not JSON.
	_, _, err := eng.Issue(context.Background(), "postgres://x", "", time.Hour)
	require.Error(t, err)
	// Missing role_arn.
	_, _, err = eng.Issue(context.Background(), `{"region":"eu-west-1"}`, "", time.Hour)
	require.Error(t, err)
}

// TestValidateAWSSTSCfg_AccountIDPinning is a regression test for a bug where
// validateAWSSTSCfg, when allowed_account_id was left unset, derived the
// "expected" account ID from role_arn itself and then compared role_arn's
// account ID against that self-derived value — a tautology that can never
// fail. That made account-ID pinning a silent no-op even though its intent
// (and doc comment) was to reject a role_arn belonging to an unexpected AWS
// account. The fix makes allowed_account_id an explicit opt-in: unset means
// pinning is not configured (any account accepted, documented as such);
// set means the comparison must be against the *operator-supplied* value,
// never a value derived from the input under test.
func TestValidateAWSSTSCfg_AccountIDPinning(t *testing.T) {
	const accountX = "111111111111"
	const accountY = "222222222222"
	roleInAccountX := "arn:aws:iam::" + accountX + ":role/keyorix-dyn"

	t.Run("explicit allowed_account_id rejects a role_arn from a different account", func(t *testing.T) {
		cfg := awsSTSConfig{RoleARN: roleInAccountX, AllowedAccountID: accountY}
		err := validateAWSSTSCfg(cfg)
		require.Error(t, err, "role_arn account %q must be refused against allowed_account_id %q", accountX, accountY)
		assert.Contains(t, err.Error(), "does not match allowed_account_id")
	})

	t.Run("explicit allowed_account_id accepts a matching role_arn", func(t *testing.T) {
		cfg := awsSTSConfig{RoleARN: roleInAccountX, AllowedAccountID: accountX}
		require.NoError(t, validateAWSSTSCfg(cfg))
	})

	t.Run("unset allowed_account_id skips pinning (no restriction, not a tautology)", func(t *testing.T) {
		// Before the fix, this path derived AllowedAccountID from RoleARN itself
		// and then compared RoleARN's account ID against that derived value,
		// so it could never fail for any syntactically-valid role_arn. The
		// correct behavior is an honest no-op: pinning simply isn't configured.
		cfg := awsSTSConfig{RoleARN: roleInAccountX}
		require.NoError(t, validateAWSSTSCfg(cfg))
	})

	// This is the case that actually distinguishes pre-fix from post-fix
	// behavior (the two subtests above pass under both): the tautological
	// "derive from role_arn, then compare against the derived value" path
	// required role_arn to contain a *parseable* account ID even when
	// pinning was never requested, purely as a side effect of doing the
	// self-comparison. A role_arn with no discoverable account ID plus an
	// unset allowed_account_id must now be accepted outright — the check is
	// skipped entirely, not silently satisfied by comparing role_arn to
	// itself.
	t.Run("unset allowed_account_id accepts a role_arn with no parseable account ID", func(t *testing.T) {
		cfg := awsSTSConfig{RoleARN: "not-an-arn"}
		require.NoError(t, validateAWSSTSCfg(cfg))
	})
}
