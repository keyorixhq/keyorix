package crypto

// REVIEW-4213-DEEP-2 N2: the all-failed error keeps every member's error, so
// a caller can tell an unreachable KMS from one that refused.

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiKEK_AllFail_ErrorWrapsEveryMember(t *testing.T) {
	var calls []string
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
	denied := errors.New("access denied")
	m, err := NewMultiKeyProvider([]KeyProvider{
		&recProvider{name: "aws-kms", err: refused, calls: &calls},
		&recProvider{name: "gcp-kms", err: denied, calls: &calls},
	})
	require.NoError(t, err)

	_, err = m.KEK()
	require.Error(t, err)
	assert.ErrorIs(t, err, denied)
	var ne net.Error
	require.ErrorAs(t, err, &ne, "the network failure of a member must stay visible to errors.As")
	assert.Same(t, refused, ne)
	assert.EqualError(t, err, "all key providers failed: aws-kms: dial tcp: connect: connection refused; gcp-kms: access denied")
}
