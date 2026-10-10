package services

// #2905: breakGlassError classified core's error with strings.Contains over
// err.Error(), which embeds i18n.T(...) output. Translate those prefixes and the
// NotFound / PermissionDenied / FailedPrecondition arms stop matching. Core now
// returns sentinels and this maps them with errors.Is. Not t.Parallel(): the
// localizer is process-global.

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Core-shaped refusals for the breakGlassError unit tests: the sentinel is what
// classifies; the surrounding text is deliberately arbitrary (and wrapped, as
// core wraps it) because the text must not matter.
var (
	errBGNotFound       = fmt.Errorf("lookup failed: %w", storage.ErrBreakGlassNotFound)
	errBGInvalidRequest = fmt.Errorf("whatever words: %w", core.ErrBreakGlassInvalidRequest)
	errBGDisabled       = fmt.Errorf("whatever words: %w", core.ErrBreakGlassDisabled)
	errBGNotMember      = fmt.Errorf("whatever words: %w", core.ErrBreakGlassNotProjectMember)
	errBGNotActive      = fmt.Errorf("whatever words: %w", storage.ErrBreakGlassNotActive)
)

// TestBreakGlassError_EnglishTextAloneDoesNotClassify is the unit-level red
// proof of #2905: each message below used to select a non-Internal code purely
// by its words. Without a sentinel they are Internal.
func TestBreakGlassError_EnglishTextAloneDoesNotClassify(t *testing.T) {
	for _, msg := range []string{
		"activation not found", "justification is required", "invalid ttl",
		"permission denied", "access denied", "already revoked", "activation is not active", "activation expired",
	} {
		assert.Equal(t, codes.Internal, status.Code(breakGlassError(errors.New(msg))), msg)
	}
}

// translateBreakGlassErrorPrefixes switches to a locale in which every error
// prefix core puts in front of a break-glass refusal reads differently from
// English (no shipped locale translates ErrorPermissionDenied, so flipping to
// one would prove nothing).
func translateBreakGlassErrorPrefixes(t *testing.T) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	restore, err := i18n.RegisterPseudoLocaleForTesting("it", map[string]string{
		"ErrorPermissionDenied": "доступ запрещён",
		"ErrorValidation":       "ошибка проверки",
		"ErrorNotFound":         "ресурс отсутствует",
		"ErrorRetrievalFailed":  "сбой получения данных",
		"ErrorStorageFailed":    "сбой хранилища",
	})
	require.NoError(t, err)
	t.Cleanup(restore)
	require.Equal(t, "доступ запрещён", i18n.T("ErrorPermissionDenied", nil))
}

func TestBreakGlassGRPC_RefusalCodesAreLocaleIndependent(t *testing.T) {
	for _, translated := range []bool{false, true} {
		name := "en"
		if translated {
			name = "translated"
		}
		t.Run(name+"/activate disabled", func(t *testing.T) {
			svc := newBreakGlassService(t)
			if translated {
				translateBreakGlassErrorPrefixes(t)
			}
			svc.core.SetBreakGlassPolicy(core.BreakGlassPolicy{Enabled: false})
			_, err := svc.ActivateBreakGlass(bgCtx(), &pb.ActivateBreakGlassRequest{ProjectId: 1, Justification: "prod incident #42"})
			assert.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)
		})
		t.Run(name+"/activate not a project member", func(t *testing.T) {
			svc := newBreakGlassService(t)
			if translated {
				translateBreakGlassErrorPrefixes(t)
			}
			svc.core.SetBreakGlassPolicy(core.BreakGlassPolicy{Enabled: true, EmergencyRole: "emergency", DefaultTTL: time.Hour, MaxTTL: time.Hour})
			// user 1 is a member of project 1 only.
			_, err := svc.ActivateBreakGlass(bgCtx(), &pb.ActivateBreakGlassRequest{ProjectId: 2, Justification: "prod incident #42"})
			assert.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)
		})
		t.Run(name+"/activate justification too short", func(t *testing.T) {
			svc := newBreakGlassService(t)
			if translated {
				translateBreakGlassErrorPrefixes(t)
			}
			_, err := svc.ActivateBreakGlass(bgCtx(), &pb.ActivateBreakGlassRequest{ProjectId: 1, Justification: "short"})
			assert.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)
		})
		t.Run(name+"/revoke unknown activation", func(t *testing.T) {
			svc := newBreakGlassService(t)
			if translated {
				translateBreakGlassErrorPrefixes(t)
			}
			_, err := svc.RevokeBreakGlass(bgCtx(), &pb.RevokeBreakGlassRequest{ProjectId: 1, ActivationId: 999999})
			assert.Equal(t, codes.NotFound, status.Code(err), "%v", err)
		})
		t.Run(name+"/revoke activation of another project", func(t *testing.T) {
			svc := newBreakGlassService(t)
			act, err := svc.ActivateBreakGlass(bgCtx(), &pb.ActivateBreakGlassRequest{ProjectId: 1, Justification: "prod incident #42", Ttl: "1h"})
			require.NoError(t, err)
			if translated {
				translateBreakGlassErrorPrefixes(t)
			}
			_, err = svc.RevokeBreakGlass(bgCtx(), &pb.RevokeBreakGlassRequest{ProjectId: 2, ActivationId: act.GetId()})
			assert.Equal(t, codes.NotFound, status.Code(err), "%v", err)
		})
		t.Run(name+"/revoke twice", func(t *testing.T) {
			svc := newBreakGlassService(t)
			act, err := svc.ActivateBreakGlass(bgCtx(), &pb.ActivateBreakGlassRequest{ProjectId: 1, Justification: "prod incident #42", Ttl: "1h"})
			require.NoError(t, err)
			_, err = svc.RevokeBreakGlass(bgCtx(), &pb.RevokeBreakGlassRequest{ProjectId: 1, ActivationId: act.GetId()})
			require.NoError(t, err)
			if translated {
				translateBreakGlassErrorPrefixes(t)
			}
			_, err = svc.RevokeBreakGlass(bgCtx(), &pb.RevokeBreakGlassRequest{ProjectId: 1, ActivationId: act.GetId()})
			assert.Equal(t, codes.FailedPrecondition, status.Code(err), "%v", err)
		})
	}
}
